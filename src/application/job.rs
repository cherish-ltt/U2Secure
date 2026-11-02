//! 步骤执行器 —— CLI 与 TUI 共用的编排策略
//!
//! 统一处理：
//! - 步骤顺序、Ctrl+C 中断、失败回滚（核心步骤失败 → 回滚并停止）
//! - 可选步骤（9/10/11）失败 → 只记录失败、不触发全局回滚、继续后续步骤
//! - 临时软件源的准备/预热与清理
//! - 每个步骤的实时输出文件与报告目录注入
//!
//! TUI 通过 `spawn()` 在后台线程执行，UI 保持响应。

use std::collections::HashSet;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use crate::application::steps::step_for;
use crate::domain::mirror::PackageMirror;
use crate::domain::steps::{ExecuteParams, HardeningStep, StepKind, StepOutcome, StepResult};
use crate::infrastructure::logger::FileLogger;
use crate::infrastructure::package_mirror::{self, MirrorSession};
use crate::infrastructure::{artifacts, rollback, system};

/// 按定义顺序筛选出待执行步骤
fn select_steps(selected: &[StepKind]) -> Vec<Box<dyn HardeningStep + Send>> {
    execution_plan(selected).into_iter().map(step_for).collect()
}

/// SSH 配置步骤后的生效检查始终排在末尾，是否重启另由明确授权与真实变化决定。
pub fn execution_plan(selected: &[StepKind]) -> Vec<StepKind> {
    let mut selected_set: HashSet<StepKind> = selected.iter().copied().collect();
    if selected.iter().any(StepKind::modifies_ssh_config) {
        selected_set.insert(StepKind::RestartSsh);
    }
    StepKind::all()
        .iter()
        .filter(|kind| selected_set.contains(kind))
        .copied()
        .collect()
}

/// 执行过程中的事件
#[derive(Debug, Clone)]
pub enum JobEvent {
    /// 某步骤开始执行（`live_log` 为该步骤实时输出文件，UI 可尾随显示）
    StepStarted {
        kind: StepKind,
        index: usize,
        total: usize,
        live_log: String,
    },
    /// 某步骤执行结束
    StepFinished(StepResult),
    /// 一般日志（镜像准备、回滚提示等）
    Log(String),
    /// 用户中断，回滚错误由步骤结果报告
    Interrupted,
    /// 临时软件源连接失败（重试耗尽，未执行任何步骤，等待用户决定重试/换源）
    MirrorFailed { reason: String },
    /// 全部结束
    AllFinished,
}

/// 后台任务句柄
pub struct JobHandle {
    pub rx: Receiver<JobEvent>,
    pub started_at: Instant,
    pub total: usize,
    handle: Option<JoinHandle<()>>,
}

impl JobHandle {
    /// 非阻塞地取出当前已产生的事件
    pub fn drain(&self) -> Vec<JobEvent> {
        self.rx.try_iter().collect()
    }

    /// 后台线程是否已结束（用于检测异常退出，避免 UI 永久卡在执行页）
    pub fn is_disconnected(&self) -> bool {
        matches!(
            self.rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        )
    }

    /// 等待后台线程结束（中断/退出时调用，确保子进程已被回收）
    pub fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// 步骤执行器
pub struct StepRunner {
    logger: Arc<FileLogger>,
    /// 本次运行希望使用的临时软件源
    mirror: PackageMirror,
    /// 报告目录覆盖（缺省使用 `artifacts::dir()`；测试注入临时目录）
    report_dir: Option<String>,
}

impl StepRunner {
    pub fn new(logger: Arc<FileLogger>) -> Self {
        Self {
            logger,
            mirror: PackageMirror::Original,
            report_dir: None,
        }
    }

    /// 覆盖报告目录（测试用，避免污染真实系统目录）
    pub fn with_report_dir(mut self, dir: impl Into<String>) -> Self {
        self.report_dir = Some(dir.into());
        self
    }

    /// 指定临时软件源（Original 表示不改动）
    pub fn with_mirror(mut self, mirror: PackageMirror) -> Self {
        self.mirror = mirror;
        self
    }

    /// 在后台线程执行选中的步骤
    pub fn spawn(self, selected: Vec<StepKind>, params: ExecuteParams) -> JobHandle {
        self.spawn_steps(select_steps(&selected), params)
    }

    /// 在后台线程执行给定步骤（测试可注入假步骤）
    pub fn spawn_steps(
        self,
        steps: Vec<Box<dyn HardeningStep + Send>>,
        params: ExecuteParams,
    ) -> JobHandle {
        let total = steps.len();
        let (tx, rx) = channel();
        let handle = std::thread::spawn(move || {
            let mut emit = |event: JobEvent| {
                let _ = tx.send(event);
            };
            self.run_steps(steps, &params, &mut emit);
        });
        JobHandle {
            rx,
            started_at: Instant::now(),
            total,
            handle: Some(handle),
        }
    }

    /// 同步执行选中的步骤（CLI 使用，事件通过回调实时输出）
    pub fn run(
        &self,
        selected: &[StepKind],
        params: &ExecuteParams,
        on_event: &mut dyn FnMut(JobEvent),
    ) -> Vec<StepResult> {
        let steps = select_steps(selected);
        self.run_steps(steps, params, on_event)
    }

    /// 执行给定计划（测试按 `execution_plan` 注入假步骤，不构造真实系统步骤）。
    pub fn run_steps(
        &self,
        steps: Vec<Box<dyn HardeningStep + Send>>,
        params: &ExecuteParams,
        on_event: &mut dyn FnMut(JobEvent),
    ) -> Vec<StepResult> {
        static RUN_LOCK: Mutex<()> = Mutex::new(());
        // The undo stack and cancellation flag belong to one running batch at a time.
        let _batch = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let checkpoint = rollback::undo_depth();
        let total = steps.len();
        let report_dir = self
            .report_dir
            .clone()
            .unwrap_or_else(artifacts::dir_display);
        let steps_dir = if let Some(dir) = &self.report_dir {
            let path = std::path::Path::new(dir).join("steps");
            let _ = std::fs::create_dir_all(&path);
            path.to_string_lossy().to_string()
        } else {
            artifacts::steps_dir()
        };

        // 每次运行前清理中断标记，避免上一次的残留导致立刻停止
        rollback::INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);

        // ── 临时软件源：仅在本次运行期间生效，TempDir 随作用域结束自动清理 ──
        let mut params = params.clone();
        let mirror_session = match self.prepare_mirror(on_event) {
            Ok(session) => session,
            Err(reason) => {
                // 源连不通：不自动回退、不执行任何步骤，交给用户决定重试/换源
                on_event(JobEvent::MirrorFailed { reason });
                on_event(JobEvent::AllFinished);
                return vec![];
            },
        };
        if let Some(session) = &mirror_session
            && session.is_active()
        {
            params.mirror = session.override_value();
        }

        let mut results = vec![];
        for (index, step) in steps.iter().enumerate() {
            let kind = step.kind();

            if rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst) {
                let failures = self.rollback_on_interrupt(checkpoint, on_event);
                if !failures.is_empty() {
                    let message = crate::i18n::tr("log_rollback_failed")
                        .replace("{errors}", &failures.join("\n"));
                    self.logger.log(&message);
                    let result = StepResult::failed(kind, message);
                    on_event(JobEvent::StepFinished(result.clone()));
                    results.push(result);
                }
                break;
            }

            // 每个步骤独立的实时输出文件
            let live_log = format!("{steps_dir}/{:02}-{}.log", index + 1, kind.slug());
            let mut step_params = params.clone();
            step_params.report_dir = Some(report_dir.clone());
            step_params.live_log = Some(live_log.clone());

            on_event(JobEvent::StepStarted {
                kind,
                index,
                total,
                live_log,
            });
            self.logger
                .log_operation(crate::i18n::tr("log_step_start"), kind.label());

            let execution = if kind == StepKind::RestartSsh && !params.ssh_restart_required {
                Ok(StepResult::skipped(
                    kind,
                    crate::i18n::tr("result_ssh_no_restart"),
                ))
            } else if kind == StepKind::RestartSsh && !params.apply_ssh_changes {
                Ok(StepResult::skipped(
                    kind,
                    crate::i18n::tr("result_ssh_pending"),
                ))
            } else {
                step.execute(&step_params)
            };
            let mut result = match execution {
                Ok(result) => result,
                Err(e) => StepResult::failed(
                    kind,
                    crate::i18n::tr("log_step_failed_detail").replace("{err}", &e.to_string()),
                ),
            };
            if result.is_changed() && result.ssh_restart_required {
                params.ssh_restart_required = true;
            }

            // 中断发生在步骤执行中：回滚错误和步骤结果一起报告
            let interrupted = rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst);

            match result.outcome {
                StepOutcome::Failed => {
                    self.logger.log_operation(
                        crate::i18n::tr("log_step_failed"),
                        &format!("{}: {}", kind.label(), result.message),
                    );
                },
                _ => {
                    self.logger.log_operation(
                        crate::i18n::tr("log_step_complete"),
                        &format!("{}: {}", kind.label(), result.message),
                    );
                },
            }

            // 失败处理策略：可选步骤只记录，核心步骤回滚并停止
            let stop = interrupted || (result.is_failed() && !kind.is_optional());
            let failures = if interrupted {
                self.rollback_on_interrupt(checkpoint, on_event)
            } else if stop {
                self.logger.log(crate::i18n::tr("log_rollback_auto"));
                let failures = rollback::undo_since(checkpoint);
                on_event(JobEvent::Log(crate::i18n::tr("log_rollback_auto").into()));
                failures
            } else {
                vec![]
            };
            if !failures.is_empty() {
                let message = crate::i18n::tr("log_rollback_failed")
                    .replace("{errors}", &failures.join("\n"));
                self.logger.log(&message);
                result.outcome = StepOutcome::Failed;
                result.message.push('\n');
                result.message.push_str(&message);
            }
            on_event(JobEvent::StepFinished(result.clone()));
            results.push(result);
            if stop {
                break;
            }
        }

        rollback::discard_since(checkpoint);
        // 临时源文件随 TempDir 清理
        drop(mirror_session);
        on_event(JobEvent::AllFinished);
        results
    }

    /// 准备临时软件源。
    ///
    /// - `Ok(None)`：未选择镜像或不需要（使用原始源）
    /// - `Ok(Some(session))`：临时源已就绪
    /// - `Err(reason)`：连接源失败（已自动重试 [`package_mirror::WARM_UP_ATTEMPTS`] 次）
    fn prepare_mirror(
        &self,
        on_event: &mut dyn FnMut(JobEvent),
    ) -> Result<Option<MirrorSession>, String> {
        if self.mirror.is_original() {
            return Ok(None);
        }
        let pm = system::detect_package_manager();
        let session = match MirrorSession::apply(self.mirror.clone(), pm) {
            Ok(session) => session,
            Err(e) => {
                // 准备失败（例如没有可改写的源）：按"取消"处理，回退原始源继续
                on_event(JobEvent::Log(
                    crate::i18n::tr("mirror_apply_failed").replace("{err}", &e.to_string()),
                ));
                return Ok(None);
            },
        };
        if !session.is_active() {
            on_event(JobEvent::Log(crate::i18n::tr("mirror_not_applied").into()));
            return Ok(Some(session));
        }

        let mirror_label = self.mirror.label();
        let log_path = artifacts::path_for("mirror", "log");
        on_event(JobEvent::Log(
            crate::i18n::tr("mirror_warming")
                .replace("{mirror}", &mirror_label)
                .replace("{log}", &log_path),
        ));

        let mut on_attempt = |attempt: usize, reason: String| {
            on_event(JobEvent::Log(
                crate::i18n::tr("mirror_attempt_failed")
                    .replace("{n}", &attempt.to_string())
                    .replace("{total}", &package_mirror::WARM_UP_ATTEMPTS.to_string())
                    .replace("{reason}", &reason),
            ));
        };

        match package_mirror::warm_up(&session, &log_path, &mut on_attempt) {
            Ok(()) => {
                on_event(JobEvent::Log(session.summary()));
                Ok(Some(session))
            },
            Err(reason) => Err(crate::i18n::tr("mirror_failed_reason")
                .replace("{mirror}", &mirror_label)
                .replace("{reason}", &reason)
                .replace("{log}", &log_path)),
        }
    }

    fn rollback_on_interrupt(
        &self,
        checkpoint: usize,
        on_event: &mut dyn FnMut(JobEvent),
    ) -> Vec<String> {
        self.logger.log(crate::i18n::tr("log_interrupt_rollback"));
        let failures = rollback::undo_since(checkpoint);
        on_event(JobEvent::Log(
            crate::i18n::tr("log_interrupt_rollback").into(),
        ));
        on_event(JobEvent::Interrupted);
        failures
    }
}
