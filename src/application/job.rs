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
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
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
    let selected_set: HashSet<StepKind> = selected.iter().copied().collect();
    StepKind::all()
        .iter()
        .filter(|kind| selected_set.contains(kind))
        .map(|kind| step_for(*kind))
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
    /// 用户中断，已回滚
    Interrupted,
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
        let selected_set: HashSet<StepKind> = selected.iter().copied().collect();
        let steps: Vec<Box<dyn HardeningStep + Send>> = StepKind::all()
            .iter()
            .filter(|kind| selected_set.contains(kind))
            .map(|kind| step_for(*kind))
            .collect();
        self.spawn_steps(steps, params)
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

    /// 执行给定的步骤列表（策略与 `run` 完全一致，便于注入测试步骤）
    pub fn run_steps(
        &self,
        steps: Vec<Box<dyn HardeningStep + Send>>,
        params: &ExecuteParams,
        on_event: &mut dyn FnMut(JobEvent),
    ) -> Vec<StepResult> {
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
        let mirror_session = self.prepare_mirror(on_event);
        if let Some(session) = &mirror_session
            && session.is_active()
        {
            params.mirror = session.override_value();
        }

        let mut results = vec![];
        for (index, step) in steps.iter().enumerate() {
            let kind = step.kind();

            if rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst) {
                self.rollback_on_interrupt(on_event);
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

            let result = match step.execute(&step_params) {
                Ok(result) => result,
                Err(e) => StepResult::failed(
                    kind,
                    crate::i18n::tr("log_step_failed_detail").replace("{err}", &e.to_string()),
                ),
            };

            // 中断发生在步骤执行中：先记录结果，再统一走中断回滚
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

            on_event(JobEvent::StepFinished(result.clone()));
            results.push(result);

            if interrupted {
                self.rollback_on_interrupt(on_event);
                break;
            }

            // 失败处理策略：可选步骤只记录，核心步骤回滚并停止
            let failed = results.last().is_some_and(|r| r.is_failed());
            if failed && !kind.is_optional() {
                self.logger.log(crate::i18n::tr("log_rollback_auto"));
                rollback::undo_all();
                on_event(JobEvent::Log(crate::i18n::tr("log_rollback_auto").into()));
                break;
            }
        }

        // 临时源文件随 TempDir 清理
        drop(mirror_session);
        on_event(JobEvent::AllFinished);
        results
    }

    /// 准备临时软件源（失败自动降级为原始源，不阻塞流程）
    fn prepare_mirror(&self, on_event: &mut dyn FnMut(JobEvent)) -> Option<MirrorSession> {
        if self.mirror.is_original() {
            return None;
        }
        let pm = system::detect_package_manager();
        let session = match MirrorSession::apply(self.mirror, pm) {
            Ok(session) => session,
            Err(e) => {
                on_event(JobEvent::Log(
                    crate::i18n::tr("mirror_apply_failed").replace("{err}", &e.to_string()),
                ));
                return None;
            },
        };
        if !session.is_active() {
            on_event(JobEvent::Log(crate::i18n::tr("mirror_not_applied").into()));
            return Some(session);
        }

        on_event(JobEvent::Log(
            crate::i18n::tr("mirror_warming").replace("{mirror}", self.mirror.label()),
        ));
        let log_path = artifacts::path_for("mirror", "log");
        match package_mirror::warm_up(&session, &log_path) {
            Ok(()) => on_event(JobEvent::Log(session.summary())),
            Err(e) => on_event(JobEvent::Log(
                crate::i18n::tr("mirror_warmup_failed").replace("{err}", &e.to_string()),
            )),
        }
        Some(session)
    }

    fn rollback_on_interrupt(&self, on_event: &mut dyn FnMut(JobEvent)) {
        self.logger.log(crate::i18n::tr("log_interrupt_rollback"));
        rollback::undo_all();
        on_event(JobEvent::Log(
            crate::i18n::tr("log_interrupt_rollback").into(),
        ));
        on_event(JobEvent::Interrupted);
    }
}
