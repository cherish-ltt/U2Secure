//! 执行器策略与异步执行测试
//!
//! 使用假步骤（不触碰真实系统），验证：
//! - 核心步骤失败 → 回滚并停止
//! - 可选步骤（9/10/11）失败 → 不回滚、继续后续步骤
//! - 中断 → 回滚并停止
//! - 后台线程执行可被取消（异步执行的关键行为）
//!
//! 注意：rollback/INTERRUPTED 是进程内全局状态，本文件内所有用例串行执行。

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use u2secure::application::job::{JobEvent, StepRunner};
use u2secure::domain::errors::DomainError;
use u2secure::domain::steps::{ExecuteParams, HardeningStep, StepKind, StepOutcome, StepResult};
use u2secure::infrastructure::logger::FileLogger;
use u2secure::infrastructure::rollback;

/// 串行化全局状态相关的用例
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// 可编程的假步骤
#[derive(Debug)]
struct FakeStep {
    kind: StepKind,
    behavior: Behavior,
}

#[derive(Debug, Clone, Copy)]
enum Behavior {
    Changed,
    Skipped,
    Failed,
    Error,
    /// 分片睡眠，便于测试取消
    Slow,
}

impl HardeningStep for FakeStep {
    fn kind(&self) -> StepKind {
        self.kind
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        match self.behavior {
            Behavior::Changed => Ok(StepResult::changed(self.kind, "ok")),
            Behavior::Skipped => Ok(StepResult::skipped(self.kind, "skip")),
            Behavior::Failed => Ok(StepResult::failed(self.kind, "soft failure")),
            Behavior::Error => Err(DomainError::SystemCommandFailed("hard failure".into())),
            Behavior::Slow => {
                for _ in 0..100 {
                    if rollback::INTERRUPTED.load(Ordering::SeqCst) {
                        return Ok(StepResult::failed(self.kind, "cancelled"));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(StepResult::changed(self.kind, "slow done"))
            },
        }
    }
}

fn fake(kind: StepKind, behavior: Behavior) -> Box<dyn HardeningStep + Send> {
    Box::new(FakeStep { kind, behavior })
}

/// 构造指向临时目录的执行器（不污染真实报告目录）
fn runner(dir: &tempfile::TempDir) -> StepRunner {
    let logger = FileLogger::with_path(dir.path().join("test.log"));
    StepRunner::new(Arc::new(logger)).with_report_dir(dir.path().to_string_lossy().to_string())
}

fn kinds(results: &[StepResult]) -> Vec<StepKind> {
    results.iter().map(|r| r.kind).collect()
}

#[test]
fn test_core_step_failure_stops_and_rolls_back() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    // 注册一个无害的撤销动作，验证失败时会执行回滚
    rollback::register_command_undo("noop".into(), vec!["true".into()]);
    assert_eq!(rollback::undo_depth(), 1);

    let steps = vec![
        fake(StepKind::Ufw, Behavior::Changed),
        fake(StepKind::Fail2ban, Behavior::Failed),
        fake(StepKind::RestartSsh, Behavior::Changed),
    ];
    let mut events = vec![];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |e| {
        events.push(format!("{e:?}"))
    });

    // 核心步骤失败：停止，后续步骤不执行
    assert_eq!(
        kinds(&results),
        vec![StepKind::Ufw, StepKind::Fail2ban],
        "核心步骤失败后不应继续执行"
    );
    assert_eq!(results[1].outcome, StepOutcome::Failed);
    // 回滚已执行
    assert_eq!(rollback::undo_depth(), 0, "失败后应回滚");
    assert!(events.iter().any(|e| e.contains("AllFinished")));
}

#[test]
fn test_hard_error_on_core_step_stops() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    let steps = vec![
        fake(StepKind::SshRootLogin, Behavior::Error),
        fake(StepKind::Ufw, Behavior::Changed),
    ];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |_| {});

    assert_eq!(kinds(&results), vec![StepKind::SshRootLogin]);
    assert_eq!(results[0].outcome, StepOutcome::Failed);
    assert!(results[0].message.contains("hard failure"));
}

#[test]
fn test_optional_step_failure_continues_without_rollback() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    rollback::register_command_undo("noop".into(), vec!["true".into()]);

    let steps = vec![
        fake(StepKind::Ufw, Behavior::Changed),
        fake(StepKind::SecurityScan, Behavior::Failed),
        fake(StepKind::RestartSsh, Behavior::Changed),
    ];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |_| {});

    // 可选步骤失败：不中断、不回滚
    assert_eq!(
        kinds(&results),
        vec![StepKind::Ufw, StepKind::SecurityScan, StepKind::RestartSsh]
    );
    assert_eq!(results[1].outcome, StepOutcome::Failed);
    assert_eq!(rollback::undo_depth(), 1, "可选步骤失败不应触发回滚");

    // 清理全局状态，避免影响其他用例
    rollback::undo_all();
}

#[test]
fn test_optional_step_hard_error_continues() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    let steps = vec![
        fake(StepKind::LogAudit, Behavior::Error),
        fake(StepKind::Ufw, Behavior::Changed),
    ];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |_| {});

    assert_eq!(kinds(&results), vec![StepKind::LogAudit, StepKind::Ufw]);
    assert_eq!(results[0].outcome, StepOutcome::Failed);
    assert_eq!(results[1].outcome, StepOutcome::Changed);
}

#[test]
fn test_skipped_step_is_not_checked() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    let steps = vec![fake(StepKind::RestartSsh, Behavior::Skipped)];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |_| {});

    assert_eq!(results[0].outcome, StepOutcome::Skipped);
    assert!(!results[0].is_changed());
    assert!(!results[0].is_failed());
}

#[test]
fn test_spawn_emits_progress_events() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    let steps = vec![
        fake(StepKind::SystemUpdate, Behavior::Changed),
        fake(StepKind::Ufw, Behavior::Changed),
    ];
    let runner = runner(&dir);
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = {
        // 直接使用 spawn 需要 AllSteps 过滤，改用 run_steps + 线程以覆盖同一路径
        let runner_dir = dir.path().to_string_lossy().to_string();
        std::thread::spawn(move || {
            let logger = FileLogger::with_path(std::path::Path::new(&runner_dir).join("spawn.log"));
            let runner = StepRunner::new(Arc::new(logger)).with_report_dir(runner_dir);
            let mut emit = |e: JobEvent| {
                let _ = tx.send(e);
            };
            runner.run_steps(steps, &ExecuteParams::default(), &mut emit)
        })
    };

    let mut started = 0;
    let mut finished = 0;
    let mut all_finished = false;
    for event in rx.iter() {
        match event {
            JobEvent::StepStarted { .. } => started += 1,
            JobEvent::StepFinished(_) => finished += 1,
            JobEvent::AllFinished => {
                all_finished = true;
                break;
            },
            _ => {},
        }
    }
    handle.join().expect("join");

    assert_eq!(started, 2);
    assert_eq!(finished, 2);
    assert!(all_finished);
    let _ = runner;
}

#[test]
fn test_interrupt_cancels_running_batch() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    rollback::register_command_undo("noop".into(), vec!["true".into()]);

    let steps = vec![
        fake(StepKind::Ufw, Behavior::Slow),
        fake(StepKind::Fail2ban, Behavior::Changed),
    ];
    let runner = runner(&dir);
    let handle = runner.spawn_steps(steps, ExecuteParams::default());

    // 等待第一步开始后请求取消
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    rollback::INTERRUPTED.store(true, Ordering::SeqCst);

    let mut saw_interrupt = false;
    let mut all_finished = false;
    for event in handle.rx.iter() {
        match event {
            JobEvent::Interrupted => saw_interrupt = true,
            JobEvent::AllFinished => {
                all_finished = true;
                break;
            },
            _ => {},
        }
    }
    handle.join();

    assert!(started.elapsed() < Duration::from_secs(3), "取消应立即生效");
    assert!(saw_interrupt, "应产生中断事件");
    assert!(all_finished, "应正常收尾");
    assert_eq!(rollback::undo_depth(), 0, "中断后应回滚已注册修改");
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
}
