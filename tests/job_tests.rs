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

use u2secure::application::job::{JobEvent, StepRunner, execution_plan};
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
    ConfigChanged,
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

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        if self.kind == StepKind::RestartSsh {
            assert!(params.apply_ssh_changes && params.ssh_restart_required);
        }
        match self.behavior {
            Behavior::Changed => Ok(StepResult::changed(self.kind, "ok")),
            Behavior::ConfigChanged => {
                Ok(StepResult::changed(self.kind, "config written").requiring_ssh_restart())
            },
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

#[test]
fn ssh_activation_uses_actual_changes_and_explicit_consent() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    for kind in [
        StepKind::SshPortChange,
        StepKind::SshPasswordAuth,
        StepKind::SshRootLogin,
    ] {
        assert_eq!(execution_plan(&[kind]), [kind, StepKind::RestartSsh]);
        for (behavior, consent, pending, expected) in [
            (Behavior::ConfigChanged, true, false, StepOutcome::Changed),
            (Behavior::Skipped, true, false, StepOutcome::Skipped),
            (Behavior::Changed, true, false, StepOutcome::Skipped),
            (Behavior::ConfigChanged, false, false, StepOutcome::Skipped),
            (Behavior::Skipped, true, true, StepOutcome::Changed),
            (Behavior::Skipped, false, true, StepOutcome::Skipped),
            (Behavior::Failed, true, false, StepOutcome::Failed),
        ] {
            let plan = execution_plan(&[kind]);
            let steps = plan
                .into_iter()
                .map(|step| {
                    fake(
                        step,
                        if step == kind {
                            behavior
                        } else {
                            Behavior::Changed
                        },
                    )
                })
                .collect();
            let params = ExecuteParams {
                apply_ssh_changes: consent,
                ssh_restart_required: pending,
                ..Default::default()
            };
            let results = runner(&dir).run_steps(steps, &params, &mut |_| {});
            if matches!(behavior, Behavior::Failed) {
                assert_eq!(results.len(), 1);
                assert!(results[0].is_failed());
                continue;
            }
            assert_eq!(results.len(), 2);
            assert_eq!(results[1].kind, StepKind::RestartSsh);
            assert_eq!(results[1].outcome, expected);
            if !consent && (pending || matches!(behavior, Behavior::ConfigChanged)) {
                assert_eq!(results[1].message, u2secure::i18n::tr("result_ssh_pending"));
            }
        }
    }
    assert_eq!(execution_plan(&[StepKind::Ufw]), [StepKind::Ufw]);
    assert_eq!(
        execution_plan(&[StepKind::RestartSsh, StepKind::SshPortChange]),
        [StepKind::SshPortChange, StepKind::RestartSsh]
    );
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

#[derive(Debug)]
struct FileStep {
    path: std::path::PathBuf,
    interrupt: bool,
}

#[derive(Debug)]
struct UnrestorableStep {
    path: std::path::PathBuf,
    interrupt: bool,
}

impl HardeningStep for UnrestorableStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPortChange
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        std::fs::write(&self.path, "only backup").unwrap();
        rollback::register_file_backup(
            "restore fixture".into(),
            self.path.display().to_string(),
            self.path.join("missing/config").display().to_string(),
        );
        rollback::INTERRUPTED.store(self.interrupt, Ordering::SeqCst);
        Ok(StepResult::failed(self.kind(), "fixture failed"))
    }
}

#[test]
fn rollback_failures_are_returned_in_step_results_and_events() {
    let _guard = serial();
    for interrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("backup");
        let mut events = vec![];
        let results = runner(&dir).run_steps(
            vec![Box::new(UnrestorableStep {
                path: backup.clone(),
                interrupt,
            })],
            &ExecuteParams::default(),
            &mut |event| events.push(event),
        );
        assert_eq!(results.len(), 1);
        assert!(results[0].is_failed());
        assert!(results[0].message.contains(&backup.display().to_string()));
        assert!(results[0].message.contains("Not a directory"));
        assert!(events.iter().any(|event| matches!(event,
            JobEvent::StepFinished(result) if result.message == results[0].message)));
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "only backup");
        rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    }
}

impl HardeningStep for FileStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPortChange
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let backup = self.path.with_extension("backup");
        std::fs::copy(&self.path, &backup).unwrap();
        rollback::register_file_backup(
            "restore fixture".into(),
            backup.display().to_string(),
            self.path.display().to_string(),
        );
        std::fs::write(&self.path, "configured").unwrap();
        if self.interrupt {
            rollback::INTERRUPTED.store(true, Ordering::SeqCst);
        }
        Ok(StepResult::changed(self.kind(), "fixture changed"))
    }
}

#[test]
fn successful_batch_survives_later_failure_or_cancellation() {
    let _guard = serial();
    for interrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, "original").unwrap();
        std::fs::write(&second, "original").unwrap();
        let runner = runner(&dir);
        runner.run_steps(
            vec![Box::new(FileStep {
                path: first.clone(),
                interrupt: false,
            })],
            &ExecuteParams::default(),
            &mut |_| {},
        );
        runner.run_steps(
            vec![
                Box::new(FileStep {
                    path: second.clone(),
                    interrupt,
                }),
                fake(StepKind::Fail2ban, Behavior::Failed),
            ],
            &ExecuteParams::default(),
            &mut |_| {},
        );
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "configured");
        assert!(first.with_extension("backup").exists());
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "original");
        assert_eq!(rollback::undo_depth(), 0);
        rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    }
}

#[test]
fn batch_does_not_consume_preexisting_undo_records() {
    let _guard = serial();
    let undone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&undone);
    rollback::register_undo(u2secure::domain::undo::UndoAction::new(
        "outside batch".into(),
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    ));
    let dir = tempfile::tempdir().unwrap();
    for behavior in [Behavior::Changed, Behavior::Failed] {
        runner(&dir).run_steps(
            vec![fake(StepKind::Ufw, behavior)],
            &ExecuteParams::default(),
            &mut |_| {},
        );
        assert_eq!(rollback::undo_depth(), 1);
        assert!(!undone.load(Ordering::SeqCst));
    }
    rollback::undo_all();
    assert!(undone.load(Ordering::SeqCst));
}

#[test]
fn test_created_users_key_is_not_generated_twice() {
    use u2secure::domain::steps::SshKeyAction;
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let params = ExecuteParams {
        new_username: Some("fixture-user".into()),
        ssh_key_username: Some("fixture-user".into()),
        ssh_key_action: Some(SshKeyAction::GenerateNew),
        ..Default::default()
    };
    let steps = vec![
        fake(StepKind::UserCreation, Behavior::Changed),
        fake(StepKind::SshKeySetup, Behavior::Error),
        fake(StepKind::Ufw, Behavior::Changed),
    ];
    let results = runner(&dir).run_steps(steps, &params, &mut |_| {});
    assert_eq!(results.len(), 3);
    assert_eq!(results[1].outcome, StepOutcome::Skipped);
    assert_eq!(results[2].outcome, StepOutcome::Changed);
}

#[test]
fn test_key_setup_remains_enabled_without_successful_matching_creation() {
    use u2secure::domain::steps::SshKeyAction;
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    for (created, target, action) in [
        (false, "fixture-user", SshKeyAction::GenerateNew),
        (true, "another-user", SshKeyAction::GenerateNew),
        (
            true,
            "fixture-user",
            SshKeyAction::PasteKey("TEST_MARKER".into()),
        ),
    ] {
        let params = ExecuteParams {
            new_username: Some("fixture-user".into()),
            ssh_key_username: Some(target.into()),
            ssh_key_action: Some(action),
            ..Default::default()
        };
        let mut steps = Vec::new();
        if created {
            steps.push(fake(StepKind::UserCreation, Behavior::Changed));
        }
        steps.push(fake(StepKind::SshKeySetup, Behavior::Changed));
        let results = runner(&dir).run_steps(steps, &params, &mut |_| {});
        assert_eq!(results.last().unwrap().outcome, StepOutcome::Changed);
    }
}

#[test]
fn test_core_step_failure_stops_and_rolls_back() {
    let _guard = serial();
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
    let dir = tempfile::tempdir().expect("tempdir");

    let path = dir.path().join("config");
    std::fs::write(&path, "original").unwrap();

    let steps = vec![
        Box::new(FileStep {
            path: path.clone(),
            interrupt: false,
        }),
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
        vec![StepKind::SshPortChange, StepKind::Fail2ban],
        "核心步骤失败后不应继续执行"
    );
    assert_eq!(results[1].outcome, StepOutcome::Failed);
    // 回滚已执行
    assert_eq!(rollback::undo_depth(), 0, "失败后应回滚");
    assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
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

    let path = dir.path().join("config");
    std::fs::write(&path, "original").unwrap();

    let steps = vec![
        Box::new(FileStep {
            path: path.clone(),
            interrupt: false,
        }),
        fake(StepKind::SecurityScan, Behavior::Failed),
        fake(StepKind::RestartSsh, Behavior::Changed),
    ];
    let results = runner(&dir).run_steps(steps, &ExecuteParams::default(), &mut |_| {});

    // 可选步骤失败：不中断、不回滚
    assert_eq!(
        kinds(&results),
        vec![
            StepKind::SshPortChange,
            StepKind::SecurityScan,
            StepKind::RestartSsh
        ]
    );
    assert_eq!(results[1].outcome, StepOutcome::Failed);
    assert_eq!(rollback::undo_depth(), 0, "批次正常完成应提交撤销记录");
    assert_eq!(std::fs::read_to_string(path).unwrap(), "configured");
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

    let path = dir.path().join("config");
    std::fs::write(&path, "original").unwrap();

    let steps = vec![
        Box::new(FileStep {
            path: path.clone(),
            interrupt: false,
        }),
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
    assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
    rollback::INTERRUPTED.store(false, Ordering::SeqCst);
}
