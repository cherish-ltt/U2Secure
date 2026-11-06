use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use u2secure::application::job::{JobEvent, StepRunner};
use u2secure::domain::errors::DomainError;
use u2secure::domain::steps::StepOutcome;
use u2secure::domain::steps::{ExecuteParams, HardeningStep, StepKind, StepResult};
use u2secure::infrastructure::logger::FileLogger;
use u2secure::infrastructure::{backup, rollback};

#[derive(Debug)]
struct Unchanged;

impl HardeningStep for Unchanged {
    fn kind(&self) -> StepKind {
        StepKind::SystemUpdate
    }

    fn execute(&self, _: &ExecuteParams) -> Result<StepResult, DomainError> {
        Ok(StepResult::skipped(
            self.kind(),
            "RAW_OUTPUT_MUST_NOT_BE_ARCHIVED",
        ))
    }
}

#[derive(Debug)]
struct Change {
    kind: StepKind,
    path: PathBuf,
    fail: bool,
    interrupt: bool,
    activate: bool,
    destroy_original: bool,
}

impl HardeningStep for Change {
    fn kind(&self) -> StepKind {
        self.kind
    }

    fn execute(&self, _: &ExecuteParams) -> Result<StepResult, DomainError> {
        if !self.activate {
            let saved = backup::backup_file(&self.path)?;
            if let Some(saved) = saved {
                rollback::register_file_backup(
                    "restore fixture".into(),
                    saved.display().to_string(),
                    self.path.display().to_string(),
                );
            }
            std::fs::write(&self.path, "changed").unwrap();
            if self.destroy_original {
                std::fs::remove_file(&self.path).unwrap();
                std::fs::create_dir(&self.path).unwrap();
            }
        }
        if self.interrupt {
            rollback::INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let mut result = StepResult::new(
            self.kind,
            if self.fail {
                StepOutcome::Failed
            } else {
                StepOutcome::Changed
            },
            "RAW_PRIVATE_OUTPUT",
        );
        result.ssh_activation_attempted = self.activate;
        Ok(result)
    }
}

fn change(path: &Path, kind: StepKind) -> Change {
    Change {
        kind,
        path: path.into(),
        fail: false,
        interrupt: false,
        activate: false,
        destroy_original: false,
    }
}

fn run(dir: &Path, steps: Vec<Box<dyn HardeningStep + Send>>) -> Value {
    let mut saved = None;
    runner(dir).run_steps(
        steps,
        &ExecuteParams {
            apply_ssh_changes: true,
            ssh_restart_required: true,
            ..ExecuteParams::default()
        },
        &mut |event| {
            if let JobEvent::BatchRecord { result } = event {
                saved = Some(result.unwrap());
            }
        },
    );
    let text = std::fs::read_to_string(saved.unwrap()).unwrap();
    assert!(!text.contains("RAW_PRIVATE_OUTPUT"));
    serde_json::from_str(&text).unwrap()
}

#[test]
fn repeated_configuration_backups_keep_step_order_and_batch_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, "initial").unwrap();
    let first = run(
        dir.path(),
        vec![
            Box::new(change(&path, StepKind::SshPortChange)),
            Box::new(change(&path, StepKind::SshPasswordAuth)),
        ],
    );
    let second = run(
        dir.path(),
        vec![Box::new(change(&path, StepKind::SshPortChange))],
    );
    assert_ne!(first["batch_id"], second["batch_id"]);
    let backups = first["backups"].as_array().unwrap();
    assert_eq!(backups.len(), 2);
    for (index, backup) in backups.iter().enumerate() {
        assert_eq!(backup["step"], index + 1);
        assert_eq!(backup["sequence"], index + 1);
        assert_eq!(backup["retention"], "present");
        assert_eq!(backup["restore"], "not_attempted");
        assert_eq!(
            first["undo_actions"][index]["outcome"],
            "discarded_without_execution"
        );
    }
    assert_ne!(backups[0]["backup_path"], backups[1]["backup_path"]);
    assert_eq!(
        std::fs::read_to_string(backups[0]["backup_path"].as_str().unwrap()).unwrap(),
        "initial"
    );
    assert_eq!(
        std::fs::read_to_string(backups[1]["backup_path"].as_str().unwrap()).unwrap(),
        "changed"
    );
    assert_eq!(first["steps"][0]["outcome"], "changed");
    assert_eq!(first["steps"][0]["final_disposition"], "retained");
    assert_eq!(first["steps"][0]["live_log"]["may_be_shared"], true);
}

#[test]
fn core_failure_and_interruption_keep_original_outcomes_and_report_reverse_undo() {
    for interrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, "initial").unwrap();
        let mut ending = change(&path, StepKind::Fail2ban);
        ending.fail = !interrupt;
        ending.interrupt = interrupt;
        let record = run(
            dir.path(),
            vec![
                Box::new(change(&path, StepKind::SshPortChange)),
                Box::new(ending),
                Box::new(Unchanged),
            ],
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "initial");
        assert_eq!(
            record["status"],
            if interrupt { "interrupted" } else { "failed" }
        );
        assert_eq!(record["steps"][0]["outcome"], "changed");
        assert_eq!(
            record["steps"][0]["final_disposition"],
            "registered_undo_attempted_other_changes_unknown"
        );
        assert_eq!(record["steps"][2]["execution"], "not_executed");
        assert_eq!(record["undo_actions"][0]["rollback_order"], 2);
        assert_eq!(record["undo_actions"][1]["rollback_order"], 1);
        for backup in record["backups"].as_array().unwrap() {
            assert_eq!(backup["restore"], "restored");
            assert_eq!(backup["cleanup"], "removed");
            assert_eq!(backup["retention"], "missing");
        }
    }
}

#[test]
fn optional_failure_continues_and_activation_failure_retains_modifications() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, "initial").unwrap();
    let mut optional = change(&path, StepKind::SecurityScan);
    optional.fail = true;
    let record = run(dir.path(), vec![Box::new(optional), Box::new(Unchanged)]);
    assert_eq!(record["status"], "completed_with_optional_failures");
    assert_eq!(
        record["steps"][0]["final_disposition"],
        "unknown_partial_changes"
    );
    assert_eq!(record["steps"][1]["outcome"], "skipped");
    assert_eq!(
        record["undo_actions"][0]["outcome"],
        "discarded_without_execution"
    );
    for interrupt in [false, true] {
        let mut ending = change(&path, StepKind::RestartSsh);
        ending.activate = true;
        ending.fail = !interrupt;
        ending.interrupt = interrupt;
        let record = run(
            dir.path(),
            vec![
                Box::new(change(&path, StepKind::SshPortChange)),
                Box::new(ending),
            ],
        );
        assert_eq!(record["ssh_activation_attempted"], true);
        assert_eq!(
            record["disposition"],
            "retained_after_ssh_activation_attempt"
        );
        assert_eq!(
            record["steps"][1]["outcome"],
            if interrupt { "changed" } else { "failed" }
        );
        assert_eq!(record["steps"][1]["reported_outcome"], "failed");
        assert_eq!(
            record["steps"][0]["final_disposition"],
            "retained_after_ssh_activation_attempt"
        );
        assert_eq!(
            record["undo_actions"][0]["outcome"],
            "discarded_without_execution"
        );
        assert_eq!(record["backups"][0]["retention"], "present");
    }
}

#[test]
fn absent_original_and_failed_restore_are_not_reported_as_restored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let record = run(dir.path(), vec![Box::new(change(&path, StepKind::Ufw))]);
    assert_eq!(record["backups"][0]["original_state"], "absent");
    assert_eq!(record["backups"][0]["retention"], "no_backup");
    assert!(record["backups"][0]["undo_sequence"].is_null());
    let mut failed = change(&path, StepKind::Ufw);
    failed.fail = true;
    failed.destroy_original = true;
    let record = run(dir.path(), vec![Box::new(failed)]);
    assert_eq!(record["backups"][0]["restore"], "failed");
    assert_eq!(record["backups"][0]["retention"], "present");
    assert_eq!(record["undo_actions"][0]["outcome"], "returned_error");
}

#[test]
fn persistence_failure_does_not_change_retention_or_undo_policy() {
    let dir = tempfile::tempdir().unwrap();
    let report_path = dir.path().join("not-a-directory");
    std::fs::write(&report_path, "existing").unwrap();
    for fail in [false, true] {
        let original = dir.path().join("config");
        std::fs::write(&original, "initial").unwrap();
        let mut step = change(&original, StepKind::Ufw);
        step.fail = fail;
        let mut save_failure = false;
        let results = runner(dir.path())
            .with_report_dir(report_path.display().to_string())
            .run_steps(
                vec![Box::new(step)],
                &ExecuteParams::default(),
                &mut |event| {
                    if let JobEvent::BatchRecord { result } = event {
                        save_failure = result.is_err();
                    }
                },
            );
        assert!(save_failure);
        assert_eq!(results[0].is_failed(), fail);
        assert_eq!(
            std::fs::read_to_string(original).unwrap(),
            if fail { "initial" } else { "changed" }
        );
        assert_eq!(std::fs::read_to_string(&report_path).unwrap(), "existing");
    }
}

fn records(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect()
}

fn runner(dir: &Path) -> StepRunner {
    StepRunner::new(Arc::new(FileLogger::with_path(dir.join("operations.log"))))
        .with_report_dir(dir.display().to_string())
}

#[test]
fn completed_batch_persists_a_private_unique_record_without_raw_output() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner(dir.path());
    for count in 1..=2 {
        let mut events = Vec::new();
        runner.run_steps(
            vec![Box::new(Unchanged)],
            &ExecuteParams::default(),
            &mut |event| {
                events.push(event);
            },
        );
        assert!(matches!(events.last(), Some(JobEvent::AllFinished)));
        let paths = records(dir.path());
        assert_eq!(
            paths.len(),
            count,
            "completed batches need independent records"
        );
        for path in paths {
            let bytes = std::fs::read(&path).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("RAW_OUTPUT_MUST_NOT_BE_ARCHIVED"));
            let record: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(record["steps"][0]["outcome"], "skipped");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}

#[test]
fn empty_plan_runner_skip_and_returned_error_are_distinct() {
    #[derive(Debug)]
    struct FailsToReturn;
    impl HardeningStep for FailsToReturn {
        fn kind(&self) -> StepKind {
            StepKind::Ufw
        }

        fn execute(&self, _: &ExecuteParams) -> Result<StepResult, DomainError> {
            Err(DomainError::PreconditionFailed("RAW_PRIVATE_OUTPUT".into()))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let empty = run(dir.path(), vec![]);
    assert_eq!(empty["status"], "empty_plan");
    assert_eq!(empty["disposition"], "no_steps_executed");
    let error = run(dir.path(), vec![Box::new(FailsToReturn)]);
    assert_eq!(error["steps"][0]["execution"], "returned_error");
    assert!(error["steps"][0]["outcome"].is_null());
    assert_eq!(error["steps"][0]["reported_outcome"], "failed");
    assert_eq!(
        error["steps"][0]["final_disposition"],
        "unknown_partial_changes"
    );
    let mut path = None;
    runner(dir.path()).run_steps(
        vec![Box::new(change(
            &dir.path().join("must-not-exist"),
            StepKind::RestartSsh,
        ))],
        &ExecuteParams::default(),
        &mut |event| {
            if let JobEvent::BatchRecord { result } = event {
                path = Some(result.unwrap());
            }
        },
    );
    let skipped: Value = serde_json::from_slice(&std::fs::read(path.unwrap()).unwrap()).unwrap();
    assert_eq!(skipped["steps"][0]["execution"], "runner_skipped");
    assert_eq!(skipped["steps"][0]["outcome"], "skipped");
    assert!(!dir.path().join("must-not-exist").exists());
}

#[cfg(unix)]
#[test]
fn firewall_records_absent_files_service_failure_and_cleanup_failure_separately() {
    use std::os::unix::fs::PermissionsExt;
    use u2secure::infrastructure::ufw::Ufw;

    #[derive(Debug)]
    struct FirewallStep(PathBuf);
    impl HardeningStep for FirewallStep {
        fn kind(&self) -> StepKind {
            StepKind::Ufw
        }
        fn execute(&self, _: &ExecuteParams) -> Result<StepResult, DomainError> {
            Ufw::new(&self.0, self.0.join("fake-ufw")).allow_port(2222, true)?;
            Ok(StepResult::failed(self.kind(), "trigger fixture rollback"))
        }
    }
    for scenario in ["changed", "unchanged", "fail-reload", "fail-cleanup"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for file in ["user.rules", "ufw.conf"] {
            std::fs::write(root.join(file), "original\n").unwrap();
        }
        std::fs::write(root.join(scenario), "").unwrap();
        let program = root.join("fake-ufw");
        std::fs::write(
            &program,
            r#"#!/bin/sh
cd "${0%/*}" || exit 70
case "$1" in
  status) printf 'Status: active\n';;
  allow)
    [ ! -f unchanged ] || exit 0
    printf 'changed\n' > user.rules
    printf 'changed\n' > user6.rules;;
  reload)
    [ ! -f fail-reload ] || exit 23
    if [ -f fail-cleanup ]; then
      for saved in user.rules.bak.*; do /bin/rm "$saved" || exit 71; done
    fi;;
  *) exit 72;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let record = run(root, vec![Box::new(FirewallStep(root.into()))]);
        assert_eq!(
            std::fs::read_to_string(root.join("user.rules")).unwrap(),
            "original\n"
        );
        assert!(!root.join("user6.rules").exists());
        let backups = record["backups"].as_array().unwrap();
        assert_eq!(backups.len(), 3);
        assert_eq!(backups[1]["original_state"], "absent");
        assert_eq!(backups[1]["retention"], "no_backup");
        assert_eq!(
            backups[0]["restore"],
            if scenario == "unchanged" {
                "already_matched"
            } else {
                "restored"
            }
        );
        assert_eq!(record["undo_actions"][0]["kind"], "ufw_restore");
        if scenario.starts_with("fail-") {
            assert_eq!(record["undo_actions"][0]["outcome"], "returned_error");
            assert_eq!(backups[2]["cleanup"], "not_attempted");
            assert_eq!(backups[2]["retention"], "present");
        } else {
            assert_eq!(record["undo_actions"][0]["outcome"], "returned_ok");
            assert_eq!(backups[1]["cleanup"], "not_applicable");
            assert_eq!(backups[2]["retention"], "missing");
        }
        assert_eq!(
            backups[0]["cleanup"],
            match scenario {
                "fail-reload" => "not_attempted",
                "fail-cleanup" => "failed",
                _ => "removed",
            }
        );
        assert_eq!(
            backups[0]["retention"],
            if scenario == "fail-reload" {
                "present"
            } else {
                "missing"
            }
        );
    }
}
