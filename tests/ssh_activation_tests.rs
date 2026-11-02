#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use u2secure::application::job::{JobEvent, StepRunner};
use u2secure::application::steps::RestartSshStep;
use u2secure::domain::errors::DomainError;
use u2secure::domain::steps::{ExecuteParams, HardeningStep, StepKind, StepResult};
use u2secure::domain::undo::UndoAction;
use u2secure::infrastructure::{logger::FileLogger, rollback};

#[derive(Debug)]
struct Configure(PathBuf);

impl HardeningStep for Configure {
    fn kind(&self) -> StepKind {
        StepKind::SshPortChange
    }

    fn execute(&self, _: &ExecuteParams) -> Result<StepResult, DomainError> {
        for name in ["config", "rules"] {
            let path = self.0.join(name);
            let saved = path.with_extension("backup");
            std::fs::copy(&path, &saved).unwrap();
            rollback::register_file_backup(
                name.into(),
                saved.display().to_string(),
                path.display().to_string(),
            );
            std::fs::write(path, "2222").unwrap();
        }
        Ok(StepResult::changed(self.kind(), "configured").requiring_ssh_restart())
    }
}

#[derive(Debug)]
struct Apply {
    cancel_before: bool,
    cancel_after: bool,
}

impl HardeningStep for Apply {
    fn kind(&self) -> StepKind {
        StepKind::RestartSsh
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        if self.cancel_before {
            rollback::INTERRUPTED.store(true, Ordering::SeqCst);
        }
        let result = RestartSshStep.execute(params);
        if self.cancel_after {
            rollback::INTERRUPTED.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[test]
fn activation_failure_does_not_close_the_running_ssh_port() {
    let dir = tempfile::tempdir().unwrap();
    if let Ok(mode) = std::env::var("U2SECURE_ACTIVATION_CASE") {
        for name in ["config", "rules"] {
            std::fs::write(dir.path().join(name), "22").unwrap();
        }
        let older_undo = dir.path().join("older-undo");
        let marker = older_undo.clone();
        rollback::register_undo(UndoAction::new(
            "outside batch".into(),
            Box::new(move || std::fs::write(marker, "undone").unwrap()),
        ));
        let runner = StepRunner::new(Arc::new(FileLogger::with_path(dir.path().join("log"))))
            .with_report_dir(dir.path().display().to_string());
        let mut events = Vec::new();
        let results = runner.run_steps(
            vec![
                Box::new(Configure(dir.path().into())),
                Box::new(Apply {
                    cancel_before: mode == "cancel-before",
                    cancel_after: mode == "success-cancel",
                }),
            ],
            &ExecuteParams {
                apply_ssh_changes: true,
                ..Default::default()
            },
            &mut |event| events.push(event),
        );
        let attempted = !matches!(mode.as_str(), "syntax" | "unit" | "cancel-before");
        for name in ["config", "rules"] {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(name)).unwrap(),
                if attempted { "2222" } else { "22" },
                "{mode}: restoring old rules can block a running new port"
            );
        }
        assert_eq!(results.len(), 2);
        assert!(results[1].is_failed(), "{mode}: must not claim success");
        assert_eq!(results[1].ssh_activation_attempted, attempted);
        if attempted {
            assert_eq!(results[1].artifacts.len(), 1);
            assert!(
                results[1]
                    .message
                    .contains(u2secure::i18n::tr("result_ssh_activation_retained"))
            );
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, JobEvent::Log(message)
                if message == u2secure::i18n::tr("log_rollback_auto")
                    || message == u2secure::i18n::tr("log_interrupt_rollback")))
            );
        }
        assert_eq!(rollback::undo_depth(), 1);
        assert!(!older_undo.exists());
        assert!(rollback::undo_all().is_empty());
        assert!(older_undo.exists());
        return;
    }

    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let scripts = [
        ("sshd", "[ \"$U2SECURE_ACTIVATION_CASE\" != syntax ]"),
        (
            "systemctl",
            r#"case "$1" in
show) if [ "$U2SECURE_ACTIVATION_CASE" = unit ]; then echo LoadState=masked; else echo LoadState=loaded; fi ;;
restart) [ "$U2SECURE_ACTIVATION_CASE" != restart-failed ] ;;
is-active) if [ "$U2SECURE_ACTIVATION_CASE" = success-cancel ]; then echo active; else echo 'fixture status error' >&2; exit 3; fi ;;
*) exit 99 ;;
esac"#,
        ),
    ];
    for (name, script) in scripts {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for mode in [
        "status",
        "restart-failed",
        "success-cancel",
        "syntax",
        "unit",
        "cancel-before",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "activation_failure_does_not_close_the_running_ssh_port",
                "--nocapture",
            ])
            .env("PATH", &bin)
            .env("U2SECURE_ACTIVATION_CASE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
