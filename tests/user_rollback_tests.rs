#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use u2secure::domain::undo::UndoAction;
use u2secure::infrastructure::rollback;

#[test]
fn user_removal_reports_command_failures() {
    for mode in ["spawn-fails", "nonzero", "success"] {
        let dir = tempfile::tempdir().unwrap();
        if mode != "spawn-fails" {
            let program = dir.path().join("userdel");
            fs::write(
                &program,
                "#!/bin/sh\n[ \"$1\" = -r ] && [ \"$2\" = fixture-user ] || exit 99\nprintf '%s' 'fixture stdout'\nif [ \"$U2SECURE_USERDEL_MODE\" = nonzero ]; then printf '%s' 'fixture stderr' >&2; exit 7; fi\n",
            )
            .unwrap();
            fs::set_permissions(program, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_user_removal_child", "--nocapture"])
            .env("PATH", dir.path())
            .env("U2SECURE_USERDEL_MODE", mode)
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

#[test]
fn isolated_user_removal_child() {
    let Ok(mode) = std::env::var("U2SECURE_USERDEL_MODE") else {
        return;
    };
    let continued = Arc::new(AtomicBool::new(false));
    let flag = continued.clone();
    rollback::register_undo(UndoAction::new(
        "independent recovery".into(),
        Box::new(move || flag.store(true, Ordering::SeqCst)),
    ));
    rollback::register_user_remove("fixture-user".into());
    let failures = rollback::undo_all();
    assert!(continued.load(Ordering::SeqCst));
    assert_eq!(failures.len(), usize::from(mode != "success"));
    if let Some(error) = failures.first() {
        assert!(error.contains("fixture-user"));
        assert!(error.contains("userdel"));
        if mode == "nonzero" {
            assert!(error.contains('7'));
            assert!(error.contains("fixture stdout"));
            assert!(error.contains("fixture stderr"));
        } else {
            assert!(error.contains("No such file or directory"));
        }
    }
}
