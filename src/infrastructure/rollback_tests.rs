use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

#[test]
fn rollback_commands_and_checkpoints_use_a_private_process() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["apt", "yum", "dnf", "fixture-command"] {
        let path = dir.path().join(name);
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' '{name}' \"$*\" >> \"$U2C_UNDO_LOG\"\n"),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let log = dir.path().join("commands.log");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "infrastructure::rollback::tests::isolated_rollback_commands",
            "--nocapture",
        ])
        .env("PATH", dir.path())
        .env("U2C_UNDO_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let commands = fs::read_to_string(log).unwrap();
    assert_eq!(
        commands
            .lines()
            .filter(|line| *line == "remove -y fixture-package")
            .count(),
        3
    );
    assert!(commands.contains("fixture-command\nARGUMENT_MARKER"));
}

#[test]
fn isolated_rollback_commands() {
    if std::env::var_os("U2C_UNDO_LOG").is_none() {
        return;
    }
    init_signal_handler().unwrap();
    assert!(init_signal_handler().is_err());
    let count = Arc::new(AtomicUsize::new(0));
    for increment in [1, 10, 100] {
        let count = Arc::clone(&count);
        register_undo(UndoAction::new(
            "count".into(),
            Box::new(move || {
                count.fetch_add(increment, Ordering::SeqCst);
            }),
        ));
    }
    assert_eq!(undo_depth(), 3);
    discard_since(2);
    assert!(undo_since(1).is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 10);
    assert_eq!(undo_depth(), 1);
    assert!(undo_all().is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 11);
    register_package_remove("remove fixture".into(), "fixture-package".into());
    register_command_undo(
        "command".into(),
        vec!["fixture-command".into(), "ARGUMENT_MARKER".into()],
    );
    register_command_undo("empty".into(), vec![]);
    register_command_undo("no args".into(), vec!["NEVER_EXECUTE".into()]);
    assert!(undo_all().is_empty());
    assert_eq!(undo_depth(), 0);
}
