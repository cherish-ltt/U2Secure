#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use u2secure::infrastructure::{rollback, system};

#[test]
fn creation_registers_rollback_before_initialization() {
    for failure in ["useradd", "usermod", "none"] {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls");
        for program in ["useradd", "usermod", "mkdir", "chown", "chmod", "userdel"] {
            let path = dir.path().join(program);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' '{program}' >> \"$U2SECURE_CALLS\"\nif [ \"$U2SECURE_FAIL\" = '{program}' ]; then printf 'fixture failure\\n' >&2; exit 6; fi\n"
                ),
            )
            .unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_creation_child", "--nocapture"])
            .env("PATH", dir.path())
            .env("U2SECURE_CREATION_CHILD", "1")
            .env("U2SECURE_FAIL", failure)
            .env("U2SECURE_CALLS", &log)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{failure}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let calls = fs::read_to_string(log).unwrap();
        assert_eq!(calls.contains("userdel"), failure != "useradd");
    }
}

#[test]
fn isolated_creation_child() {
    if std::env::var("U2SECURE_CREATION_CHILD").as_deref() != Ok("1") {
        return;
    }
    let failure = std::env::var("U2SECURE_FAIL").unwrap();
    let result = system::create_system_user("fixture-user");
    assert_eq!(result.is_ok(), failure == "none");
    assert_eq!(rollback::undo_depth(), usize::from(failure != "useradd"));
    rollback::undo_all();
}
