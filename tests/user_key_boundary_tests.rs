#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;

#[test]
fn user_creation_reuses_secure_key_directory_without_path_commands() {
    for mode in [
        "normal",
        "directory-link",
        "useradd-fails",
        "existing-user",
        "group-fails",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let home = dir.path().join("custom-home");
        let victim = dir.path().join("victim");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&home).unwrap();
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(victim.join("marker"), "UNTOUCHED").unwrap();
        if mode == "directory-link" {
            symlink(&victim, home.join(".ssh")).unwrap();
        } else {
            fs::create_dir(home.join(".ssh")).unwrap();
        }
        let info = fs::metadata(&home).unwrap();
        for (name, body) in [
            ("id", "[ \"$U2SECURE_USER_MODE\" = existing-user ]"),
            (
                "useradd",
                "[ \"$U2SECURE_USER_MODE\" != useradd-fails ] || { echo useradd-failure >&2; exit 9; }",
            ),
            (
                "usermod",
                "[ \"$U2SECURE_USER_MODE\" != group-fails ] || { echo group-failure >&2; exit 6; }",
            ),
            ("getent", "printf '%s\\n' \"$U2SECURE_ACCOUNT\""),
            ("passwd", "exit 0"),
            ("userdel", "exit 0"),
            ("mkdir", "exit 0"),
            ("chown", "exit 0"),
            ("chmod", "exit 0"),
            (
                "ssh-keygen",
                "while [ \"$1\" != -f ]; do shift; done; shift\nprintf PRIVATE_MARKER > \"$1\"\nprintf PUBLIC_MARKER > \"$1.pub\"",
            ),
        ] {
            let path = bin.join(name);
            fs::write(
                &path,
                format!("#!/bin/sh\nprintf '%s\\n' '{name}' >> \"$U2SECURE_CALLS\"\n{body}\n"),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let calls = dir.path().join("calls");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_user_creation_child", "--nocapture"])
            .env("PATH", &bin)
            .env("U2SECURE_USER_MODE", mode)
            .env("U2SECURE_CALLS", &calls)
            .env(
                "U2SECURE_ACCOUNT",
                format!(
                    "fixture-user:x:{}:{}::{}:/bin/sh",
                    info.uid(),
                    info.gid(),
                    home.display()
                ),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let calls = fs::read_to_string(calls).unwrap();
        assert!(
            !calls
                .lines()
                .any(|name| matches!(name, "mkdir" | "chown" | "chmod")),
            "{mode}: unsafe path commands called: {calls}"
        );
        assert_eq!(
            calls.lines().filter(|name| *name == "ssh-keygen").count(),
            usize::from(mode == "normal")
        );
        assert_eq!(
            fs::read_to_string(victim.join("marker")).unwrap(),
            "UNTOUCHED"
        );
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o750);
        if mode == "normal" {
            assert_eq!(
                fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap(),
                "PUBLIC_MARKER\n"
            );
        }
    }
}

#[test]
fn isolated_user_creation_child() {
    use u2secure::application::steps::UserCreationStep;
    use u2secure::domain::steps::{ExecuteParams, HardeningStep};
    use u2secure::infrastructure::rollback;
    let Ok(mode) = std::env::var("U2SECURE_USER_MODE") else {
        return;
    };
    let result = UserCreationStep.execute(&ExecuteParams {
        new_username: Some("fixture-user".into()),
        ..Default::default()
    });
    assert_eq!(result.is_ok(), mode == "normal");
    if mode == "useradd-fails" {
        assert!(result.unwrap_err().to_string().contains("useradd-failure"));
        assert_eq!(rollback::undo_depth(), 0);
    }
    if mode == "existing-user" {
        assert_eq!(rollback::undo_depth(), 0);
    }
    assert!(rollback::undo_all().is_empty());
}
