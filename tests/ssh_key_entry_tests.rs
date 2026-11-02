#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;

#[test]
fn public_key_entry_uses_account_database_and_rejects_links() {
    for unsafe_target in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let home = dir.path().join("custom-home");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&home).unwrap();
        fs::create_dir(home.join(".ssh")).unwrap();
        let info = fs::metadata(&home).unwrap();
        let getent = bin.join("getent");
        fs::write(&getent, "#!/bin/sh\n[ \"$1\" = passwd ] && [ \"$2\" = fixture-user ] || exit 9\nprintf '%s\\n' \"$U2SECURE_ACCOUNT\"\n").unwrap();
        fs::set_permissions(&getent, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "UNTOUCHED").unwrap();
        if unsafe_target {
            symlink(&victim, home.join(".ssh/authorized_keys")).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_public_key_entry_child", "--nocapture"])
            .env("PATH", &bin)
            .env("U2SECURE_ENTRY_CHILD", "1")
            .env("U2SECURE_UNSAFE_TARGET", unsafe_target.to_string())
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
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(victim).unwrap(), "UNTOUCHED");
        if !unsafe_target {
            assert_eq!(
                fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap(),
                "TEST_PUBLIC_MARKER\n"
            );
        }
    }
}

#[test]
fn isolated_public_key_entry_child() {
    if std::env::var("U2SECURE_ENTRY_CHILD").as_deref() != Ok("1") {
        return;
    }
    let result =
        u2secure::infrastructure::system::add_authorized_key("fixture-user", "TEST_PUBLIC_MARKER");
    assert_eq!(
        result.is_err(),
        std::env::var("U2SECURE_UNSAFE_TARGET").unwrap() == "true"
    );
}

#[test]
fn key_generation_entry_never_deletes_existing_files_on_failure() {
    for mode in [
        "generate-fails",
        "refuse-existing",
        "replace",
        "partial-output",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let home = dir.path().join("home");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&home).unwrap();
        fs::create_dir(home.join(".ssh")).unwrap();
        let info = fs::metadata(&home).unwrap();
        let scripts = [
            (
                "getent",
                "#!/bin/sh\nprintf '%s\\n' \"$U2SECURE_ACCOUNT\"\n",
            ),
            (
                "ssh-keygen",
                "#!/bin/sh\n[ \"$U2SECURE_MODE\" = generate-fails ] && exit 8\nwhile [ \"$1\" != -f ]; do shift; done\nshift\nprintf NEW_PRIVATE_MARKER > \"$1\"\n[ \"$U2SECURE_MODE\" = partial-output ] && exit 0\nprintf NEW_PUBLIC_MARKER > \"$1.pub\"\n",
            ),
        ];
        for (name, script) in scripts {
            let path = bin.join(name);
            fs::write(&path, script).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["id_ed25519", "id_ed25519.pub"] {
            fs::write(home.join(".ssh").join(name), format!("ORIGINAL_{name}")).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_key_generation_child", "--nocapture"])
            .env("PATH", &bin)
            .env("U2SECURE_GENERATION_CHILD", "1")
            .env("U2SECURE_MODE", mode)
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
        for name in ["id_ed25519", "id_ed25519.pub"] {
            assert_eq!(
                fs::read_to_string(home.join(".ssh").join(name)).unwrap(),
                format!("ORIGINAL_{name}")
            );
        }
    }
}

#[test]
fn isolated_key_generation_child() {
    use u2secure::application::steps::SshKeySetupStep;
    use u2secure::domain::steps::{ExecuteParams, HardeningStep, SshKeyAction};
    use u2secure::infrastructure::rollback;
    if std::env::var("U2SECURE_GENERATION_CHILD").as_deref() != Ok("1") {
        return;
    }
    let mode = std::env::var("U2SECURE_MODE").unwrap();
    let action = if mode == "refuse-existing" {
        SshKeyAction::GenerateNew
    } else {
        SshKeyAction::ReplaceExisting
    };
    let params = ExecuteParams {
        ssh_key_username: Some("fixture-user".into()),
        ssh_key_action: Some(action),
        ..Default::default()
    };
    let result = SshKeySetupStep.execute(&params);
    assert_eq!(result.is_ok(), mode == "replace");
    assert!(rollback::undo_all().is_empty());
}
