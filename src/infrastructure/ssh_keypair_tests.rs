use std::fs;
use std::os::unix::fs::symlink;

use super::*;
use rustix::process::{getgid, getuid};

#[test]
fn keypair_lifecycle_preserves_originals_and_tracks_only_created_files() {
    // The undo stack belongs to a process, not to an individual test thread.
    if std::env::var_os("U2SECURE_KEYPAIR_TEST_CHILD").is_none() {
        let workspace = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "infrastructure::ssh_keys::keypair::tests::keypair_lifecycle_preserves_originals_and_tracks_only_created_files",
                "--nocapture",
            ])
            .env("U2SECURE_KEYPAIR_TEST_CHILD", "1")
            .env("TMPDIR", workspace.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for (replace, revert) in [(false, true), (true, true), (true, false)] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::create_dir(home.join(".ssh")).unwrap();
        let account = Account {
            home: home.clone(),
            uid: getuid(),
            gid: getgid(),
        };
        let dir = Arc::new(KeyDirectory::open(&account).unwrap());
        let generated = temp.path().join("generated");
        fs::create_dir(&generated).unwrap();
        for name in NAMES {
            fs::write(home.join(".ssh").join(name), format!("ORIGINAL_{name}")).unwrap();
            fs::write(generated.join(name), format!("NEW_{name}")).unwrap();
        }
        let record = crate::infrastructure::batch_record::BatchRecord::begin(
            [crate::domain::steps::StepKind::SshKeySetup].into_iter(),
            "fixture.log",
        );
        let existing: Vec<_> = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        let result = install_pair(dir, &generated, replace);
        assert_eq!(result.is_ok(), replace);
        assert_eq!(rollback::undo_depth(), usize::from(replace));
        let temporary_backups: Vec<_> = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| !existing.contains(path))
            .collect();
        assert_eq!(temporary_backups.len(), usize::from(replace));
        if revert {
            assert!(rollback::undo_all().is_empty());
        } else {
            rollback::discard_since(0);
        }
        assert!(temporary_backups.iter().all(|path| !path.exists()));
        for name in NAMES {
            assert_eq!(
                fs::read_to_string(home.join(".ssh").join(name)).unwrap(),
                format!(
                    "{}_{name}",
                    if replace && !revert {
                        "NEW"
                    } else {
                        "ORIGINAL"
                    }
                )
            );
        }
        let text = fs::read_to_string(record.finish(temp.path()).unwrap()).unwrap();
        assert!(!text.contains("ORIGINAL_") && !text.contains("NEW_"));
        let record: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(record["backups"].as_array().unwrap().len(), 0);
        assert_eq!(
            record["undo_actions"].as_array().unwrap().len(),
            usize::from(replace)
        );
        if replace {
            assert_eq!(record["undo_actions"][0]["kind"], "key_restore_temporary");
            assert_eq!(
                record["undo_actions"][0]["outcome"],
                if revert {
                    "returned_ok"
                } else {
                    "discarded_without_execution"
                }
            );
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::create_dir(home.join(".ssh")).unwrap();
    let account = Account {
        home: home.clone(),
        uid: getuid(),
        gid: getgid(),
    };
    let dir = Arc::new(KeyDirectory::open(&account).unwrap());
    let generated = temp.path().join("generated");
    fs::create_dir(&generated).unwrap();
    fs::write(generated.join(NAMES[0]), "NEW_PRIVATE_MARKER").unwrap();
    assert!(install_pair(dir, &generated, false).is_err());
    assert!(rollback::undo_all().is_empty());
    assert!(!home.join(".ssh").join(NAMES[0]).exists());
    assert!(!home.join(".ssh").join(NAMES[1]).exists());

    let dir = Arc::new(KeyDirectory::open(&account).unwrap());
    let victim = temp.path().join("victim");
    fs::write(&victim, "UNTOUCHED").unwrap();
    symlink(&victim, home.join(".ssh").join(NAMES[0])).unwrap();
    assert!(install_pair(dir, &generated, true).is_err());
    assert_eq!(rollback::undo_depth(), 0);
    assert_eq!(fs::read_to_string(victim).unwrap(), "UNTOUCHED");

    fs::remove_file(home.join(".ssh").join(NAMES[0])).unwrap();
    fs::write(generated.join(NAMES[1]), "NEW_PUBLIC_MARKER").unwrap();
    for name in NAMES {
        fs::write(home.join(".ssh").join(name), format!("ORIGINAL_{name}")).unwrap();
    }
    let dir = Arc::new(KeyDirectory::open(&account).unwrap());
    install_pair(dir, &generated, true).unwrap();
    let original = home.join(".ssh").join(NAMES[0]);
    let moved = home.join(".ssh/moved-original");
    fs::rename(&original, &moved).unwrap();
    let victim = temp.path().join("second-victim");
    fs::write(&victim, "UNTOUCHED").unwrap();
    symlink(&victim, &original).unwrap();
    let errors = rollback::undo_all();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("SSH key path changed during rollback"));
    let backup = errors[0].split("; backup: ").nth(1).unwrap();
    assert_eq!(
        fs::read_to_string(Path::new(backup).join(NAMES[0])).unwrap(),
        format!("ORIGINAL_{}", NAMES[0])
    );
    assert_eq!(
        fs::read_to_string(moved).unwrap(),
        format!("ORIGINAL_{}", NAMES[0])
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "UNTOUCHED");
    fs::remove_dir_all(backup).unwrap();
}
