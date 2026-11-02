use std::fs;
use std::os::unix::fs::symlink;

use super::*;
use rustix::process::{getgid, getuid};

#[test]
fn keypair_lifecycle_preserves_originals_and_tracks_only_created_files() {
    for replace in [false, true] {
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
        let result = install_pair(dir, &generated, replace);
        assert_eq!(result.is_ok(), replace);
        assert_eq!(rollback::undo_depth(), usize::from(replace));
        assert!(rollback::undo_all().is_empty());
        for name in NAMES {
            assert_eq!(
                fs::read_to_string(home.join(".ssh").join(name)).unwrap(),
                format!("ORIGINAL_{name}")
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
