use std::fs as stdfs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use super::*;

fn fixture() -> (tempfile::TempDir, Account) {
    let temp = tempfile::tempdir().unwrap();
    let account = Account {
        home: temp.path().to_path_buf(),
        uid: rustix::process::getuid(),
        gid: rustix::process::getgid(),
    };
    stdfs::create_dir(account.home.join(".ssh")).unwrap();
    (temp, account)
}

#[test]
fn append_preserves_existing_content_and_sets_fd_permissions() {
    let (_temp, account) = fixture();
    let path = account.home.join(".ssh/authorized_keys");
    stdfs::write(&path, "ORIGINAL_PUBLIC_MARKER\n").unwrap();
    let dir = KeyDirectory::open(&account).unwrap();
    dir.append("ADDED_PUBLIC_MARKER").unwrap();
    assert_eq!(
        stdfs::read_to_string(&path).unwrap(),
        "ORIGINAL_PUBLIC_MARKER\nADDED_PUBLIC_MARKER\n"
    );
    assert_eq!(stdfs::metadata(path).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn missing_directory_and_file_are_created_for_the_current_account() {
    let (_temp, account) = fixture();
    stdfs::remove_dir(account.home.join(".ssh")).unwrap();
    let dir = KeyDirectory::open(&account).unwrap();
    dir.append("TEST_MARKER").unwrap();
    let path = account.home.join(".ssh/authorized_keys");
    assert_eq!(stdfs::read_to_string(&path).unwrap(), "TEST_MARKER\n");
    assert_eq!(stdfs::metadata(path).unwrap().uid(), account.uid.as_raw());
    assert_eq!(
        stdfs::metadata(account.home.join(".ssh")).unwrap().mode() & 0o777,
        0o700
    );
}

#[test]
fn direct_link_hardlink_and_nonregular_targets_are_rejected() {
    for kind in ["symlink", "hardlink", "directory", "fifo"] {
        let (_temp, account) = fixture();
        let path = account.home.join(".ssh/authorized_keys");
        let victim = account.home.join("victim");
        stdfs::write(&victim, "UNTOUCHED_MARKER").unwrap();
        stdfs::set_permissions(&victim, stdfs::Permissions::from_mode(0o640)).unwrap();
        match kind {
            "symlink" => symlink(&victim, &path).unwrap(),
            "hardlink" => stdfs::hard_link(&victim, &path).unwrap(),
            "directory" => stdfs::create_dir(&path).unwrap(),
            _ => assert!(
                Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            ),
        }
        assert!(
            KeyDirectory::open(&account)
                .unwrap()
                .append("TEST_MARKER")
                .is_err(),
            "{kind}"
        );
        assert_eq!(stdfs::read_to_string(&victim).unwrap(), "UNTOUCHED_MARKER");
        assert_eq!(stdfs::metadata(victim).unwrap().mode() & 0o777, 0o640);
    }
}

#[test]
fn directory_links_and_writable_directories_are_rejected() {
    let (_temp, mut account) = fixture();
    let home = account.home.clone();
    stdfs::rename(home.join(".ssh"), home.join("real-ssh")).unwrap();
    symlink(home.join("real-ssh"), home.join(".ssh")).unwrap();
    assert!(KeyDirectory::open(&account).is_err());
    stdfs::remove_file(home.join(".ssh")).unwrap();
    stdfs::rename(home.join("real-ssh"), home.join(".ssh")).unwrap();
    stdfs::set_permissions(home.join(".ssh"), stdfs::Permissions::from_mode(0o777)).unwrap();
    assert!(KeyDirectory::open(&account).is_err());
    stdfs::set_permissions(home.join(".ssh"), stdfs::Permissions::from_mode(0o700)).unwrap();
    symlink(&home, home.join("home-link")).unwrap();
    account.home = home.join("home-link");
    assert!(KeyDirectory::open(&account).is_err());
}

#[test]
fn replacing_directory_or_file_after_open_does_not_redirect_fd_operations() {
    let (_temp, account) = fixture();
    let dir = KeyDirectory::open(&account).unwrap();
    let mut file = dir.authorized_file().unwrap();
    let ssh = account.home.join(".ssh");
    let victim = account.home.join("victim");
    stdfs::write(&victim, "UNTOUCHED").unwrap();
    stdfs::set_permissions(&victim, stdfs::Permissions::from_mode(0o640)).unwrap();
    stdfs::rename(ssh.join("authorized_keys"), ssh.join("opened-file")).unwrap();
    symlink(&victim, ssh.join("authorized_keys")).unwrap();
    stdfs::rename(&ssh, account.home.join("opened-directory")).unwrap();
    symlink(&victim, &ssh).unwrap();
    writeln!(file, "TEST_MARKER").unwrap();
    fs::fchmod(&file, Mode::from_raw_mode(0o600)).unwrap();
    assert_eq!(stdfs::read_to_string(&victim).unwrap(), "UNTOUCHED");
    assert_eq!(stdfs::metadata(victim).unwrap().mode() & 0o777, 0o640);
    assert_eq!(
        stdfs::read_to_string(account.home.join("opened-directory/opened-file")).unwrap(),
        "TEST_MARKER\n"
    );
}

#[test]
fn malformed_account_records_are_rejected() {
    for record in [
        "other:x:1:1::/home/test:/bin/sh",
        "test:x:no:1::/home/test:/bin/sh",
        "test:x:4294967295:1::/home/test:/bin/sh",
        "test:x:1:1::/home/test:/bin/sh\nother:x:2:2::/home/other:/bin/sh",
    ] {
        assert!(Account::parse("test", record).is_err());
    }
}
