use std::fs;

use super::*;

#[test]
fn supported_distributions_report_marker_presence_without_reading_contents() {
    for (id, source) in [
        ("debian", "/run/reboot-required"),
        ("\"ubuntu\"", "/var/run/reboot-required"),
        ("'ubuntu'", "/var/run/reboot-required"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/os-release"), format!("ID={id}\n")).unwrap();
        assert_eq!(detect(dir.path()).unwrap(), RebootHint::NotFound(source));
        let marker = dir.path().join(&source[1..]);
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(marker, [0xff, 0xfe]).unwrap();
        assert_eq!(detect(dir.path()).unwrap(), RebootHint::Found(source));
    }
}

#[test]
fn identification_respects_os_release_precedence_and_ignores_id_like() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert_eq!(detect(root).unwrap(), RebootHint::Unsupported);
    fs::create_dir_all(root.join("usr/lib")).unwrap();
    fs::write(root.join("usr/lib/os-release"), "ID=debian\n").unwrap();
    assert_eq!(
        detect(root).unwrap(),
        RebootHint::NotFound("/run/reboot-required")
    );
    fs::create_dir(root.join("etc")).unwrap();
    for content in [
        "ID=linuxmint\nID_LIKE=ubuntu\n",
        "# ID=debian\nID_LIKE=debian\n",
        "ID=debian\nID=fedora\n",
        "NAME=Ubuntu\n",
    ] {
        fs::write(root.join("etc/os-release"), content).unwrap();
        assert_eq!(detect(root).unwrap(), RebootHint::Unsupported);
    }
    for content in ["ID=\"debian\n", "ID=\n", "ID=$(debian)\n", "ID=Debian\n"] {
        fs::write(root.join("etc/os-release"), content).unwrap();
        assert!(detect(root).is_err());
    }
}

#[test]
fn configuration_and_marker_io_failures_are_not_reported_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("etc/os-release")).unwrap();
    assert!(detect(root).is_err());
    fs::remove_dir(root.join("etc/os-release")).unwrap();
    fs::write(root.join("etc/os-release"), "ID=debian\n").unwrap();
    fs::write(root.join("run"), "not a directory").unwrap();
    let error = detect(root).unwrap_err().to_string();
    assert!(error.contains("/run/reboot-required"));
    assert!(error.contains("directory"));
}
