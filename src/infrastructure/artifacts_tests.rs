use super::*;

#[test]
fn candidate_selection_and_truncated_tail_stay_in_temporary_directories() {
    let dir = tempfile::tempdir().unwrap();
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory").unwrap();
    assert!(!is_writable(&blocked));
    assert!(first_writable(std::slice::from_ref(&blocked)).is_none());
    let writable = dir.path().join("reports");
    assert_eq!(first_writable(&[blocked, writable.clone()]), Some(writable));
    let log = dir.path().join("log");
    std::fs::write(&log, "discarded prefix\nline two\nline three\n").unwrap();
    assert_eq!(
        read_tail(log.to_str().unwrap(), 2, 22).as_deref(),
        Some("line two\nline three")
    );
    assert_eq!(
        read_tail(log.to_str().unwrap(), 0, 1024).as_deref(),
        Some("")
    );
    assert_eq!(read_tail(log.to_str().unwrap(), 3, 0).as_deref(), Some(""));
    std::fs::write(&log, []).unwrap();
    assert_eq!(
        read_tail(log.to_str().unwrap(), 3, 1024).as_deref(),
        Some("")
    );
    restrict_file(log.to_str().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn report_paths_use_a_process_local_temporary_override() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "infrastructure::artifacts::coverage_tests::isolated_report_paths",
            "--nocapture",
        ])
        .env("U2C_ARTIFACTS_DIR", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn isolated_report_paths() {
    let Some(path) = std::env::var_os("U2C_ARTIFACTS_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    DIR.set(path.clone()).unwrap();
    assert_eq!(dir(), path);
    assert_eq!(dir_display(), path.display().to_string());
    assert_eq!(steps_dir(), path.join("steps").display().to_string());
    assert!(path.join("steps").is_dir());
    let report = PathBuf::from(path_for("audit", "json"));
    assert_eq!(report.parent(), Some(path.as_path()));
    assert!(
        report
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("audit-")
    );
    assert_eq!(report.extension().unwrap(), "json");
    assert!(!report.exists());
}
