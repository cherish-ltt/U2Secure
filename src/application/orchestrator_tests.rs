use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn audit_and_permission_checks_use_the_shared_logger() {
    for uid in ["0", "1000", "unavailable"] {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [
            (
                "id",
                "[ \"$AUDIT_UID\" != unavailable ] || exit 1\nprintf '%s\\n' \"$AUDIT_UID\"",
            ),
            ("which", "exit 1"),
            ("getent", "echo sudo:x:27:"),
            ("ufw", "echo 'Status: inactive'"),
            ("systemctl", "exit 1"),
            ("sshd", "exit 1"),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "application::orchestrator::tests::isolated_audit_child",
                "--nocapture",
            ])
            .env("PATH", dir.path())
            .env("AUDIT_UID", uid)
            .env("AUDIT_LOG", dir.path().join("audit.log"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn isolated_audit_child() {
    let Ok(uid) = std::env::var("AUDIT_UID") else {
        return;
    };
    let path = std::env::var("AUDIT_LOG").unwrap();
    let logger = Arc::new(FileLogger::with_path(&path));
    let orchestrator = HardeningOrchestrator {
        logger: logger.clone(),
    };
    assert!(Arc::ptr_eq(&logger, &orchestrator.logger()));
    let allowed = uid == "0";
    assert_eq!(orchestrator.check_root().is_ok(), allowed);
    let report = orchestrator.audit();
    assert_eq!(report.is_root, allowed);
    assert_eq!(
        report.package_manager,
        crate::domain::audit::PackageManager::Unknown
    );
    assert!(!report.items.is_empty());
    let text = fs::read_to_string(path).unwrap();
    assert!(text.contains(crate::i18n::tr("log_audit_start")));
    assert!(text.contains(
        &crate::i18n::tr("log_audit_done").replace("{n}", &report.items.len().to_string())
    ));
}
