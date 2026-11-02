#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn firewall_audit_requires_successful_active_status() {
    let dir = tempfile::tempdir().unwrap();
    let ufw = dir.path().join("ufw");
    fs::write(
        &ufw,
        "#!/bin/sh\n[ \"$1\" = status ] || exit 99\nprintf '%s\\n' \"$U2SECURE_UFW_STATUS\"\nexit \"$U2SECURE_UFW_EXIT\"\n",
    )
    .unwrap();
    fs::set_permissions(&ufw, fs::Permissions::from_mode(0o700)).unwrap();
    for (status, exit, active) in [
        ("Status: active", "0", true),
        ("Status: inactive", "0", false),
        ("Status: active", "1", false),
        ("unexpected output", "0", false),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_firewall_status", "--nocapture"])
            .env("PATH", dir.path())
            .env("U2SECURE_UFW_STATUS", status)
            .env("U2SECURE_UFW_EXIT", exit)
            .env("U2SECURE_UFW_EXPECTED", active.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "status={status:?}, exit={exit}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn isolated_firewall_status() {
    let Ok(expected) = std::env::var("U2SECURE_UFW_EXPECTED") else {
        return;
    };
    assert_eq!(
        u2secure::infrastructure::system::detect_ufw_enabled(),
        expected == "true"
    );
}
