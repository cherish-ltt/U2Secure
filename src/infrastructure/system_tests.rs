use super::*;

#[cfg(unix)]
#[test]
fn system_detection_uses_isolated_commands_and_account_fixtures() {
    use std::os::unix::fs::PermissionsExt;

    for mode in ["active", "missing", "wheel", "broken"] {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let scripts = [
            (
                "which",
                "case \"$U2C_MODE:$1\" in active:*|wheel:yum|broken:dnf) exit 0;; *) exit 1;; esac",
            ),
            (
                "id",
                "case \"$*\" in '-u') [ \"$U2C_MODE\" = active ] && printf 0 || printf 1000;; '-u alice') printf 1000;; '-u bob') printf 1001;; '-u daemon') printf 1;; '-u invalid') printf invalid;; alice) exit 0;; *) exit 1;; esac",
            ),
            (
                "getent",
                "case \"$1:$2:$U2C_MODE\" in group:sudo:active) printf 'sudo:x:27:alice, daemon, invalid, bob';; group:wheel:wheel) printf 'wheel:x:27:alice';; group:sudo:broken) printf malformed;; passwd:alice:*) printf 'alice:x:1000:1000::/fixture/home:/bin/sh';; passwd:empty:*) printf 'empty:x:1000:1000:::/bin/sh';; *) exit 1;; esac",
            ),
            (
                "systemctl",
                "[ \"$U2C_MODE\" = active ] && [ \"$1\" = is-enabled ]",
            ),
            (
                "ufw",
                "[ \"$LC_ALL\" = C ] || exit 9; [ \"$U2C_MODE\" = active ] && printf 'Status: active\\n' || printf 'Status: inactive\\n'",
            ),
            (
                "dpkg-query",
                "[ \"$3\" = installed ] && printf 'install ok installed' || { printf 'deinstall ok config-files'; exit 1; }",
            ),
            (
                "rpm",
                "[ \"$2\" = installed ] && printf 'installed-1.0-1.x86_64' || { printf 'package absent is not installed'; exit 1; }",
            ),
            (
                "passwd",
                "[ \"$1\" = -l ] && [ \"$2\" = alice ] || { printf 'denied' >&2; exit 7; }",
            ),
            (
                "sshd",
                "[ \"$U2C_MODE\" = broken ] && exit 3; if [ \"$U2C_MODE\" = active ]; then printf 'port 2222\\npasswordauthentication no\\nkbdinteractiveauthentication no\\npermitrootlogin no\\n'; else printf 'port 22\\npasswordauthentication yes\\nkbdinteractiveauthentication yes\\npermitrootlogin yes\\n'; fi",
            ),
            (
                "ssh-keygen",
                "case \"$U2C_MODE\" in active) printf '256 SHA256:TEST_FINGERPRINT fixture';; wheel) exit 0;; *) exit 2;; esac",
            ),
        ];
        for (name, script) in scripts {
            let path = bin.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "infrastructure::system::coverage_tests::isolated_system_detection",
                "--nocapture",
            ])
            .env("PATH", &bin)
            .env("U2C_MODE", mode)
            .env("U2C_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn isolated_system_detection() {
    let Ok(mode) = std::env::var("U2C_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("U2C_DIR").unwrap());
    assert_eq!(detect_is_root(), mode == "active");
    assert_eq!(
        detect_package_manager(),
        match mode.as_str() {
            "active" => PackageManager::Apt,
            "wheel" => PackageManager::Yum,
            "broken" => PackageManager::Dnf,
            _ => PackageManager::Unknown,
        }
    );
    assert_eq!(
        detect_sudo_users(),
        match mode.as_str() {
            "active" => vec!["alice", "bob"],
            "wheel" => vec!["alice"],
            _ => vec![],
        }
    );
    assert!(user_exists("alice"));
    assert!(!user_exists("missing"));
    assert_eq!(home_dir("root"), "/root");
    assert_eq!(home_dir("alice"), "/fixture/home");
    assert_eq!(home_dir("empty"), "/home/empty");
    assert_eq!(home_dir("missing"), "/home/missing");
    for pm in [
        PackageManager::Apt,
        PackageManager::Dnf,
        PackageManager::Yum,
    ] {
        assert!(package_installed(pm, "installed"));
        assert!(!package_installed(pm, "absent"));
    }
    assert!(lock_user_password("alice").is_ok());
    assert!(
        lock_user_password("missing")
            .unwrap_err()
            .to_string()
            .contains("denied")
    );
    let config = dir.join("sshd_config");
    std::fs::write(&config, "Port 2222\n").unwrap();
    let report = run_full_audit_with(ssh::SshConfig::new(&config, "sshd"));
    assert_eq!(report.items.len(), 10);
    assert_eq!(report.is_root, mode == "active");
    assert_eq!(report.ufw_enabled, mode == "active");
    assert_eq!(report.password_auth_disabled, mode == "active");
    assert_eq!(report.root_login_disabled, mode == "active");
    assert_eq!(report.ssh_config_verified, mode != "broken");
    assert_eq!(report.ssh_port, if mode == "active" { 2222 } else { 22 });
    assert_eq!(report.fail2ban_installed, mode == "active");
    assert_eq!(report.lynis_installed, mode == "active");
    assert_eq!(report.logwatch_installed, mode == "active");
    assert_eq!(report.aide_installed, mode == "active");
    if mode == "active" {
        assert!(report.auto_updates_enabled);
    }
    std::fs::write(&config, "Include extras\n").unwrap();
    assert!(!run_full_audit_with(ssh::SshConfig::new(&config, "sshd")).ssh_config_verified);

    let keys = dir.join("authorized_keys");
    assert!(key_fingerprint_at(&keys).is_none());
    std::fs::write(&keys, "\n# ignored\n").unwrap();
    assert!(key_fingerprint_at(&keys).is_none());
    std::fs::write(&keys, "# comment\nssh-ed25519 TEST_PUBLIC_MARKER\n").unwrap();
    let fingerprint = key_fingerprint_at(&keys);
    match mode.as_str() {
        "active" => assert_eq!(
            fingerprint.as_deref(),
            Some("256 SHA256:TEST_FINGERPRINT fixture")
        ),
        "wheel" => assert!(fingerprint.is_none()),
        _ => {
            assert_eq!(
                fingerprint.as_deref(),
                Some("(ssh-ed25519) ssh-ed25519 TEST_PUBLIC_MARKER")
            );
            std::fs::write(&keys, format!("ssh-ed25519 {}", "x".repeat(80))).unwrap();
            assert!(key_fingerprint_at(&keys).unwrap().ends_with("..."));
        },
    }
}

#[test]
fn command_status_descriptions_and_input_errors_remain_explicit() {
    for status in [
        StreamStatus::Success,
        StreamStatus::Failed(Some(17)),
        StreamStatus::Failed(None),
        StreamStatus::TimedOut,
        StreamStatus::NoResponse,
        StreamStatus::Cancelled,
    ] {
        assert_eq!(status.is_success(), status == StreamStatus::Success);
        assert_eq!(
            status.describe().is_empty(),
            status == StreamStatus::Success
        );
        assert_eq!(
            status.exit_code(),
            if status == StreamStatus::Failed(Some(17)) {
                Some(17)
            } else {
                None
            }
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    assert!(run_streaming_argv(&[], &[], log.to_str().unwrap(), Duration::from_secs(1)).is_err());
    assert!(!log.exists());
    assert!(
        run_streaming_argv(
            &["unused".into()],
            &[],
            dir.path().to_str().unwrap(),
            Duration::from_secs(1)
        )
        .is_err()
    );
    let missing = dir.path().join("missing").display().to_string();
    assert!(run_cmd(&missing, &[]).is_err());
    assert!(
        run_streaming(
            &missing,
            &[],
            &[],
            log.to_str().unwrap(),
            Duration::from_secs(1)
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn command_execution_preserves_args_environment_and_error_output() {
    assert_eq!(
        run_cmd("/bin/sh", &["-c", "printf '  output  \\n'"]).unwrap(),
        "output"
    );
    assert!(
        run_cmd("/bin/sh", &["-c", "printf TEST_FAILURE >&2; exit 7"])
            .unwrap_err()
            .to_string()
            .contains("TEST_FAILURE")
    );
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    assert_eq!(
        run_streaming(
            "/bin/sh",
            &["-c", "printf '%s' \"$TEST_VALUE\""],
            &[("TEST_VALUE", "ENV_MARKER")],
            log.to_str().unwrap(),
            Duration::from_secs(2)
        )
        .unwrap(),
        StreamStatus::Success
    );
    assert!(std::fs::read_to_string(log).unwrap().contains("ENV_MARKER"));
    let port = random_suggested_port();
    assert!((1024..=65535).contains(&port));
    assert!(![3306, 5432, 6379, 8080, 8443].contains(&port));
}
