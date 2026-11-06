use std::io;
use std::process::{Command, Stdio};

use super::*;
use crate::domain::audit::{AuditItem, PackageManager, RebootHint};
use crate::i18n::{self, Lang};

fn report() -> AuditReport {
    AuditReport {
        items: vec![AuditItem::safe(
            "ignored-localized-label",
            "PRIVATE_CONFIG_MARKER".into(),
        )],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 2222,
        ssh_config_verified: false,
        password_auth_disabled: true,
        root_login_disabled: true,
        sudo_users: vec!["alice".into()],
        fail2ban_installed: false,
        ufw_enabled: true,
        auto_updates_enabled: false,
        system_up_to_date: false,
        reboot_hint: RebootHint::Unsupported,
        lynis_installed: true,
        logwatch_installed: true,
        aide_installed: false,
        ssh_restart_needed: true,
    }
}

#[test]
fn system_update_includes_a_typed_reboot_hint() {
    let details = details(&report(), StepKind::SystemUpdate);
    assert_eq!(details["apt_cache_recent"], false);
    assert_eq!(details["reboot_hint"]["status"], "unsupported");
    assert_eq!(details["reboot_hint"]["source"], Value::Null);
}

#[test]
fn reboot_hints_extend_schema_without_changing_cache_or_ssh_status() {
    let mut report = report();
    let mut bytes = Vec::new();
    for recent in [false, true] {
        report.system_up_to_date = recent;
        for (hint, status, source) in [
            (
                RebootHint::Found("/run/reboot-required"),
                "found",
                Some("/run/reboot-required"),
            ),
            (
                RebootHint::NotFound("/var/run/reboot-required"),
                "not_found",
                Some("/var/run/reboot-required"),
            ),
            (RebootHint::Unsupported, "unsupported", None),
        ] {
            report.reboot_hint = hint;
            bytes.clear();
            run_with(
                &["--format".into(), "json".into()],
                || Ok(report.clone()),
                &mut bytes,
            )
            .unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["schema_version"], 1);
            let checks = value["checks"].as_array().unwrap();
            let update = checks
                .iter()
                .find(|check| check["id"] == "system-update")
                .unwrap();
            assert_eq!(update["details"]["apt_cache_recent"], recent);
            assert_eq!(
                update["details"]["reboot_hint"],
                json!({"status": status, "source": source})
            );
            assert_eq!(
                update["status"],
                if recent { "safe" } else { "needs_update" }
            );
            assert_eq!(
                report.status_for(StepKind::RestartSsh),
                AuditStatus::NeedsUpdate
            );
            assert!(
                text_detail(&report, StepKind::SystemUpdate).contains(&i18n::reboot_hint(hint))
            );
        }
    }
    bytes.clear();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/os-release")).unwrap();
    assert!(
        run_with(
            &[],
            || {
                report.reboot_hint = crate::infrastructure::reboot::detect(dir.path())?;
                Ok(report)
            },
            &mut bytes
        )
        .is_err()
    );
    assert!(bytes.is_empty());
}

#[test]
fn parsing_and_help_do_not_collect_or_write_on_failure() {
    for args in [
        vec!["--format"],
        vec!["--format", "yaml"],
        vec!["--format", "json", "extra"],
        vec!["--format", "json", "--format", "text"],
        vec!["--help", "--format", "json"],
        vec!["unknown"],
    ] {
        let args: Vec<_> = args.into_iter().map(str::to_string).collect();
        let mut bytes = Vec::new();
        let result = run_with(
            &args,
            || panic!("invalid arguments must not audit"),
            &mut bytes,
        );
        assert!(matches!(result, Err(DomainError::AuditFailed(_))));
        assert!(bytes.is_empty());
    }
    for flag in ["-h", "--help"] {
        let mut bytes = Vec::new();
        run_with(&[flag.into()], || panic!("help must not audit"), &mut bytes).unwrap();
        assert_eq!(bytes, tr("audit_usage").as_bytes());
    }
    for (args, expected) in [
        (vec![], Format::Text),
        (vec!["--format", "text"], Format::Text),
        (vec!["--format", "json"], Format::Json),
    ] {
        let args: Vec<_> = args.into_iter().map(str::to_string).collect();
        assert_eq!(Format::parse(&args).unwrap(), Some(expected));
    }
}

#[test]
fn failed_collection_never_emits_a_partial_report() {
    let mut bytes = Vec::new();
    assert!(matches!(
        run_with(&[], || Err(DomainError::PermissionDenied), &mut bytes),
        Err(DomainError::PermissionDenied)
    ));
    assert!(bytes.is_empty());
    run_with(
        &["--format".into(), "json".into()],
        || Ok(report()),
        &mut bytes,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(value["collected_at"].as_str().unwrap()).is_ok());
}

#[test]
fn json_retains_partial_scope_and_excludes_unverified_or_raw_data() {
    let mut bytes = Vec::new();
    render(&report(), Format::Json, "2026-11-05T00:00:00Z", &mut bytes).unwrap();
    assert!(bytes.ends_with(b"\n"));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["collected_at"], "2026-11-05T00:00:00Z");
    assert_eq!(value["package_manager"], "apt");
    assert_eq!(value["is_root"], true);
    let scope = value["check_scope"].as_array().unwrap();
    assert_eq!(scope.len(), 9);
    assert!(scope.contains(&json!(
        "debian-ubuntu-reboot-marker-not-complete-patch-activation"
    )));
    assert!(scope.contains(&json!(
        "firewall-chains-not-complete-rules-or-atomic-snapshot"
    )));
    let checks = value["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 12);
    let get = |id: &str| checks.iter().find(|check| check["id"] == id).unwrap();
    assert_eq!(get("system-update")["status"], "needs_update");
    assert_eq!(get("ufw")["status"], "safe");
    assert_eq!(get("fail2ban")["status"], "missing");
    assert_eq!(get("log-audit")["status"], "partial");
    assert_eq!(get("ssh-port-change")["status"], "partial");
    assert_eq!(get("ssh-port-change")["details"]["port"], Value::Null);
    assert_eq!(
        get("ssh-root-login")["details"]["root_login_restricted"],
        Value::Null
    );
    assert_eq!(
        get("ssh-password-auth")["details"]["password_auth_disabled"],
        Value::Null
    );
    assert_eq!(get("ssh-key-setup")["details"]["keys_verified"], false);
    assert_eq!(get("security-scan")["details"]["scan_executed"], false);
    assert_eq!(
        get("restart-ssh")["details"]["live_settings_verified"],
        false
    );
    assert_eq!(
        get("user-creation")["details"]["sudo_users"],
        json!(["alice"])
    );
    let output = String::from_utf8(bytes).unwrap();
    for excluded in [
        "PRIVATE_CONFIG_MARKER",
        "ignored-localized-label",
        "✅",
        "⚠️",
        "2222",
    ] {
        assert!(!output.contains(excluded), "leaked {excluded}");
    }
    assert!(output.contains("ssh-global-only-no-connection-or-key-verification"));
}

#[test]
fn verified_values_and_text_findings_follow_the_same_report() {
    let mut report = report();
    report.ssh_config_verified = true;
    report.ssh_restart_needed = false;
    report.aide_installed = true;
    report.system_up_to_date = true;
    report.auto_updates_enabled = true;
    report.fail2ban_installed = true;
    for changed in [false, true] {
        if changed {
            report.ssh_port = 22;
            report.root_login_disabled = false;
            report.password_auth_disabled = false;
            report.sudo_users.clear();
            report.lynis_installed = false;
            report.logwatch_installed = false;
            report.aide_installed = false;
            report.ufw_enabled = false;
        }
        let document = document(&report, "fixture-time");
        let port = document
            .checks
            .iter()
            .find(|check| check.id == "ssh-port-change")
            .unwrap();
        assert_eq!(port.details["port"], report.ssh_port);
        assert_eq!(port.status, if changed { "missing" } else { "safe" });
        let mut bytes = Vec::new();
        render(&report, Format::Text, "fixture-time", &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for kind in StepKind::all() {
            assert!(text.contains(kind.slug()));
            assert!(text.contains(kind.label()));
        }
        assert!(text.contains("fixture-time"));
        assert!(text.contains(tr("audit_scope_ssh")));
        assert!(text.contains(tr("audit_scope_cache")));
        assert!(text.contains(tr("audit_scope_ufw")));
        assert!(text.contains(tr("audit_scope_installed")));
        assert!(text.contains(tr("audit_scope_restart")));
        assert!(!text.contains("PRIVATE_CONFIG_MARKER"));
        assert!(!text.contains("\u{1b}"));
    }
}

#[test]
fn output_and_flush_failures_are_explicit() {
    struct FailingWriter(bool);
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture-output-failure",
                ))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fixture-flush-failure"))
        }
    }
    for flush in [false, true] {
        let error = render(
            &report(),
            Format::Json,
            "fixture-time",
            &mut FailingWriter(flush),
        )
        .unwrap_err();
        assert!(matches!(&error, DomainError::AuditFailed(_)));
        assert!(error.to_string().contains(if flush {
            "fixture-flush-failure"
        } else {
            "fixture-output-failure"
        }));
    }
}

#[test]
fn json_is_locale_independent_without_tty_or_files() {
    let mut previous = None;
    for language in ["zh_cn", "zh_tw", "en"] {
        let dir = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "presentation::audit::tests::isolated_locale",
                "--nocapture",
            ])
            .current_dir(dir.path())
            .env("PATH", dir.path())
            .env("U2SECURE_AUDIT_LANGUAGE", language)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{language}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let json = stdout
            .split_once("JSON_BEGIN\n")
            .unwrap()
            .1
            .split_once("JSON_END")
            .unwrap()
            .0
            .to_owned();
        if let Some(previous) = &previous {
            assert_eq!(&json, previous);
        }
        previous = Some(json);
    }
}

#[test]
fn isolated_locale() {
    let Ok(language) = std::env::var("U2SECURE_AUDIT_LANGUAGE") else {
        return;
    };
    i18n::init(match language.as_str() {
        "zh_cn" => Lang::ZhCn,
        "zh_tw" => Lang::ZhTw,
        "en" => Lang::En,
        _ => panic!("unknown fixture language"),
    });
    let text = render_text(&report(), "fixture-time");
    assert!(text.contains(tr("audit_scope_keys")));
    assert!(text.contains(tr("audit_status_partial")));
    assert!(!text.contains("audit_scope_"));
    assert!(!text.contains("audit_status_"));
    for hint in [
        RebootHint::Found("/run/reboot-required"),
        RebootHint::NotFound("/var/run/reboot-required"),
        RebootHint::Unsupported,
    ] {
        let mut report = report();
        report.reboot_hint = hint;
        let text = render_text(&report, "fixture-time");
        assert!(text.contains(&i18n::reboot_hint(hint)));
        assert!(!text.contains("reboot_"));
        if let Some(source) = hint.source() {
            assert!(text.contains(source));
        }
    }
    println!("JSON_BEGIN");
    render(
        &report(),
        Format::Json,
        "fixture-time",
        &mut io::stdout().lock(),
    )
    .unwrap();
    println!("JSON_END");
}
