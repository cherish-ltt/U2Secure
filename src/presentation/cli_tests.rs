use std::process::Command;

use super::*;
use crate::domain::audit::{AuditItem, PackageManager};

fn report() -> AuditReport {
    AuditReport {
        items: [
            AuditStatus::Safe,
            AuditStatus::Partial,
            AuditStatus::Missing,
            AuditStatus::NeedsUpdate,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, status)| AuditItem::new("fixture-check", status, format!("detail-{index}")))
        .collect(),
        is_root: false,
        package_manager: PackageManager::Unknown,
        ssh_port: 22,
        ssh_config_verified: false,
        password_auth_disabled: false,
        root_login_disabled: false,
        sudo_users: vec![],
        fail2ban_installed: false,
        ufw_enabled: false,
        auto_updates_enabled: false,
        system_up_to_date: false,
        reboot_hint: crate::domain::audit::RebootHint::Unsupported,
        lynis_installed: false,
        logwatch_installed: false,
        aide_installed: false,
        ssh_restart_needed: false,
    }
}

fn rendered(mode: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "presentation::cli::tests::isolated_render_child",
            "--nocapture",
        ])
        .current_dir(dir.path())
        .env("PATH", dir.path())
        .env("U2SECURE_CLI_RENDER", mode)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn event_output_distinguishes_outcomes_and_shows_only_first_result_line() {
    let text = rendered("events");
    assert!(text.contains("2/3"));
    assert!(text.contains(StepKind::Ufw.label()));
    assert!(text.contains("/fixture/live.log"));
    for marker in [
        "changed-first",
        "skipped-first",
        "failed-first",
        "fixture-log",
        "mirror-failure",
    ] {
        assert!(text.contains(marker), "missing {marker}: {text}");
    }
    assert!(!text.contains("result-second-line"));
    assert!(text.contains(crate::i18n::tr("cli_interrupted")));
}

#[test]
fn audit_output_includes_every_status_and_detail() {
    let text = rendered("audit");
    assert!(text.contains(crate::i18n::tr("cli_audit_done")));
    assert_eq!(text.matches("fixture-check").count(), 4);
    for (index, status) in [
        AuditStatus::Safe,
        AuditStatus::Partial,
        AuditStatus::Missing,
        AuditStatus::NeedsUpdate,
    ]
    .into_iter()
    .enumerate()
    {
        assert!(text.contains(status.icon()));
        assert!(text.contains(&format!("detail-{index}")));
    }
}

#[test]
fn audit_output_preserves_the_collected_reboot_hint_and_scope() {
    use crate::domain::audit::RebootHint;
    let text = rendered("reboot-hints");
    for hint in [
        RebootHint::Found("/run/reboot-required"),
        RebootHint::NotFound("/var/run/reboot-required"),
        RebootHint::Unsupported,
    ] {
        assert!(text.contains(&crate::i18n::reboot_hint(hint)));
    }
}

#[test]
fn summary_preserves_details_artifacts_and_correct_totals() {
    let text = rendered("summary");
    for marker in [
        "changed-first",
        "result-second-line",
        "skipped-first",
        "failed-first",
        "/fixture/report.txt",
        "/fixture/app.log",
        "/fixture/reports",
    ] {
        assert!(text.contains(marker), "missing {marker}: {text}");
    }
    for outcome in [
        StepOutcome::Changed,
        StepOutcome::Skipped,
        StepOutcome::Failed,
    ] {
        assert!(text.contains(outcome.label()));
    }
    let total = crate::i18n::tr("cli_summary_total")
        .replace("{ok}", "1")
        .replace("{skip}", "1")
        .replace("{fail}", "1");
    assert!(text.contains(&total));
    let empty = rendered("empty-summary");
    let total = crate::i18n::tr("cli_summary_total")
        .replace("{ok}", "0")
        .replace("{skip}", "0")
        .replace("{fail}", "0");
    assert!(empty.contains(&total));
}

#[test]
fn noninteractive_steps_keep_safe_defaults_and_original_mirror() {
    let steps = [StepKind::Ufw];
    let params = collect_step_params(&steps, &report());
    assert!(params.new_username.is_none());
    assert!(params.new_ssh_port.is_none());
    assert!(params.ssh_key_action.is_none());
    assert!(!params.apply_ssh_changes);
    assert!(!params.ssh_restart_required);
    assert_eq!(select_mirror(&steps), PackageMirror::Original);
    assert_eq!(
        describe_mirror(&PackageMirror::Original),
        crate::i18n::tr("mirror_original")
    );
    assert_eq!(
        crate::presentation::mirror_failure_options(),
        [
            crate::i18n::tr("mirror_action_retry"),
            crate::i18n::tr("mirror_action_change"),
            crate::i18n::tr("mirror_action_abort"),
        ]
    );
}

#[test]
fn cli_plan_cancel_and_edit_never_approve_stale_inputs() {
    let original = RunPlan::new(
        &[StepKind::SshPortChange],
        ExecuteParams {
            new_ssh_port: Some(2201),
            ..Default::default()
        },
        PackageMirror::Original,
    );
    assert!(review_plan(original.clone(), |_| 2, |_| panic!("cancel must not edit")).is_none());
    assert!(review_plan(original.clone(), |_| 1, |_| None).is_none());
    let mut review_count = 0;
    let approved = review_plan(
        original,
        |plan| {
            review_count += 1;
            if review_count == 1 {
                assert_eq!(plan.params.new_ssh_port, Some(2201));
                1
            } else {
                assert_eq!(plan.params.new_ssh_port, Some(2202));
                assert_eq!(plan.mirror, PackageMirror::Ustc);
                0
            }
        },
        |selected| {
            assert_eq!(selected, [StepKind::SshPortChange, StepKind::RestartSsh]);
            Some(RunPlan::new(
                &[StepKind::SystemUpdate, StepKind::SshPortChange],
                ExecuteParams {
                    new_ssh_port: Some(2202),
                    apply_ssh_changes: true,
                    ..Default::default()
                },
                PackageMirror::Ustc,
            ))
        },
    )
    .unwrap();
    assert_eq!(review_count, 2);
    assert_eq!(approved.params.new_ssh_port, Some(2202));
    assert!(approved.params.apply_ssh_changes);
    assert_eq!(
        approved.selected,
        [
            StepKind::SystemUpdate,
            StepKind::SshPortChange,
            StepKind::RestartSsh
        ]
    );
}

#[test]
fn cli_plan_output_uses_shared_preview_without_sensitive_fields() {
    let text = rendered("plan");
    let plan = RunPlan::new(
        &[StepKind::SshKeySetup],
        ExecuteParams {
            ssh_key_username: Some("deploy-fixture".into()),
            ssh_key_action: Some(SshKeyAction::PasteKey("key-body-fixture".into())),
            ..Default::default()
        },
        PackageMirror::Original,
    );
    for line in plan.lines() {
        assert!(text.contains(&line), "missing {line}");
    }
    assert!(!text.contains("key-body-fixture"));
}

#[test]
fn isolated_render_child() {
    let Ok(mode) = std::env::var("U2SECURE_CLI_RENDER") else {
        return;
    };
    let results = vec![
        StepResult::changed(StepKind::Ufw, "changed-first\nresult-second-line")
            .with_artifacts(vec!["/fixture/report.txt".into()]),
        StepResult::skipped(StepKind::Fail2ban, "skipped-first"),
        StepResult::failed(StepKind::AutoUpdates, "failed-first"),
    ];
    match mode.as_str() {
        "plan" => print_plan(&RunPlan::new(
            &[StepKind::SshKeySetup],
            ExecuteParams {
                ssh_key_username: Some("deploy-fixture".into()),
                ssh_key_action: Some(SshKeyAction::PasteKey("key-body-fixture".into())),
                ..Default::default()
            },
            PackageMirror::Original,
        )),
        "events" => {
            print_event(&JobEvent::StepStarted {
                kind: StepKind::Ufw,
                index: 1,
                total: 3,
                live_log: "/fixture/live.log".into(),
            });
            for result in results {
                print_event(&JobEvent::StepFinished(result));
            }
            print_event(&JobEvent::StepFinished(StepResult::skipped(
                StepKind::Ufw,
                "",
            )));
            print_event(&JobEvent::Log("fixture-log".into()));
            print_event(&JobEvent::MirrorFailed {
                reason: "mirror-failure".into(),
            });
            print_event(&JobEvent::Interrupted);
            print_event(&JobEvent::AllFinished);
        },
        "audit" => render_audit_report(&report()),
        "reboot-hints" => {
            use crate::domain::audit::RebootHint;
            let mut report = report();
            for hint in [
                RebootHint::Found("/run/reboot-required"),
                RebootHint::NotFound("/var/run/reboot-required"),
                RebootHint::Unsupported,
            ] {
                report.reboot_hint = hint;
                report.items = vec![AuditItem::new(
                    crate::i18n::tr("audit_sys_update"),
                    report.status_for(StepKind::SystemUpdate),
                    crate::i18n::reboot_hint(hint),
                )];
                render_audit_report(&report);
            }
        },
        "summary" => render_summary(&results, "/fixture/app.log", "/fixture/reports"),
        "empty-summary" => render_summary(&[], "/fixture/app.log", "/fixture/reports"),
        _ => panic!("unknown render fixture"),
    }
}
