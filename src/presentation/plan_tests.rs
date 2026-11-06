use std::process::Command;

use super::*;

#[test]
fn preview_uses_executor_order_and_redacts_every_key_body() {
    let params = ExecuteParams {
        new_username: Some("operator".into()),
        new_ssh_port: Some(2209),
        ssh_key_username: Some("deploy".into()),
        ssh_key_action: Some(SshKeyAction::PasteKey("private-fixture-key-body".into())),
        live_log: Some("private-fixture-log".into()),
        report_dir: Some("private-fixture-dir".into()),
        ..Default::default()
    };
    let plan = RunPlan::new(
        &[
            StepKind::SshKeySetup,
            StepKind::SystemUpdate,
            StepKind::SshPortChange,
            StepKind::UserCreation,
            StepKind::SshPortChange,
        ],
        params,
        PackageMirror::custom("https://mirror.example.test/repo").unwrap(),
    );
    assert_eq!(
        plan.selected,
        [
            StepKind::SystemUpdate,
            StepKind::UserCreation,
            StepKind::SshPortChange,
            StepKind::SshKeySetup,
            StepKind::RestartSsh,
        ]
    );
    let lines = plan.lines();
    for (index, kind) in plan.selected.iter().enumerate() {
        assert_eq!(lines[index], format!("{}. {}", index + 1, kind.label()));
    }
    let text = lines.join("\n");
    for expected in [
        "operator",
        "deploy",
        "2209",
        "mirror.example.test",
        tr("plan_key_paste"),
        tr("plan_ssh_not_authorized"),
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
    assert!(!text.contains("private-fixture"));
    assert!(!text.contains(tr("plan_key_duplicate")));
}

#[test]
fn preview_marks_missing_and_conditional_inputs_without_guessing() {
    let mut plan = RunPlan::new(
        &[
            StepKind::UserCreation,
            StepKind::SshKeySetup,
            StepKind::SshPortChange,
            StepKind::Ufw,
        ],
        ExecuteParams::default(),
        PackageMirror::Tsinghua,
    );
    let text = plan.lines().join("\n");
    assert!(text.contains(tr("plan_unset")));
    assert!(text.contains(tr("plan_mirror_unused")));
    assert!(text.contains(tr("plan_ufw_conditional")));
    assert!(text.contains(tr("plan_user_locked")));
    assert!(text.contains(tr("plan_user_key")));
    assert!(!text.contains("tuna"));
    assert!(!text.contains(tr("plan_key_duplicate")));
    plan.params.new_username = Some("operator".into());
    plan.params.ssh_key_username = Some("operator".into());
    plan.params.ssh_key_action = Some(SshKeyAction::GenerateNew);
    plan.params.apply_ssh_changes = true;
    plan.params.lock_password = false;
    let text = plan.lines().join("\n");
    for key in [
        "plan_key_generate",
        "plan_key_duplicate",
        "plan_ssh_authorized",
        "plan_user_unlocked",
    ] {
        assert!(text.contains(tr(key)));
    }
    plan.params.ssh_key_action = Some(SshKeyAction::ReplaceExisting);
    let text = plan.lines().join("\n");
    assert!(text.contains(tr("plan_key_replace")));
    assert!(!text.contains(tr("plan_key_duplicate")));
    plan.params.ssh_key_action = Some(SshKeyAction::GenerateNew);
    plan.params.ssh_key_username = Some("other".into());
    assert!(!plan.lines().join("\n").contains(tr("plan_key_duplicate")));
    let original = RunPlan::new(
        &[StepKind::SystemUpdate],
        ExecuteParams::default(),
        PackageMirror::Original,
    );
    assert!(original.lines().join("\n").contains(tr("mirror_original")));
}

#[test]
fn previews_are_translated_in_isolated_processes() {
    for language in ["zh_cn", "zh_tw", "en"] {
        let dir = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "presentation::plan::tests::isolated_preview_child",
            ])
            .env("U2SECURE_PLAN_LANGUAGE", language)
            .env("PATH", dir.path())
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{language}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn isolated_preview_child() {
    let Ok(language) = std::env::var("U2SECURE_PLAN_LANGUAGE") else {
        return;
    };
    let language = match language.as_str() {
        "en" => crate::i18n::Lang::En,
        "zh_tw" => crate::i18n::Lang::ZhTw,
        _ => crate::i18n::Lang::ZhCn,
    };
    crate::i18n::init(language);
    let plan = RunPlan::new(
        StepKind::all(),
        ExecuteParams::default(),
        PackageMirror::Original,
    );
    let text = plan.lines().join("\n");
    assert!(!text.contains("plan_"));
    assert!(!text.contains("step_"));
    assert!(text.contains(tr("plan_cancel_scope")));
    assert_eq!(
        choices(),
        [tr("plan_execute"), tr("plan_edit"), tr("plan_cancel")]
    );
    assert!(!choices().join(" ").contains("plan_"));
}
