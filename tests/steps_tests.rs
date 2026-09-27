//! 步骤状态与默认勾选策略测试（纯逻辑，不触碰真实系统）

use u2secure::application::steps::step_for;
use u2secure::domain::audit::{AuditReport, AuditStatus, PackageManager};
use u2secure::domain::steps::{ExecuteParams, HardeningStep, StepKind, StepOutcome, StepResult};

/// 构造审计报告（默认全部"未配置"）
// 测试辅助函数：参数即用例维度，拆成结构体反而降低可读性
#[allow(clippy::too_many_arguments)]
fn make_report(
    ssh_port: u16,
    password_disabled: bool,
    root_disabled: bool,
    sudo_users: Vec<String>,
    fail2ban: bool,
    ufw: bool,
    auto_updates: bool,
    sys_up_to_date: bool,
) -> AuditReport {
    AuditReport {
        items: vec![],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port,
        password_auth_disabled: password_disabled,
        root_login_disabled: root_disabled,
        sudo_users,
        fail2ban_installed: fail2ban,
        ufw_enabled: ufw,
        auto_updates_enabled: auto_updates,
        system_up_to_date: sys_up_to_date,
        lynis_installed: false,
        logwatch_installed: false,
        aide_installed: false,
        ssh_restart_needed: false,
    }
}

fn hardened_report() -> AuditReport {
    AuditReport {
        items: vec![],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 2222,
        password_auth_disabled: true,
        root_login_disabled: true,
        sudo_users: vec!["admin".into()],
        fail2ban_installed: true,
        ufw_enabled: true,
        auto_updates_enabled: true,
        system_up_to_date: true,
        lynis_installed: true,
        logwatch_installed: true,
        aide_installed: true,
        ssh_restart_needed: false,
    }
}

// AllSteps 集合测试

#[test]
fn test_all_kinds_have_step_implementation() {
    let kinds: Vec<StepKind> = StepKind::all()
        .iter()
        .map(|kind| step_for(*kind).kind())
        .collect();
    assert_eq!(kinds.len(), 12);
    assert_eq!(kinds, StepKind::all().to_vec());
}

#[test]
fn test_step_for_matches_kind() {
    for kind in StepKind::all() {
        assert_eq!(step_for(*kind).kind(), *kind);
    }
}

// 步骤状态检测（领域层单一真值）

#[test]
fn test_status_for_hardened_system() {
    let report = hardened_report();
    for kind in StepKind::all() {
        if *kind == StepKind::SshKeySetup {
            // 密钥设置无法可靠判定：有 sudo 用户即认为"部分配置"
            continue;
        }
        assert_eq!(
            report.status_for(*kind),
            AuditStatus::Safe,
            "{} 应为已安全配置",
            kind.label()
        );
    }
    assert_eq!(
        report.status_for(StepKind::SshKeySetup),
        AuditStatus::Partial
    );
}

#[test]
fn test_status_for_fresh_system() {
    let report = make_report(22, false, false, vec![], false, false, false, false);

    assert_eq!(
        report.status_for(StepKind::SystemUpdate),
        AuditStatus::NeedsUpdate
    );
    for kind in [
        StepKind::UserCreation,
        StepKind::SshRootLogin,
        StepKind::SshPortChange,
        StepKind::SshPasswordAuth,
        StepKind::Ufw,
        StepKind::Fail2ban,
        StepKind::AutoUpdates,
        StepKind::SecurityScan,
        StepKind::LogAudit,
    ] {
        assert_eq!(
            report.status_for(kind),
            AuditStatus::Missing,
            "{} 应为未配置",
            kind.label()
        );
    }
}

#[test]
fn test_security_scan_status_follows_lynis() {
    let mut report = make_report(22, false, false, vec![], false, false, false, false);
    assert_eq!(
        report.status_for(StepKind::SecurityScan),
        AuditStatus::Missing
    );
    report.lynis_installed = true;
    assert_eq!(report.status_for(StepKind::SecurityScan), AuditStatus::Safe);
}

#[test]
fn test_log_audit_status_partial_when_half_installed() {
    let mut report = make_report(22, false, false, vec![], false, false, false, false);
    assert_eq!(report.status_for(StepKind::LogAudit), AuditStatus::Missing);
    report.logwatch_installed = true;
    assert_eq!(report.status_for(StepKind::LogAudit), AuditStatus::Partial);
    report.aide_installed = true;
    assert_eq!(report.status_for(StepKind::LogAudit), AuditStatus::Safe);
}

#[test]
fn test_restart_ssh_status_follows_pending_config() {
    let mut report = hardened_report();
    assert_eq!(report.status_for(StepKind::RestartSsh), AuditStatus::Safe);
    report.ssh_restart_needed = true;
    assert_eq!(
        report.status_for(StepKind::RestartSsh),
        AuditStatus::NeedsUpdate
    );
}

#[test]
fn test_ssh_key_setup_partial_with_sudo_users() {
    let report = make_report(
        22,
        false,
        false,
        vec!["bob".into()],
        false,
        false,
        false,
        false,
    );
    assert_eq!(
        report.status_for(StepKind::SshKeySetup),
        AuditStatus::Partial
    );
}

// 默认勾选策略：9/10/11 默认关闭

#[test]
fn test_opt_in_steps_are_nine_ten_eleven() {
    let opt_in: Vec<StepKind> = StepKind::all()
        .iter()
        .copied()
        .filter(|k| k.is_opt_in())
        .collect();
    assert_eq!(
        opt_in,
        vec![
            StepKind::AutoUpdates,
            StepKind::SecurityScan,
            StepKind::LogAudit
        ]
    );
    // 可选步骤失败不触发全局回滚
    for kind in StepKind::all() {
        assert_eq!(kind.is_optional(), kind.is_opt_in());
    }
}

#[test]
fn test_opt_in_steps_never_default_checked() {
    let report = make_report(22, false, false, vec![], false, false, false, false);
    for kind in [
        StepKind::AutoUpdates,
        StepKind::SecurityScan,
        StepKind::LogAudit,
    ] {
        assert!(
            !kind.default_checked(&report),
            "{} 默认不应勾选",
            kind.label()
        );
    }
}

#[test]
fn test_default_checked_skips_safe_steps() {
    let report = hardened_report();
    for kind in StepKind::all() {
        if *kind == StepKind::SshKeySetup {
            // Partial 状态仍会默认勾选（保持既有交互行为）
            continue;
        }
        assert!(
            !kind.default_checked(&report),
            "{} 已安全配置，默认不应勾选",
            kind.label()
        );
    }

    let fresh = make_report(22, false, false, vec![], false, false, false, false);
    assert!(StepKind::SshRootLogin.default_checked(&fresh));
    assert!(StepKind::Ufw.default_checked(&fresh));
    // 仅在配置待生效时才需要重启 SSH
    assert!(!StepKind::RestartSsh.default_checked(&fresh));
    let mut pending = fresh.clone();
    pending.ssh_restart_needed = true;
    assert!(StepKind::RestartSsh.default_checked(&pending));
}

#[test]
fn test_touches_package_manager() {
    let pm_steps: Vec<StepKind> = StepKind::all()
        .iter()
        .copied()
        .filter(|k| k.touches_package_manager())
        .collect();
    assert_eq!(
        pm_steps,
        vec![
            StepKind::SystemUpdate,
            StepKind::Fail2ban,
            StepKind::AutoUpdates,
            StepKind::SecurityScan,
            StepKind::LogAudit,
        ]
    );
}

#[test]
fn test_step_kind_slug_unique() {
    let mut slugs: Vec<&str> = StepKind::all().iter().map(|k| k.slug()).collect();
    let count = slugs.len();
    slugs.sort_unstable();
    slugs.dedup();
    assert_eq!(slugs.len(), count, "slug 必须唯一");
}

#[test]
fn test_step_kind_check_default_status_delegates() {
    let report = make_report(22, false, false, vec![], false, false, false, true);
    assert_eq!(
        StepKind::SystemUpdate.check_default_status(&report),
        AuditStatus::Safe
    );
    assert_eq!(
        StepKind::SshRootLogin.check_default_status(&report),
        AuditStatus::Missing
    );
}

// StepResult / StepOutcome

#[test]
fn test_step_outcome_helpers() {
    let changed = StepResult::changed(StepKind::Ufw, "ok");
    assert!(changed.is_changed());
    assert!(!changed.is_failed());
    assert!(changed.artifacts.is_empty());

    let skipped = StepResult::skipped(StepKind::SecurityScan, "不支持");
    assert_eq!(skipped.outcome, StepOutcome::Skipped);

    let failed = StepResult::failed(StepKind::LogAudit, "安装失败");
    assert!(failed.is_failed());

    let with_artifacts = failed.with_artifacts(vec!["/tmp/a.log".into()]);
    assert_eq!(with_artifacts.artifacts, vec!["/tmp/a.log".to_string()]);
}

#[test]
fn test_step_outcome_labels_and_icons() {
    assert_eq!(StepOutcome::Changed.icon(), "✅");
    assert_eq!(StepOutcome::Skipped.icon(), "⏭");
    assert_eq!(StepOutcome::Failed.icon(), "❌");
    assert_eq!(StepOutcome::Changed.label(), "成功");
    assert_eq!(StepOutcome::Skipped.label(), "跳过");
    assert_eq!(StepOutcome::Failed.label(), "失败");
}

// ExecuteParams

#[test]
fn test_execute_params_default_has_no_mirror() {
    let params = ExecuteParams::default();
    assert!(params.mirror.is_empty());
    assert!(params.report_dir.is_none());
    assert!(params.live_log.is_none());
}

#[test]
fn test_step_for_returns_send_step() {
    // 编译期校验：步骤必须可跨线程执行（异步执行的前提）
    let step: Box<dyn HardeningStep + Send> = step_for(StepKind::Ufw);
    assert_eq!(step.kind(), StepKind::Ufw);
}
