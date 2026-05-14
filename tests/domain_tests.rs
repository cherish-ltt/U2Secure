use u2secure::domain::audit::{AuditItem, AuditReport, AuditStatus, PackageManager};
use u2secure::domain::steps::{ExecuteParams, SshKeyAction, StepKind};

#[test]
fn test_audit_status_icons() {
    assert_eq!(AuditStatus::Safe.icon(), "✅");
    assert_eq!(AuditStatus::Partial.icon(), "⚠️");
    assert_eq!(AuditStatus::Missing.icon(), "❌");
    assert_eq!(AuditStatus::NeedsUpdate.icon(), "🔄");
}

#[test]
fn test_audit_item_constructors() {
    let item = AuditItem::safe("测试", "已启用".into());
    assert_eq!(item.status, AuditStatus::Safe);
    assert_eq!(item.detail, "已启用");

    let item = AuditItem::missing("测试", "未配置".into());
    assert_eq!(item.status, AuditStatus::Missing);

    let item = AuditItem::needs_update("测试", "需要更新".into());
    assert_eq!(item.status, AuditStatus::NeedsUpdate);

    let item = AuditItem::partial("测试", "部分配置".into());
    assert_eq!(item.status, AuditStatus::Partial);
}

#[test]
fn test_package_manager_display() {
    assert_eq!(PackageManager::Apt.name(), "apt");
    assert_eq!(PackageManager::Yum.name(), "yum");
    assert_eq!(PackageManager::Dnf.to_string(), "dnf");
    assert_eq!(PackageManager::Unknown.to_string(), "unknown");
}

#[test]
fn test_package_manager_update_upgrade_cmd() {
    assert_eq!(PackageManager::Apt.update_cmd(), &["apt", "update"]);
    assert_eq!(PackageManager::Apt.upgrade_cmd(), &["apt", "upgrade", "-y"]);
    assert_eq!(PackageManager::Yum.update_cmd(), &["yum", "update", "-y"]);
    assert_eq!(PackageManager::Unknown.update_cmd(), &[] as &[&str]);
}

#[test]
fn test_step_kind_labels() {
    assert_eq!(StepKind::SystemUpdate.label(), "系统更新");
    assert_eq!(StepKind::UserCreation.label(), "非 root 用户创建");
    assert_eq!(StepKind::SshRootLogin.label(), "禁止 root SSH 登录");
    assert_eq!(StepKind::SshPortChange.label(), "SSH 端口修改");
    assert_eq!(StepKind::SshPasswordAuth.label(), "禁止密码登录");
    assert_eq!(StepKind::SshKeySetup.label(), "ED25519 密钥设置");
    assert_eq!(StepKind::Ufw.label(), "UFW 防火墙配置");
    assert_eq!(StepKind::Fail2ban.label(), "Fail2ban 安装配置");
    assert_eq!(StepKind::AutoUpdates.label(), "自动安全更新");
    assert_eq!(StepKind::SecurityScan.label(), "安全扫描");
    assert_eq!(StepKind::LogAudit.label(), "日志与审计增强");
    assert_eq!(StepKind::RestartSsh.label(), "SSH 服务重启与验证");
}

#[test]
fn test_step_kind_all_contains_all() {
    let all = StepKind::all();
    assert_eq!(all.len(), 12);
    assert!(all.contains(&StepKind::SystemUpdate));
    assert!(all.contains(&StepKind::RestartSsh));
}

#[test]
fn test_audit_report_status_for_all_secure() {
    let report = AuditReport {
        items: vec![],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 2222,
        password_auth_disabled: true,
        root_login_disabled: true,
        sudo_users: vec!["alice".into()],
        fail2ban_installed: true,
        ufw_enabled: true,
        auto_updates_enabled: true,
        system_up_to_date: true,
    };

    assert_eq!(report.status_for(StepKind::SystemUpdate), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::UserCreation), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::SshRootLogin), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::SshPortChange), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::SshPasswordAuth), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::Ufw), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::Fail2ban), AuditStatus::Safe);
    assert_eq!(report.status_for(StepKind::AutoUpdates), AuditStatus::Safe);
}

#[test]
fn test_audit_report_status_for_all_missing() {
    let report = AuditReport {
        items: vec![],
        is_root: false,
        package_manager: PackageManager::Unknown,
        ssh_port: 22,
        password_auth_disabled: false,
        root_login_disabled: false,
        sudo_users: vec![],
        fail2ban_installed: false,
        ufw_enabled: false,
        auto_updates_enabled: false,
        system_up_to_date: false,
    };

    assert_eq!(report.status_for(StepKind::SystemUpdate), AuditStatus::NeedsUpdate);
    assert_eq!(report.status_for(StepKind::UserCreation), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::SshRootLogin), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::SshPortChange), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::SshPasswordAuth), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::SshKeySetup), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::Ufw), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::Fail2ban), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::AutoUpdates), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::SecurityScan), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::LogAudit), AuditStatus::Missing);
    assert_eq!(report.status_for(StepKind::RestartSsh), AuditStatus::Missing);
}

#[test]
fn test_audit_report_status_for_key_setup_with_sudo_users() {
    let report = AuditReport {
        items: vec![],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 22,
        password_auth_disabled: false,
        root_login_disabled: false,
        sudo_users: vec!["bob".into()],
        fail2ban_installed: false,
        ufw_enabled: false,
        auto_updates_enabled: false,
        system_up_to_date: false,
    };

    // 有 sudo 用户 -> Partial（可能有密钥）
    assert_eq!(report.status_for(StepKind::SshKeySetup), AuditStatus::Partial);
}

#[test]
fn test_audit_report_summary_lines() {
    let report = AuditReport {
        items: vec![],
        is_root: false,
        package_manager: PackageManager::Apt,
        ssh_port: 2222,
        password_auth_disabled: true,
        root_login_disabled: true,
        sudo_users: vec!["admin".into()],
        fail2ban_installed: false,
        ufw_enabled: true,
        auto_updates_enabled: false,
        system_up_to_date: true,
    };

    let summary = report.summary_lines();
    assert_eq!(summary.len(), 8);
    // 系统更新 -> Safe
    assert_eq!(summary[0].1, AuditStatus::Safe);
    // 非 root 用户 -> Safe
    assert_eq!(summary[1].1, AuditStatus::Safe);
    // 禁止 root SSH -> Safe
    assert_eq!(summary[2].1, AuditStatus::Safe);
    // SSH 端口 -> Safe
    assert_eq!(summary[3].1, AuditStatus::Safe);
    // 禁止密码 -> Safe
    assert_eq!(summary[4].1, AuditStatus::Safe);
    // UFW -> Safe
    assert_eq!(summary[5].1, AuditStatus::Safe);
    // Fail2ban -> Missing
    assert_eq!(summary[6].1, AuditStatus::Missing);
    // 自动更新 -> Missing
    assert_eq!(summary[7].1, AuditStatus::Missing);
}

#[test]
fn test_step_kind_display() {
    assert_eq!(StepKind::SystemUpdate.to_string(), "系统更新");
    assert_eq!(StepKind::RestartSsh.to_string(), "SSH 服务重启与验证");
}

#[test]
fn test_step_kind_check_default_status() {
    let report = AuditReport {
        items: vec![],
        is_root: true,
        package_manager: PackageManager::Apt,
        ssh_port: 2222,
        password_auth_disabled: true,
        root_login_disabled: false,
        sudo_users: vec!["admin".into()],
        fail2ban_installed: false,
        ufw_enabled: true,
        auto_updates_enabled: false,
        system_up_to_date: true,
    };

    assert_eq!(StepKind::SystemUpdate.check_default_status(&report), AuditStatus::Safe);
    assert_eq!(StepKind::SshRootLogin.check_default_status(&report), AuditStatus::Missing);
    assert_eq!(StepKind::Fail2ban.check_default_status(&report), AuditStatus::Missing);
}

// ---------------------------------------------------------------------------
// ExecuteParams 测试
// ---------------------------------------------------------------------------

#[test]
fn test_execute_params_default() {
    let params = ExecuteParams::default();
    assert!(params.new_username.is_none());
    assert!(params.lock_password);
    assert!(params.new_ssh_port.is_none());
    assert!(params.ssh_key_action.is_none());
    assert!(params.ssh_key_username.is_none());
}

#[test]
fn test_execute_params_user_creation() {
    let params = ExecuteParams {
        new_username: Some("deploy".into()),
        lock_password: true,
        ..Default::default()
    };
    assert_eq!(params.new_username.as_deref(), Some("deploy"));
    assert!(params.lock_password);
}

#[test]
fn test_execute_params_ssh_port() {
    let params = ExecuteParams {
        new_ssh_port: Some(2222),
        ..Default::default()
    };
    assert_eq!(params.new_ssh_port, Some(2222));
}

#[test]
fn test_execute_params_ssh_key_generate() {
    let params = ExecuteParams {
        ssh_key_username: Some("admin".into()),
        ssh_key_action: Some(SshKeyAction::GenerateNew),
        ..Default::default()
    };
    assert_eq!(params.ssh_key_username.as_deref(), Some("admin"));
    assert!(matches!(params.ssh_key_action, Some(SshKeyAction::GenerateNew)));
}

#[test]
fn test_execute_params_ssh_key_paste() {
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host".to_string();
    let params = ExecuteParams {
        ssh_key_username: Some("admin".into()),
        ssh_key_action: Some(SshKeyAction::PasteKey(key.clone())),
        ..Default::default()
    };
    assert!(matches!(&params.ssh_key_action, Some(SshKeyAction::PasteKey(k)) if k == &key));
}

#[test]
fn test_execute_params_all_fields() {
    let params = ExecuteParams {
        new_username: Some("deploy".into()),
        lock_password: false,
        new_ssh_port: Some(2222),
        ssh_key_username: Some("deploy".into()),
        ssh_key_action: Some(SshKeyAction::GenerateNew),
    };
    assert_eq!(params.new_username.as_deref(), Some("deploy"));
    assert!(!params.lock_password);
    assert_eq!(params.new_ssh_port, Some(2222));
    assert_eq!(params.ssh_key_username.as_deref(), Some("deploy"));
}

// ---------------------------------------------------------------------------
// SshKeyAction 测试
// ---------------------------------------------------------------------------

#[test]
fn test_ssh_key_action_debug() {
    let action = SshKeyAction::GenerateNew;
    assert!(format!("{action:?}").contains("GenerateNew"));

    let action = SshKeyAction::PasteKey("ssh-ed25519 key".into());
    assert!(format!("{action:?}").contains("PasteKey"));
}

#[test]
fn test_ssh_key_action_clone() {
    let action = SshKeyAction::PasteKey("ssh-ed25519 key".into());
    let cloned = action.clone();
    assert!(matches!(cloned, SshKeyAction::PasteKey(_)));
}
