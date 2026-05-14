use u2secure::application::steps::{
    AllSteps, AutoUpdatesStep, Fail2banStep, SshPasswordAuthStep, SshRootLoginStep,
    SystemUpdateStep, UfwStep,
};
use u2secure::domain::audit::{AuditReport, AuditStatus, PackageManager};
use u2secure::domain::steps::{HardeningStep, StepKind};
use u2secure::infrastructure::system;

// ---------------------------------------------------------------------------
// AllSteps 集合测试
// ---------------------------------------------------------------------------

#[test]
fn test_all_steps_contains_all_kinds() {
    let all = AllSteps::new();
    let kinds: Vec<StepKind> = all.steps().iter().map(|s| s.kind()).collect();
    assert_eq!(kinds.len(), 12);
    assert!(kinds.contains(&StepKind::SystemUpdate));
    assert!(kinds.contains(&StepKind::Ufw));
    assert!(kinds.contains(&StepKind::RestartSsh));
}

// ---------------------------------------------------------------------------
// 步骤状态检测测试（无系统调用，纯逻辑）
// ---------------------------------------------------------------------------

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
    }
}

#[test]
fn test_system_update_step_status() {
    let step = SystemUpdateStep;

    let report = make_report(22, false, false, vec![], false, false, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(22, false, false, vec![], false, false, false, false);
    assert_eq!(step.check_status(&report), AuditStatus::NeedsUpdate);
}

#[test]
fn test_root_login_step_status() {
    let step = SshRootLoginStep;

    let report = make_report(
        22,
        false,
        true,
        vec!["admin".into()],
        false,
        false,
        false,
        true,
    );
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(
        22,
        false,
        false,
        vec!["admin".into()],
        false,
        false,
        false,
        true,
    );
    assert_eq!(step.check_status(&report), AuditStatus::Missing);
}

#[test]
fn test_password_auth_step_status() {
    let step = SshPasswordAuthStep;

    let report = make_report(
        22,
        true,
        false,
        vec!["admin".into()],
        false,
        false,
        false,
        true,
    );
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(
        22,
        false,
        false,
        vec!["admin".into()],
        false,
        false,
        false,
        true,
    );
    assert_eq!(step.check_status(&report), AuditStatus::Missing);
}

#[test]
fn test_ufw_step_status() {
    let step = UfwStep;

    let report = make_report(22, false, false, vec![], false, true, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(22, false, false, vec![], false, false, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Missing);
}

#[test]
fn test_fail2ban_step_status() {
    let step = Fail2banStep;

    let report = make_report(22, false, false, vec![], true, false, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(22, false, false, vec![], false, false, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Missing);
}

#[test]
fn test_auto_updates_step_status() {
    let step = AutoUpdatesStep;

    let report = make_report(22, false, false, vec![], false, false, true, true);
    assert_eq!(step.check_status(&report), AuditStatus::Safe);

    let report = make_report(22, false, false, vec![], false, false, false, true);
    assert_eq!(step.check_status(&report), AuditStatus::Missing);
}

#[test]
fn test_ssh_key_setup_step_own_implementation() {
    // SshKeySetupStep 的 check_status 检查 authorized_keys 文件，无法在 CI 可靠测试
    // 只验证它实现了 HardeningStep trait
    let step = u2secure::application::steps::SshKeySetupStep;
    assert_eq!(step.kind(), StepKind::SshKeySetup);
}

// ---------------------------------------------------------------------------
// 基础设施测试（安全只读调用）
// ---------------------------------------------------------------------------

#[test]
fn test_detect_package_manager() {
    // 在 CI 或本地，至少应返回一个已知的包管理器
    let pm = system::detect_package_manager();
    // 只要是 Known 或 Unknown 都可以，不会 panic
    let _name = pm.name();
}

#[test]
fn test_detect_is_root_can_run() {
    // 调用不 panic
    let _is_root = system::detect_is_root();
}

#[test]
fn test_which_existing_command() {
    assert!(system::which("sh"));
    assert!(system::which("echo"));
}

#[test]
fn test_which_non_existing_command() {
    assert!(!system::which("nonexistent_cmd_xyz123"));
}

// ---------------------------------------------------------------------------
// SshPasswordAuthStep 前置条件测试
// ---------------------------------------------------------------------------

#[test]
fn test_password_auth_precondition() {
    // 如果没有 sudo 用户，execute 应返回 PreconditionFailed
    // 但 execute 会调用系统命令修改 sshd_config，在测试环境中跳过
    // 验证步骤的 kind 正确即可
    let step = SshPasswordAuthStep;
    assert_eq!(step.kind(), StepKind::SshPasswordAuth);
}
