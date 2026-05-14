use std::process::Command;

use chrono::Local;

use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::errors::DomainError;
use crate::domain::steps::{HardeningStep, StepKind, StepResult};
use crate::infrastructure::system;

// ---------------------------------------------------------------------------
// 所有步骤的集合容器
// ---------------------------------------------------------------------------

pub struct AllSteps {
    steps: Vec<Box<dyn HardeningStep>>,
}

impl AllSteps {
    pub fn new() -> Self {
        let steps: Vec<Box<dyn HardeningStep>> = vec![
            Box::new(SystemUpdateStep),
            Box::new(UserCreationStep),
            Box::new(SshRootLoginStep),
            Box::new(SshPortChangeStep),
            Box::new(SshPasswordAuthStep),
            Box::new(SshKeySetupStep),
            Box::new(UfwStep),
            Box::new(Fail2banStep),
            Box::new(AutoUpdatesStep),
            Box::new(SecurityScanStep),
            Box::new(LogAuditStep),
            Box::new(RestartSshStep),
        ];
        Self { steps }
    }

    pub fn steps(&self) -> &[Box<dyn HardeningStep>] {
        &self.steps
    }
}

impl Default for AllSteps {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 步骤 1：系统更新
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SystemUpdateStep;

impl HardeningStep for SystemUpdateStep {
    fn kind(&self) -> StepKind {
        StepKind::SystemUpdate
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.system_up_to_date {
            AuditStatus::Safe
        } else {
            AuditStatus::NeedsUpdate
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();

        // update
        let update_cmd = pm.update_cmd();
        if !update_cmd.is_empty() {
            let output = Command::new(update_cmd[0])
                .args(&update_cmd[1..])
                .output()
                .map_err(|e| {
                    DomainError::SystemCommandFailed(format!("update 失败: {e}"))
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::SystemCommandFailed(format!(
                    "update 失败: {stderr}"
                )));
            }
        }

        // upgrade
        let upgrade_cmd = pm.upgrade_cmd();
        if !upgrade_cmd.is_empty() {
            let output = Command::new(upgrade_cmd[0])
                .args(&upgrade_cmd[1..])
                .output()
                .map_err(|e| {
                    DomainError::SystemCommandFailed(format!("upgrade 失败: {e}"))
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::SystemCommandFailed(format!(
                    "upgrade 失败: {stderr}"
                )));
            }
        }

        Ok(StepResult {
            kind: StepKind::SystemUpdate,
            changes_made: true,
            message: "系统更新完成".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 2：非 root 用户创建
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct UserCreationStep;

impl HardeningStep for UserCreationStep {
    fn kind(&self) -> StepKind {
        StepKind::UserCreation
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.sudo_users.is_empty() {
            AuditStatus::Missing
        } else {
            AuditStatus::Safe
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 实际执行时外部交互提供用户名，这里为框架预留
        // presentation 层会拦截交互，这里只返回 stub
        Ok(StepResult {
            kind: StepKind::UserCreation,
            changes_made: false,
            message: "用户创建需要交互式输入，由 UI 层处理".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 3：禁止 root SSH 登录
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SshRootLoginStep;

impl HardeningStep for SshRootLoginStep {
    fn kind(&self) -> StepKind {
        StepKind::SshRootLogin
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.root_login_disabled {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        modify_sshd_config("PermitRootLogin", "prohibit-password")
    }
}

// ---------------------------------------------------------------------------
// 步骤 4：SSH 端口修改
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SshPortChangeStep;

impl HardeningStep for SshPortChangeStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPortChange
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.ssh_port != 22 {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 实际端口由 presentation 层交互提供，这里返回 stub
        Ok(StepResult {
            kind: StepKind::SshPortChange,
            changes_made: false,
            message: "端口修改需要交互式输入，由 UI 层处理".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 5：禁止密码登录
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SshPasswordAuthStep;

impl HardeningStep for SshPasswordAuthStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPasswordAuth
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.password_auth_disabled {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 先检查是否有 sudo 用户（前置条件）
        let sudo_users = system::detect_sudo_users();
        if sudo_users.is_empty() {
            return Err(DomainError::PreconditionFailed(
                "禁止密码登录前请先创建 sudo 用户".into(),
            ));
        }

        modify_sshd_config("PasswordAuthentication", "no")?;
        modify_sshd_config("ChallengeResponseAuthentication", "no")?;

        Ok(StepResult {
            kind: StepKind::SshPasswordAuth,
            changes_made: true,
            message: "密码登录已禁用".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 6：ED25519 密钥设置
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SshKeySetupStep;

impl HardeningStep for SshKeySetupStep {
    fn kind(&self) -> StepKind {
        StepKind::SshKeySetup
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        // 检查当前用户的 authorized_keys
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let auth_keys = format!("{home}/.ssh/authorized_keys");
        if std::path::Path::new(&auth_keys).exists() {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        Ok(StepResult {
            kind: StepKind::SshKeySetup,
            changes_made: false,
            message: "密钥设置需要交互式输入，由 UI 层处理".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 7：UFW 防火墙
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct UfwStep;

impl HardeningStep for UfwStep {
    fn kind(&self) -> StepKind {
        StepKind::Ufw
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.ufw_enabled {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 启用 UFW 并允许 SSH
        let port = system::detect_ssh_port();

        Command::new("ufw")
            .args(["allow", &port.to_string()])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("ufw allow 失败: {e}")))?;

        // 如果没启用，启用之
        if !system::detect_ufw_enabled() {
            // 非交互式启用
            Command::new("ufw")
                .args(["--force", "enable"])
                .output()
                .map_err(|e| DomainError::SystemCommandFailed(format!("ufw enable 失败: {e}")))?;
        }

        Ok(StepResult {
            kind: StepKind::Ufw,
            changes_made: true,
            message: format!("UFW 已启用，SSH 端口 {port} 已放行"),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 8：Fail2ban
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Fail2banStep;

impl HardeningStep for Fail2banStep {
    fn kind(&self) -> StepKind {
        StepKind::Fail2ban
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.fail2ban_installed {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        if !system::which("fail2ban-server") {
            // 安装 fail2ban
            let pm = system::detect_package_manager();
            let install_args: &[&str] = match pm {
                crate::domain::audit::PackageManager::Apt => {
                    &["install", "-y", "fail2ban"]
                }
                crate::domain::audit::PackageManager::Yum => {
                    &["install", "-y", "fail2ban"]
                }
                crate::domain::audit::PackageManager::Dnf => {
                    &["install", "-y", "fail2ban"]
                }
                _ => {
                    return Err(DomainError::SystemCommandFailed(
                        "不支持的包管理器".into(),
                    ));
                }
            };

            let pm_name = pm.name();
            Command::new(pm_name)
                .args(install_args)
                .output()
                .map_err(|e| {
                    DomainError::SystemCommandFailed(format!("安装 fail2ban 失败: {e}"))
                })?;
        }

        // 确保服务运行
        Command::new("systemctl")
            .args(["enable", "--now", "fail2ban"])
            .output()
            .ok();

        Ok(StepResult {
            kind: StepKind::Fail2ban,
            changes_made: true,
            message: "Fail2ban 已安装并运行".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 9：自动安全更新
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct AutoUpdatesStep;

impl HardeningStep for AutoUpdatesStep {
    fn kind(&self) -> StepKind {
        StepKind::AutoUpdates
    }

    fn check_status(&self, report: &AuditReport) -> AuditStatus {
        if report.auto_updates_enabled {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 仅支持 Debian/Ubuntu 的 unattended-upgrades
        let pm = system::detect_package_manager();
        if pm != crate::domain::audit::PackageManager::Apt {
            return Err(DomainError::SystemCommandFailed(
                "自动安全更新仅支持 Debian/Ubuntu".into(),
            ));
        }

        // 安装 unattended-upgrades
        Command::new("apt")
            .args(["install", "-y", "unattended-upgrades"])
            .output()
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!("安装 unattended-upgrades 失败: {e}"))
            })?;

        // 启用服务
        Command::new("systemctl")
            .args(["enable", "--now", "unattended-upgrades"])
            .output()
            .ok();

        Ok(StepResult {
            kind: StepKind::AutoUpdates,
            changes_made: true,
            message: "自动安全更新已启用".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 10：安全扫描（预留）
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SecurityScanStep;

impl HardeningStep for SecurityScanStep {
    fn kind(&self) -> StepKind {
        StepKind::SecurityScan
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        AuditStatus::Missing
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        Ok(StepResult {
            kind: StepKind::SecurityScan,
            changes_made: false,
            message: "安全扫描：安装 lynis 并运行审计（待实现）".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 11：日志与审计增强（预留）
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct LogAuditStep;

impl HardeningStep for LogAuditStep {
    fn kind(&self) -> StepKind {
        StepKind::LogAudit
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        AuditStatus::Missing
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        Ok(StepResult {
            kind: StepKind::LogAudit,
            changes_made: false,
            message: "日志与审计增强：配置 logwatch/aide（待实现）".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 12：SSH 服务重启与验证
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RestartSshStep;

impl HardeningStep for RestartSshStep {
    fn kind(&self) -> StepKind {
        StepKind::RestartSsh
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        AuditStatus::Missing
    }

    fn execute(&self) -> Result<StepResult, DomainError> {
        // 重启 SSH 服务
        let output = Command::new("systemctl")
            .args(["restart", "sshd"])
            .output()
            .or_else(|_| Command::new("systemctl").args(["restart", "ssh"]).output())
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!("重启 SSH 服务失败: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "重启 SSH 服务失败: {stderr}"
            )));
        }

        Ok(StepResult {
            kind: StepKind::RestartSsh,
            changes_made: true,
            message: "SSH 服务已重启，建议在另一终端验证连接".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 辅助函数：修改 sshd_config
// ---------------------------------------------------------------------------

/// 修改 sshd_config 中的某条指令。备份原文件，追加或替换。
fn modify_sshd_config(key: &str, value: &str) -> Result<StepResult, DomainError> {
    let path = std::path::Path::new("/etc/ssh/sshd_config");
    if !path.exists() {
        return Err(DomainError::ParseError("sshd_config 不存在".into()));
    }

    // 备份
    let backup = format!(
        "/etc/ssh/sshd_config.bak.{}",
        Local::now().format("%Y%m%d%H%M%S")
    );
    std::fs::copy(path, &backup)
        .map_err(|e| DomainError::SystemCommandFailed(format!("备份失败: {e}")))?;

    let content = std::fs::read_to_string(path)
        .map_err(|e| DomainError::ParseError(format!("读取失败: {e}")))?;

    let mut found = false;
    let new_content: Vec<String> = content
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                return line.to_string();
            }
            if trimmed.starts_with(key) {
                found = true;
                format!("{key} {value}")
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut result = new_content.join("\n");
    if !found {
        // 追加到文件末尾
        result.push_str(&format!("\n{key} {value}\n"));
    }

    std::fs::write(path, result)
        .map_err(|e| DomainError::SystemCommandFailed(format!("写入失败: {e}")))?;

    Ok(StepResult {
        kind: StepKind::SshRootLogin,
        changes_made: true,
        message: format!("{key} 已设置为 {value}（备份: {backup}）"),
    })
}
