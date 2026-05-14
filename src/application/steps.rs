use std::process::Command;

use chrono::Local;

use crate::domain::audit::{AuditReport, AuditStatus, PackageManager};
use crate::domain::errors::DomainError;
use crate::domain::steps::{ExecuteParams, HardeningStep, SshKeyAction, StepKind, StepResult};
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();
        if pm == PackageManager::Unknown {
            return Err(DomainError::SystemCommandFailed("无法识别的包管理器".into()));
        }

        let update_cmd = pm.update_cmd();
        let output = Command::new(update_cmd[0])
            .args(&update_cmd[1..])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("update 失败: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!("update 失败: {stderr}")));
        }

        let upgrade_cmd = pm.upgrade_cmd();
        let output = Command::new(upgrade_cmd[0])
            .args(&upgrade_cmd[1..])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("upgrade 失败: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!("upgrade 失败: {stderr}")));
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

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let username = params
            .new_username
            .as_deref()
            .ok_or_else(|| DomainError::PreconditionFailed("未提供用户名".into()))?;

        if system::user_exists(username) {
            return Err(DomainError::PreconditionFailed(format!(
                "用户 '{username}' 已存在"
            )));
        }

        system::create_system_user(username)?;

        if params.lock_password {
            system::lock_user_password(username)?;
        }

        // 为用户生成 SSH key pair
        let pub_key_path = system::generate_ssh_keypair(username)?;

        // 读取公钥并添加到 authorized_keys
        if let Ok(pub_key) = std::fs::read_to_string(&pub_key_path) {
            system::add_authorized_key(username, pub_key.trim())?;
        }

        Ok(StepResult {
            kind: StepKind::UserCreation,
            changes_made: true,
            message: format!(
                "用户 '{username}' 已创建并加入 sudo 组，密钥已设置（私钥: ~/.ssh/id_ed25519）"
            ),
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 前置条件：必须存在 sudo 用户
        let sudo_users = system::detect_sudo_users();
        if sudo_users.is_empty() {
            return Err(DomainError::PreconditionFailed(
                "禁止 root 登录前请先创建 sudo 用户".into(),
            ));
        }

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

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let new_port = params
            .new_ssh_port
            .ok_or_else(|| DomainError::PreconditionFailed("未提供新 SSH 端口".into()))?;

        if new_port == 0 {
            return Err(DomainError::PreconditionFailed(
                "端口 0 无效".into(),
            ));
        }

        let result = modify_sshd_config("Port", &new_port.to_string())?;

        // UFW 放行新端口（如果 ufw 已启用）
        if system::detect_ufw_enabled() {
            let _ = Command::new("ufw")
                .args(["allow", &new_port.to_string()])
                .output();
        }

        Ok(StepResult {
            kind: StepKind::SshPortChange,
            changes_made: true,
            message: format!("SSH 端口已修改为 {new_port}（{})", result.message),
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 前置条件
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
            message: "密码登录已禁用（仅允许密钥登录）".into(),
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
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let auth_keys = format!("{home}/.ssh/authorized_keys");
        if std::path::Path::new(&auth_keys).exists() {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let username = params
            .ssh_key_username
            .as_deref()
            .ok_or_else(|| DomainError::PreconditionFailed("未提供目标用户名".into()))?;

        let action = params
            .ssh_key_action
            .as_ref()
            .ok_or_else(|| DomainError::PreconditionFailed("未选择密钥操作".into()))?;

        match action {
            SshKeyAction::GenerateNew => {
                let pub_key_path = system::generate_ssh_keypair(username)?;
                let msg = format!(
                    "ED25519 密钥对已生成\n  私钥: {}\n  公钥: {}.pub\n  请立即复制私钥并安全保存！",
                    pub_key_path.trim_end_matches(".pub"),
                    pub_key_path
                );
                Ok(StepResult {
                    kind: StepKind::SshKeySetup,
                    changes_made: true,
                    message: msg,
                })
            }
            SshKeyAction::PasteKey(pub_key) => {
                system::add_authorized_key(username, pub_key)?;
                Ok(StepResult {
                    kind: StepKind::SshKeySetup,
                    changes_made: true,
                    message: format!("公钥已添加到 {username} 的 authorized_keys"),
                })
            }
        }
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let port = system::detect_ssh_port();

        let output = Command::new("ufw")
            .args(["allow", &port.to_string()])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("ufw allow 失败: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!("ufw allow 失败: {stderr}")));
        }

        if !system::detect_ufw_enabled() {
            let output = Command::new("ufw")
                .args(["--force", "enable"])
                .output()
                .map_err(|e| DomainError::SystemCommandFailed(format!("ufw enable 失败: {e}")))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::SystemCommandFailed(format!(
                    "ufw enable 失败: {stderr}"
                )));
            }
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        if !system::which("fail2ban-server") {
            let pm = system::detect_package_manager();
            let (pm_name, install_args): (&str, &[&str]) = match pm {
                PackageManager::Apt => ("apt", &["install", "-y", "fail2ban"]),
                PackageManager::Yum => ("yum", &["install", "-y", "fail2ban"]),
                PackageManager::Dnf => ("dnf", &["install", "-y", "fail2ban"]),
                _ => {
                    return Err(DomainError::SystemCommandFailed(
                        "不支持的包管理器".into(),
                    ));
                }
            };

            let output = Command::new(pm_name)
                .args(install_args)
                .output()
                .map_err(|e| {
                    DomainError::SystemCommandFailed(format!("安装 fail2ban 失败: {e}"))
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::SystemCommandFailed(format!(
                    "安装 fail2ban 失败: {stderr}"
                )));
            }
        }

        // 配置监狱规则（使用 SSH 端口）
        let port = system::detect_ssh_port();
        let jail_local = "[sshd]\nenabled = true\nport = ".to_string() + &port.to_string() + "\n";
        let _ = std::fs::write("/etc/fail2ban/jail.local", &jail_local);

        let _ = Command::new("systemctl")
            .args(["enable", "--now", "fail2ban"])
            .output();

        Ok(StepResult {
            kind: StepKind::Fail2ban,
            changes_made: true,
            message: format!("Fail2ban 已安装并运行，SSH 端口 {port} 已加入监控"),
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();
        if pm != PackageManager::Apt {
            return Err(DomainError::SystemCommandFailed(
                "自动安全更新仅支持 Debian/Ubuntu".into(),
            ));
        }

        let output = Command::new("apt")
            .args(["install", "-y", "unattended-upgrades"])
            .output()
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!("安装 unattended-upgrades 失败: {e}"))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "安装 unattended-upgrades 失败: {stderr}"
            )));
        }

        // 写入配置：启用自动安全更新
        let auto_config = "APT::Periodic::Update-Package-Lists \"1\";\n\
                          APT::Periodic::Unattended-Upgrade \"1\";\n\
                          APT::Periodic::Download-Upgradeable-Packages \"1\";\n\
                          APT::Periodic::AutocleanInterval \"7\";\n";
        let _ = std::fs::write("/etc/apt/apt.conf.d/20auto-upgrades", auto_config);

        let _ = Command::new("systemctl")
            .args(["enable", "--now", "unattended-upgrades"])
            .output();

        Ok(StepResult {
            kind: StepKind::AutoUpdates,
            changes_made: true,
            message: "自动安全更新已启用（每日检查，自动安装安全补丁）".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 10：安全扫描
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SecurityScanStep;

impl HardeningStep for SecurityScanStep {
    fn kind(&self) -> StepKind {
        StepKind::SecurityScan
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        if system::which("lynis") {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        if !system::which("lynis") {
            // 安装 lynis
            let pm = system::detect_package_manager();
            match pm {
                PackageManager::Apt => {
                    // 添加 lynis 仓库并安装
                    let _ = Command::new("sh")
                        .args(["-c", "apt install -y curl && \
                                        curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | \
                                        apt-key add - 2>/dev/null && \
                                        echo 'deb https://packages.cisofy.com/community/lynis/deb/ stable main' \
                                        > /etc/apt/sources.list.d/lynis.list && \
                                        apt update && apt install -y lynis"])
                        .output();
                }
                PackageManager::Yum | PackageManager::Dnf => {
                    let pm_name = pm.name();
                    let _ = Command::new(pm_name)
                        .args(["install", "-y", "lynis"])
                        .output();
                }
                PackageManager::Unknown => {
                    return Err(DomainError::SystemCommandFailed(
                        "无法确定包管理器，请手动安装 lynis".into(),
                    ));
                }
            }
        }

        if !system::which("lynis") {
            return Ok(StepResult {
                kind: StepKind::SecurityScan,
                changes_made: false,
                message: "lynis 无法自动安装，请手动安装后重新运行".into(),
            });
        }

        // 执行 lynis 审计（仅 system audit，不需要交互）
        let output = Command::new("lynis")
            .args(["audit", "system", "--quick"])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("lynis 执行失败: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // 提取摘要信息
        let warnings = stdout
            .lines()
            .filter(|l| l.contains("Warning"))
            .count();
        let suggestions = stdout
            .lines()
            .filter(|l| l.contains("Suggestion"))
            .count();

        Ok(StepResult {
            kind: StepKind::SecurityScan,
            changes_made: true,
            message: format!(
                "lynis 安全扫描完成（{warnings} 个警告, {suggestions} 个建议）\n  详细报告: /var/log/lynis.log"
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// 步骤 11：日志与审计增强
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct LogAuditStep;

impl HardeningStep for LogAuditStep {
    fn kind(&self) -> StepKind {
        StepKind::LogAudit
    }

    fn check_status(&self, _report: &AuditReport) -> AuditStatus {
        let has_logwatch = system::which("logwatch");
        let has_aide = system::which("aide");
        if has_logwatch && has_aide {
            AuditStatus::Safe
        } else {
            AuditStatus::Missing
        }
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let mut installed = vec![];

        // 安装 logwatch
        if !system::which("logwatch") {
            let pm = system::detect_package_manager();
            let pm_name = pm.name();
            let _ = Command::new(pm_name)
                .args(["install", "-y", "logwatch"])
                .output();
            if system::which("logwatch") {
                installed.push("logwatch");
            }
        } else {
            installed.push("logwatch");
        }

        // 安装 aide
        if !system::which("aide") {
            let pm = system::detect_package_manager();
            let pm_name = pm.name();
            let _ = Command::new(pm_name)
                .args(["install", "-y", "aide"])
                .output();
            if system::which("aide") {
                installed.push("aide");
            }
        } else {
            installed.push("aide");
        }

        // 配置 logwatch 每日报告
        let _ = std::fs::write(
            "/etc/cron.daily/00logwatch",
            "#!/bin/bash\n/usr/sbin/logwatch --output mail --format html --range today\n",
        );
        let _ = Command::new("chmod")
            .args(["+x", "/etc/cron.daily/00logwatch"])
            .output();

        // 初始化 aide 数据库
        let _ = Command::new("aideinit")
            .args(["--yes"])
            .output();

        Ok(StepResult {
            kind: StepKind::LogAudit,
            changes_made: true,
            message: format!(
                "日志与审计增强完成\n  已安装/配置: {}\n  logwatch: 每日邮件报告\n  aide: 文件完整性检查已初始化",
                installed.join(", ")
            ),
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

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 先验证 sshd_config 语法
        let check = Command::new("sshd")
            .args(["-t"])
            .output()
            .map_err(|e| DomainError::SystemCommandFailed(format!("sshd 语法检查失败: {e}")))?;

        if !check.status.success() {
            let stderr = String::from_utf8_lossy(&check.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "sshd_config 语法错误，请检查配置: {stderr}"
            )));
        }

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

        // 验证服务状态
        let status = Command::new("systemctl")
            .args(["is-active", "sshd"])
            .output()
            .or_else(|_| Command::new("systemctl").args(["is-active", "ssh"]).output());

        let status_str = match &status {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".into(),
        };

        Ok(StepResult {
            kind: StepKind::RestartSsh,
            changes_made: true,
            message: format!(
                "SSH 服务已重启（状态: {status_str}）\n  ⚠️  请在另一终端验证连接后再关闭当前会话！\n  🔄 如需回滚：systemctl restart sshd 或恢复备份 /etc/ssh/sshd_config.bak.*"
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// 辅助函数：修改 sshd_config
// ---------------------------------------------------------------------------

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
            // 检查是否以 key 开头（忽略空格）
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
        result.push_str(&format!("\n{key} {value}\n"));
    }

    std::fs::write(path, result)
        .map_err(|e| DomainError::SystemCommandFailed(format!("写入失败: {e}")))?;

    Ok(StepResult {
        kind: StepKind::SshRootLogin, // 占位 kind，调用方会覆盖
        changes_made: true,
        message: format!("{key} 已设置为 {value}（备份: {backup}）"),
    })
}
