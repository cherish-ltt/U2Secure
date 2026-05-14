use std::fmt;

use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::errors::DomainError;

/// 加固步骤的类型（值对象）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepKind {
    SystemUpdate,
    UserCreation,
    SshRootLogin,
    SshPortChange,
    SshPasswordAuth,
    SshKeySetup,
    Ufw,
    Fail2ban,
    AutoUpdates,
    SecurityScan,
    LogAudit,
    RestartSsh,
}

impl StepKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SystemUpdate => "系统更新",
            Self::UserCreation => "非 root 用户创建",
            Self::SshRootLogin => "禁止 root SSH 登录",
            Self::SshPortChange => "SSH 端口修改",
            Self::SshPasswordAuth => "禁止密码登录",
            Self::SshKeySetup => "ED25519 密钥设置",
            Self::Ufw => "UFW 防火墙配置",
            Self::Fail2ban => "Fail2ban 安装配置",
            Self::AutoUpdates => "自动安全更新",
            Self::SecurityScan => "安全扫描",
            Self::LogAudit => "日志与审计增强",
            Self::RestartSsh => "SSH 服务重启与验证",
        }
    }

    pub fn all() -> &'static [StepKind] {
        &[
            Self::SystemUpdate,
            Self::UserCreation,
            Self::SshRootLogin,
            Self::SshPortChange,
            Self::SshPasswordAuth,
            Self::SshKeySetup,
            Self::Ufw,
            Self::Fail2ban,
            Self::AutoUpdates,
            Self::SecurityScan,
            Self::LogAudit,
            Self::RestartSsh,
        ]
    }

    pub fn check_default_status(&self, report: &AuditReport) -> AuditStatus {
        report.status_for(*self)
    }
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// SSH 密钥操作类型
#[derive(Clone)]
pub enum SshKeyAction {
    /// 生成新密钥对
    GenerateNew,
    /// 粘贴用户提供的公钥
    PasteKey(String),
}

impl fmt::Debug for SshKeyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerateNew => write!(f, "GenerateNew"),
            Self::PasteKey(key) => {
                // 脱敏：取前 20 个字符（按 char 边界，避免字节切片 panic）
                let prefix: String = key.chars().take(20).collect();
                let truncated = if key.len() > prefix.len() {
                    format!("{prefix}... [redacted]")
                } else {
                    key.clone()
                };
                write!(f, "PasteKey(\"{}\")", truncated)
            }
        }
    }
}

/// 用户在执行步骤前的交互参数 —— 领域值对象
#[derive(Clone)]
pub struct ExecuteParams {
    /// 要创建的管理员用户名
    pub new_username: Option<String>,
    /// 是否为该用户锁定密码（强制密钥登录）
    pub lock_password: bool,
    /// 新的 SSH 端口
    pub new_ssh_port: Option<u16>,
    /// SSH 密钥操作
    pub ssh_key_action: Option<SshKeyAction>,
    /// 目标用户名（密钥设置到哪个用户）
    pub ssh_key_username: Option<String>,
}

impl fmt::Debug for ExecuteParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 手动 Debug 以控制 SshKeyAction::PasteKey 的脱敏输出
        f.debug_struct("ExecuteParams")
            .field("new_username", &self.new_username)
            .field("lock_password", &self.lock_password)
            .field("new_ssh_port", &self.new_ssh_port)
            .field("ssh_key_action", &self.ssh_key_action)
            .field("ssh_key_username", &self.ssh_key_username)
            .finish()
    }
}

impl Default for ExecuteParams {
    fn default() -> Self {
        Self {
            new_username: None,
            lock_password: true,
            new_ssh_port: None,
            ssh_key_action: None,
            ssh_key_username: None,
        }
    }
}

/// 步骤执行结果
#[derive(Debug, Clone)]
pub struct StepResult {
    pub kind: StepKind,
    pub changes_made: bool,
    pub message: String,
}

/// 加固步骤的领域服务 trait
pub trait HardeningStep: fmt::Debug {
    fn kind(&self) -> StepKind;
    #[allow(dead_code)]
    fn check_status(&self, report: &AuditReport) -> AuditStatus;
    /// 执行加固步骤，接收用户交互参数
    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError>;
}
