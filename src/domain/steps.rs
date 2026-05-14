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
    fn execute(&self) -> Result<StepResult, DomainError>;
}
