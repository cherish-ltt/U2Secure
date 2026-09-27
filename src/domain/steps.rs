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
            Self::SystemUpdate => crate::i18n::tr("step_system_update"),
            Self::UserCreation => crate::i18n::tr("step_user_creation"),
            Self::SshRootLogin => crate::i18n::tr("step_ssh_root_login"),
            Self::SshPortChange => crate::i18n::tr("step_ssh_port_change"),
            Self::SshPasswordAuth => crate::i18n::tr("step_ssh_password_auth"),
            Self::SshKeySetup => crate::i18n::tr("step_ssh_key_setup"),
            Self::Ufw => crate::i18n::tr("step_ufw"),
            Self::Fail2ban => crate::i18n::tr("step_fail2ban"),
            Self::AutoUpdates => crate::i18n::tr("step_auto_updates"),
            Self::SecurityScan => crate::i18n::tr("step_security_scan"),
            Self::LogAudit => crate::i18n::tr("step_log_audit"),
            Self::RestartSsh => crate::i18n::tr("step_restart_ssh"),
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

    /// 稳定短名（用于日志/报告文件名）
    pub fn slug(&self) -> &'static str {
        match self {
            Self::SystemUpdate => "system-update",
            Self::UserCreation => "user-creation",
            Self::SshRootLogin => "ssh-root-login",
            Self::SshPortChange => "ssh-port-change",
            Self::SshPasswordAuth => "ssh-password-auth",
            Self::SshKeySetup => "ssh-key-setup",
            Self::Ufw => "ufw",
            Self::Fail2ban => "fail2ban",
            Self::AutoUpdates => "auto-updates",
            Self::SecurityScan => "security-scan",
            Self::LogAudit => "log-audit",
            Self::RestartSsh => "restart-ssh",
        }
    }

    /// 默认不勾选的"可选步骤"：需要安装额外软件、耗时较长，
    /// 必须由用户主动勾选才会执行（步骤 9/10/11）。
    pub fn is_opt_in(&self) -> bool {
        matches!(
            self,
            Self::AutoUpdates | Self::SecurityScan | Self::LogAudit
        )
    }

    /// 非关键步骤：失败时不触发全局回滚，也不打断后续步骤。
    /// 避免"装不上 lynis 就把已加固的 SSH 配置全部退回"。
    pub fn is_optional(&self) -> bool {
        self.is_opt_in()
    }

    /// 该步骤是否会改动软件包/软件源（决定是否需要询问临时镜像源）
    pub fn touches_package_manager(&self) -> bool {
        matches!(
            self,
            Self::SystemUpdate
                | Self::Fail2ban
                | Self::AutoUpdates
                | Self::SecurityScan
                | Self::LogAudit
        )
    }

    pub fn check_default_status(&self, report: &AuditReport) -> AuditStatus {
        report.status_for(*self)
    }

    /// 默认勾选策略：可选步骤一律不勾选，其余按审计状态（已安全则跳过）
    pub fn default_checked(&self, report: &AuditReport) -> bool {
        if self.is_opt_in() {
            return false;
        }
        !matches!(self.check_default_status(report), AuditStatus::Safe)
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
                let truncated = if key.chars().count() > prefix.chars().count() {
                    format!("{prefix}... [redacted]")
                } else {
                    key.clone()
                };
                write!(f, "PasteKey(\"{}\")", truncated)
            },
        }
    }
}

/// 临时软件源覆盖参数（由基础设施层生成，步骤原样透传给包管理器）
#[derive(Clone, Debug, Default)]
pub struct MirrorOverride {
    /// apt: 临时 sources.list 路径
    pub apt_sourcelist: Option<String>,
    /// apt: 临时 sources.list.d 目录（deb822 格式）
    pub apt_sourceparts: Option<String>,
    /// yum/dnf: 临时 reposdir
    pub yum_reposdir: Option<String>,
}

impl MirrorOverride {
    pub fn is_empty(&self) -> bool {
        self.apt_sourcelist.is_none() && self.yum_reposdir.is_none()
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
    /// 本次运行的报告目录（步骤把扫描产物写到这里）
    pub report_dir: Option<String>,
    /// 当前步骤的实时输出文件（长耗时命令写入，UI 尾随显示）
    pub live_log: Option<String>,
    /// 本次运行使用的临时软件源
    pub mirror: MirrorOverride,
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
            .field("report_dir", &self.report_dir)
            .field("live_log", &self.live_log)
            .field("mirror", &self.mirror)
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
            report_dir: None,
            live_log: None,
            mirror: MirrorOverride::default(),
        }
    }
}

/// 步骤执行结局 —— 三态显式区分，避免用 bool 同时表达"跳过"和"失败"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// 实际修改了系统
    Changed,
    /// 无需修改（已满足条件 / 当前环境不支持），不是失败
    Skipped,
    /// 执行失败（但步骤本身正常返回，不含回滚语义）
    Failed,
}

impl StepOutcome {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Changed => "✅",
            Self::Skipped => "⏭",
            Self::Failed => "❌",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Changed => crate::i18n::tr("outcome_changed"),
            Self::Skipped => crate::i18n::tr("outcome_skipped"),
            Self::Failed => crate::i18n::tr("outcome_failed"),
        }
    }
}

/// 步骤执行结果
#[derive(Debug, Clone)]
pub struct StepResult {
    pub kind: StepKind,
    pub outcome: StepOutcome,
    pub message: String,
    /// 本次执行产生的报告文件（供用户查看完整结果）
    pub artifacts: Vec<String>,
}

impl StepResult {
    pub fn new(kind: StepKind, outcome: StepOutcome, message: impl Into<String>) -> Self {
        Self {
            kind,
            outcome,
            message: message.into(),
            artifacts: vec![],
        }
    }

    pub fn changed(kind: StepKind, message: impl Into<String>) -> Self {
        Self::new(kind, StepOutcome::Changed, message)
    }

    pub fn skipped(kind: StepKind, message: impl Into<String>) -> Self {
        Self::new(kind, StepOutcome::Skipped, message)
    }

    pub fn failed(kind: StepKind, message: impl Into<String>) -> Self {
        Self::new(kind, StepOutcome::Failed, message)
    }

    pub fn with_artifacts(mut self, artifacts: Vec<String>) -> Self {
        self.artifacts = artifacts;
        self
    }

    pub fn is_changed(&self) -> bool {
        self.outcome == StepOutcome::Changed
    }

    pub fn is_failed(&self) -> bool {
        self.outcome == StepOutcome::Failed
    }
}

/// 加固步骤的领域服务 trait
pub trait HardeningStep: fmt::Debug + Send {
    fn kind(&self) -> StepKind;
    /// 执行加固步骤，接收用户交互参数
    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError>;
}
