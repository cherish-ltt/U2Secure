use std::fmt;

use crate::domain::steps::StepKind;

/// 每条审计项的状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    /// ✅ 已安全配置
    Safe,
    /// ⚠️ 部份配置或存在同类工具
    Partial,
    /// ❌ 未配置
    Missing,
    /// 🔄 需要更新
    NeedsUpdate,
}

impl AuditStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Safe => "✅",
            Self::Partial => "⚠️",
            Self::Missing => "❌",
            Self::NeedsUpdate => "🔄",
        }
    }
}

/// 单条审计项目
#[derive(Debug, Clone)]
pub struct AuditItem {
    pub name: &'static str,
    pub status: AuditStatus,
    pub detail: String,
}

impl AuditItem {
    pub fn new(name: &'static str, status: AuditStatus, detail: String) -> Self {
        Self {
            name,
            status,
            detail,
        }
    }

    pub fn safe(name: &'static str, detail: String) -> Self {
        Self::new(name, AuditStatus::Safe, detail)
    }

    pub fn missing(name: &'static str, detail: String) -> Self {
        Self::new(name, AuditStatus::Missing, detail)
    }

    #[allow(dead_code)]
    pub fn partial(name: &'static str, detail: String) -> Self {
        Self::new(name, AuditStatus::Partial, detail)
    }

    pub fn needs_update(name: &'static str, detail: String) -> Self {
        Self::new(name, AuditStatus::NeedsUpdate, detail)
    }
}

/// 支持的包管理器
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Yum,
    Dnf,
    Unknown,
}

impl PackageManager {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Yum => "yum",
            Self::Dnf => "dnf",
            Self::Unknown => "unknown",
        }
    }

    pub fn update_cmd(&self) -> &'static [&'static str] {
        match self {
            Self::Apt => &["apt", "update"],
            Self::Yum => &["yum", "update", "-y"],
            Self::Dnf => &["dnf", "update", "-y"],
            Self::Unknown => &[],
        }
    }

    pub fn upgrade_cmd(&self) -> &'static [&'static str] {
        match self {
            Self::Apt => &["apt", "upgrade", "-y"],
            Self::Yum => &["yum", "upgrade", "-y"],
            Self::Dnf => &["dnf", "upgrade", "-y"],
            Self::Unknown => &[],
        }
    }
}

impl fmt::Display for PackageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// 系统审计报告 —— 领域实体
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// 原始审计项目列表（用于渲染）
    pub items: Vec<AuditItem>,
    /// 是否以 root 运行
    #[allow(dead_code)]
    pub is_root: bool,
    /// 包管理器类型
    #[allow(dead_code)]
    pub package_manager: PackageManager,
    /// SSH 端口（默认 22）
    pub ssh_port: u16,
    /// 是否禁止密码登录
    pub password_auth_disabled: bool,
    /// 是否禁止 root 登录
    pub root_login_disabled: bool,
    /// 现有 sudo 用户列表
    pub sudo_users: Vec<String>,
    /// 是否已安装 fail2ban
    pub fail2ban_installed: bool,
    /// UFW 是否已启用
    pub ufw_enabled: bool,
    /// 自动安全更新是否已启用
    pub auto_updates_enabled: bool,
    /// 系统包列表是否已是最新
    pub system_up_to_date: bool,
    /// 是否已安装 lynis（步骤 10）
    pub lynis_installed: bool,
    /// 是否已安装 logwatch（步骤 11）
    pub logwatch_installed: bool,
    /// 是否已安装 aide（步骤 11）
    pub aide_installed: bool,
    /// sshd_config 是否比运行中的服务更新（步骤 12 是否需要重启）
    pub ssh_restart_needed: bool,
}

impl AuditReport {
    /// 根据步骤类型返回当前审计状态（全项目唯一真值来源）
    pub fn status_for(&self, step: StepKind) -> AuditStatus {
        match step {
            StepKind::SystemUpdate => {
                if self.system_up_to_date {
                    AuditStatus::Safe
                } else {
                    AuditStatus::NeedsUpdate
                }
            },
            StepKind::UserCreation => {
                if self.sudo_users.is_empty() {
                    AuditStatus::Missing
                } else {
                    AuditStatus::Safe
                }
            },
            StepKind::SshRootLogin => {
                if self.root_login_disabled {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::SshPortChange => {
                if self.ssh_port != 22 {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::SshPasswordAuth => {
                if self.password_auth_disabled {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::SshKeySetup => {
                // 粗略检查：有 sudo 用户即认为可能已有密钥
                if self.sudo_users.is_empty() {
                    AuditStatus::Missing
                } else {
                    AuditStatus::Partial
                }
            },
            StepKind::Ufw => {
                if self.ufw_enabled {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::Fail2ban => {
                if self.fail2ban_installed {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::AutoUpdates => {
                if self.auto_updates_enabled {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::SecurityScan => {
                if self.lynis_installed {
                    AuditStatus::Safe
                } else {
                    AuditStatus::Missing
                }
            },
            StepKind::LogAudit => match (self.logwatch_installed, self.aide_installed) {
                (true, true) => AuditStatus::Safe,
                (false, false) => AuditStatus::Missing,
                _ => AuditStatus::Partial,
            },
            StepKind::RestartSsh => {
                if self.ssh_restart_needed {
                    AuditStatus::NeedsUpdate
                } else {
                    AuditStatus::Safe
                }
            },
        }
    }
}
