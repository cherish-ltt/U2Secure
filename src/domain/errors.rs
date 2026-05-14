use std::fmt;

/// 领域层错误 —— 纯净，零外部依赖
#[derive(Debug)]
pub enum DomainError {
    /// 非 root 用户执行
    PermissionDenied,
    /// 底层系统命令失败
    SystemCommandFailed(String),
    /// 解析配置文件失败
    ParseError(String),
    /// 前置条件不满足（如无 sudo 用户时禁止 root 登录）
    PreconditionFailed(String),
    /// 用户取消操作
    #[allow(dead_code)]
    UserAborted,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "需要 root 权限运行"),
            Self::SystemCommandFailed(msg) => write!(f, "系统命令执行失败: {msg}"),
            Self::ParseError(msg) => write!(f, "配置解析错误: {msg}"),
            Self::PreconditionFailed(msg) => write!(f, "前置条件不满足: {msg}"),
            Self::UserAborted => write!(f, "用户取消操作"),
        }
    }
}

impl std::error::Error for DomainError {}
