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
            Self::PermissionDenied => write!(f, "{}", crate::i18n::tr("err_permission_denied")),
            Self::SystemCommandFailed(msg) => {
                write!(f, "{}", crate::i18n::tr("err_cmd_failed").replace("{msg}", msg))
            }
            Self::ParseError(msg) => {
                write!(f, "{}", crate::i18n::tr("err_parse_error").replace("{msg}", msg))
            }
            Self::PreconditionFailed(msg) => write!(
                f,
                "{}",
                crate::i18n::tr("err_precondition_failed").replace("{msg}", msg)
            ),
            Self::UserAborted => write!(f, "{}", crate::i18n::tr("err_user_aborted")),
        }
    }
}

impl std::error::Error for DomainError {}
