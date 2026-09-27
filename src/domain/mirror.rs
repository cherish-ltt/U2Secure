//! 临时软件源（镜像仓库）选择 —— 领域值对象
//!
//! 仅在本次运行期间生效：执行前切换到所选镜像加速下载，运行结束后恢复原始源。
//! 具体改写与延迟探测属于基础设施细节，见 `infrastructure::package_mirror`。

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageMirror {
    /// 使用系统原有软件源（不做任何改动）
    Original,
    /// 清华大学 TUNA 镜像
    Tsinghua,
    /// 中国科学技术大学镜像
    Ustc,
    /// 用户自定义源（只取主机名，路径沿用系统原有源）
    Custom(String),
}

/// 自定义源解析失败原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorParseError {
    /// 输入为空
    Empty,
    /// 不是合法的主机名 / IP
    Invalid,
}

impl MirrorParseError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Empty => crate::i18n::tr("mirror_custom_empty"),
            Self::Invalid => crate::i18n::tr("mirror_custom_invalid"),
        }
    }
}

impl PackageMirror {
    /// 预设选项（自定义源由界面单独入口输入）
    pub fn all() -> &'static [PackageMirror] {
        &[Self::Original, Self::Tsinghua, Self::Ustc]
    }

    pub fn label(&self) -> String {
        match self {
            Self::Original => crate::i18n::tr("mirror_original").to_string(),
            Self::Tsinghua => crate::i18n::tr("mirror_tsinghua").to_string(),
            Self::Ustc => crate::i18n::tr("mirror_ustc").to_string(),
            Self::Custom(host) => crate::i18n::tr("mirror_custom_label").replace("{host}", host),
        }
    }

    /// 用于延迟探测与主机改写的主机名（Original 无需探测）
    pub fn probe_host(&self) -> Option<String> {
        match self {
            Self::Original => None,
            Self::Tsinghua => Some("mirrors.tuna.tsinghua.edu.cn".into()),
            Self::Ustc => Some("mirrors.ustc.edu.cn".into()),
            Self::Custom(host) => Some(host.clone()),
        }
    }

    pub fn is_original(&self) -> bool {
        matches!(self, Self::Original)
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }

    /// 从用户输入解析自定义源
    ///
    /// 接受 `host`、`host:port`、`https://host/path` 等写法，只保留主机部分；
    /// 路径沿用系统原有源（镜像站通常保持与上游一致的路径结构）。
    pub fn custom(input: &str) -> Result<Self, MirrorParseError> {
        Ok(Self::Custom(parse_host(input)?))
    }
}

/// 纯函数：从任意输入中提取主机名（含可选端口）
pub fn parse_host(input: &str) -> Result<String, MirrorParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(MirrorParseError::Empty);
    }

    // 去掉 scheme
    let without_scheme = match trimmed.split_once("://") {
        Some((_, rest)) => rest,
        None => trimmed,
    };
    // 去掉路径 / 查询 / 锚点
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // 去掉 userinfo
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    }
    .trim();

    if host.is_empty() {
        return Err(MirrorParseError::Invalid);
    }

    let charset_ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '[' | ']'));
    let has_alnum = host.chars().any(|c| c.is_ascii_alphanumeric());
    if !charset_ok || !has_alnum {
        return Err(MirrorParseError::Invalid);
    }

    Ok(host.to_string())
}

impl fmt::Display for PackageMirror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}
