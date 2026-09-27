//! 临时软件源（镜像仓库）选择 —— 领域值对象
//!
//! 仅在本次运行期间生效：执行前切换到所选镜像加速下载，运行结束后恢复原始源。
//! 具体改写与延迟探测属于基础设施细节，见 `infrastructure::package_mirror`。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageMirror {
    /// 使用系统原有软件源（不做任何改动）
    Original,
    /// 清华大学 TUNA 镜像
    Tsinghua,
    /// 中国科学技术大学镜像
    Ustc,
}

impl PackageMirror {
    pub fn all() -> &'static [PackageMirror] {
        &[Self::Original, Self::Tsinghua, Self::Ustc]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Original => crate::i18n::tr("mirror_original"),
            Self::Tsinghua => crate::i18n::tr("mirror_tsinghua"),
            Self::Ustc => crate::i18n::tr("mirror_ustc"),
        }
    }

    /// 用于延迟探测的主机名（Original 无需探测）
    pub fn probe_host(&self) -> Option<&'static str> {
        match self {
            Self::Original => None,
            Self::Tsinghua => Some("mirrors.tuna.tsinghua.edu.cn"),
            Self::Ustc => Some("mirrors.ustc.edu.cn"),
        }
    }

    pub fn is_original(&self) -> bool {
        matches!(self, Self::Original)
    }
}

impl fmt::Display for PackageMirror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}
