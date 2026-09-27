use std::sync::Arc;

use crate::domain::audit::AuditReport;
use crate::domain::errors::DomainError;
use crate::infrastructure::logger::FileLogger;
use crate::infrastructure::system;

/// 应用服务 —— 环境审计与依赖装配
///
/// 步骤执行（含失败/中断策略、临时软件源、异步）统一由
/// [`crate::application::job::StepRunner`] 负责，避免两套编排逻辑。
pub struct HardeningOrchestrator {
    pub logger: Arc<FileLogger>,
}

impl HardeningOrchestrator {
    pub fn new() -> Self {
        Self {
            logger: Arc::new(FileLogger::new()),
        }
    }

    /// 执行环境审计（只读）
    pub fn audit(&self) -> AuditReport {
        self.logger.log(crate::i18n::tr("log_audit_start"));
        let report = system::run_full_audit();
        self.logger.log(
            &crate::i18n::tr("log_audit_done").replace("{n}", &report.items.len().to_string()),
        );
        report
    }

    /// 检查 root 权限
    pub fn check_root(&self) -> Result<(), DomainError> {
        if system::detect_is_root() {
            Ok(())
        } else {
            Err(DomainError::PermissionDenied)
        }
    }
}

impl Default for HardeningOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}
