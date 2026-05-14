use std::collections::HashSet;

use crate::application::steps::AllSteps;
use crate::domain::audit::AuditReport;
use crate::domain::errors::DomainError;
use crate::domain::steps::{ExecuteParams, StepKind, StepResult};
use crate::infrastructure::logger::FileLogger;
use crate::infrastructure::system;

/// 应用服务 —— 编排整个加固流程
pub struct HardeningOrchestrator {
    pub logger: FileLogger,
}

impl HardeningOrchestrator {
    pub fn new() -> Self {
        Self {
            logger: FileLogger::new(),
        }
    }

    /// 执行环境审计（只读）
    pub fn audit(&self) -> AuditReport {
        self.logger.log("[审计] 开始环境审计...");
        let report = system::run_full_audit();
        self.logger.log(&format!(
            "[审计] 完成，共 {} 项检测",
            report.items.len()
        ));
        report
    }

    /// 执行选中的步骤，接收用户交互参数
    pub fn execute_steps(
        &self,
        _report: &AuditReport,
        selected: &[StepKind],
        params: &ExecuteParams,
    ) -> Vec<StepResult> {
        let selected_set: HashSet<StepKind> = selected.iter().copied().collect();
        let all_steps = AllSteps::new();

        let mut results = vec![];
        for step in all_steps.steps() {
            if !selected_set.contains(&step.kind()) {
                continue;
            }

            let kind = step.kind();
            self.logger.log_operation("开始执行", kind.label());

            match step.execute(params) {
                Ok(result) => {
                    let msg = result.message.clone();
                    self.logger
                        .log_operation("完成", &format!("{}: {}", kind.label(), msg));
                    results.push(result);
                }
                Err(e) => {
                    let err_msg = format!("{}: {e}", kind.label());
                    self.logger.log_operation("失败", &err_msg);
                    results.push(StepResult {
                        kind,
                        changes_made: false,
                        message: format!("失败: {e}"),
                    });
                }
            }
        }
        results
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
