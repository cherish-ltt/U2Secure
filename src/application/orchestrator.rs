use std::collections::HashSet;

use crate::application::steps::AllSteps;
use crate::domain::audit::AuditReport;
use crate::domain::errors::DomainError;
use crate::domain::steps::{ExecuteParams, StepKind, StepResult};
use crate::infrastructure::logger::FileLogger;
use crate::infrastructure::rollback;
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
        self.logger
            .log(&format!("[审计] 完成，共 {} 项检测", report.items.len()));
        report
    }

    /// 执行选中的步骤，接收用户交互参数。
    /// 每步执行前检查 Ctrl+C 中断标记，失败时自动回退全部已注册的修改。
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

            // 检查是否被 Ctrl+C 中断
            if rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst) {
                self.logger.log("[中断] 检测到用户中断，停止执行并回退");
                break;
            }

            let kind = step.kind();
            self.logger.log_operation("开始执行", kind.label());

            match step.execute(params) {
                Ok(result) => {
                    self.logger
                        .log_operation("完成", &format!("{}: {}", kind.label(), result.message));
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

                    // 步骤失败 → 自动回退已完成步骤的修改
                    self.logger.log("[回退] 步骤失败，自动回退所有已注册的修改");
                    rollback::undo_all();
                    break;
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
