//! U2Secure - Linux 服务器安全加固工具
//!
//! 遵循 DDD + 洋葱架构：
//! - domain: 领域层（纯净，零外部依赖）
//! - application: 应用层（编排流程）
//! - infrastructure: 基础设施（系统命令、日志）
//! - presentation: 表示层（dialoguer 交互式 CLI）

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;
