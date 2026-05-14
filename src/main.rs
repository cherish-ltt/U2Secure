mod application;
mod domain;
mod infrastructure;
mod presentation;

use application::orchestrator::HardeningOrchestrator;
use infrastructure::rollback;
use presentation::cli;

fn main() {
    // 初始化 Ctrl+C 信号处理器（确保在任何修改前就位）
    rollback::init_signal_handler();

    let orchestrator = HardeningOrchestrator::new();
    cli::run_interactive(&orchestrator);
}
