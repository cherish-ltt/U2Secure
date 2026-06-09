mod application;
mod domain;
mod infrastructure;
mod presentation;

use application::orchestrator::HardeningOrchestrator;
use infrastructure::rollback;
use presentation::{cli, tui};

enum ModeChoice {
    Cli,
    Tui,
}

impl ModeChoice {
    fn from_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        if args.len() > 1 {
            match args[1].as_str() {
                "-c" | "--cli" => return Self::Cli,
                "-t" | "--tui" => return Self::Tui,
                other => {
                    eprintln!("未知参数: {other}，使用 -c (CLI) 或 -t (TUI)");
                    std::process::exit(1);
                }
            }
        }
        Self::interactive()
    }

    fn interactive() -> Self {
        let options = &["CLI 模式（传统交互式）", "TUI 模式（终端图形界面）"];
        let selection = dialoguer::Select::new()
            .with_prompt("请选择启动模式")
            .items(options)
            .default(1)
            .interact()
            .unwrap_or(1);
        match selection {
            0 => Self::Cli,
            _ => Self::Tui,
        }
    }
}

fn main() {
    // 初始化 Ctrl+C 信号处理器（确保在任何修改前就位）
    rollback::init_signal_handler();

    let orchestrator = HardeningOrchestrator::new();

    match ModeChoice::from_args() {
        ModeChoice::Cli => cli::run_interactive(&orchestrator),
        ModeChoice::Tui => {
            if let Err(e) = tui::run_tui(&orchestrator) {
                eprintln!("\n TUI 错误: {e}");
            }
        }
    }
}
