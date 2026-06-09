mod application;
mod domain;
mod infrastructure;
mod presentation;

use u2secure::i18n;
use u2secure::i18n::Lang;

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
                    eprintln!("{}", i18n::translate("unknown_arg").replace("{arg}", other));
                    std::process::exit(1);
                }
            }
        }
        Self::interactive()
    }

    fn interactive() -> Self {
        // 语言选择
        let lang_options: Vec<&str> = Lang::all().iter().map(|l| l.label()).collect();
        let lang_sel = dialoguer::Select::new()
            .with_prompt(i18n::translate("select_language"))
            .items(&lang_options)
            .default(0)
            .interact()
            .unwrap_or(0);
        i18n::init(Lang::all()[lang_sel]);

        // 模式选择
        let options = &[i18n::translate("mode_tui"), i18n::translate("mode_cli")];
        let selection = dialoguer::Select::new()
            .with_prompt(i18n::translate("select_mode"))
            .items(options)
            .default(0)
            .interact()
            .unwrap_or(0);
        match selection {
            0 => Self::Tui,
            _ => Self::Cli,
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
                eprintln!("\n TUI {e}");
            }
        }
    }
}
