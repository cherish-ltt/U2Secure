// U2Secure 是 Linux 专用加固工具（依赖 apt/dnf、ufw、sshd、systemd、/var/log 等），
// 只发布 Linux 二进制。在 Windows 上直接编译失败，避免产出"能编译但不能用"的产物；
// macOS 仍可编译，便于在开发机上跑单元测试（见 AGENTS.md 10.4）。
#[cfg(windows)]
compile_error!("U2Secure 仅支持 Linux 目标（请使用 x86_64/aarch64-unknown-linux-gnu）");

use u2secure::application::orchestrator::HardeningOrchestrator;
use u2secure::i18n;
use u2secure::i18n::Lang;
use u2secure::infrastructure::rollback;
use u2secure::presentation::{cli, tui};

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
                },
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
    if let Err(e) = rollback::init_signal_handler() {
        eprintln!("[!] {e}");
        std::process::exit(1);
    }

    let orchestrator = HardeningOrchestrator::new();

    match ModeChoice::from_args() {
        ModeChoice::Cli => cli::run_interactive(&orchestrator),
        ModeChoice::Tui => {
            if let Err(e) = tui::run_tui(&orchestrator) {
                eprintln!("\n TUI {e}");
                std::process::exit(1);
            }
        },
    }
}
