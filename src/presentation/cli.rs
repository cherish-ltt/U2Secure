use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::application::orchestrator::HardeningOrchestrator;
use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::steps::{ExecuteParams, SshKeyAction, StepKind};
use crate::infrastructure::system;

/// 运行交互式 CLI
pub fn run_interactive(orchestrator: &HardeningOrchestrator) {
    // ── 权限检查 ──
    if let Err(e) = orchestrator.check_root() {
        eprintln!("{} {}", "[!]".red(), e);
        std::process::exit(1);
    }

    println!(
        "\n{} {}\n",
        "🔐".bright_green(),
        crate::i18n::tr("cli_welcome").replace("{ver}", env!("CARGO_PKG_VERSION")),
    );

    // ── 步骤 0：环境审计 ──
    println!("{} {}...\n", "🔍".bright_blue(), crate::i18n::tr("cli_auditing"));
    let report = orchestrator.audit();

    render_audit_report(&report);

    // ── 步骤选择 ──
    let selected_steps = step_selection(&report);

    if selected_steps.is_empty() {
        println!("\n{} {}", "ℹ️".yellow(), crate::i18n::tr("cli_no_selection"));
        return;
    }

    // ── 为每个需要交互的步骤收集输入 ──
    println!("\n{} {}\n", "📝".bright_blue(), crate::i18n::tr("cli_collecting"));

    // 确认后再收集交互输入
    println!("\n{} {}", "📋".bright_blue(), crate::i18n::tr("cli_will_execute"));
    for s in &selected_steps {
        let status = s.check_default_status(&report);
        println!("  {} {}", status.icon(), s.label());
    }

    if !Confirm::new()
        .with_prompt(crate::i18n::tr("cli_confirm"))
        .default(false)
        .interact()
        .unwrap_or(false)
    {
        println!("\n{} {}", "ℹ️".yellow(), crate::i18n::tr("cli_cancelled"));
        return;
    }

    // ── 收集交互式步骤的参数 ──
    let params = collect_step_params(&selected_steps, &report);

    // ── 执行 ──
    println!("\n{} {}\n", "⚙️".bright_green(), crate::i18n::tr("cli_executing"));
    let results = orchestrator.execute_steps(&report, &selected_steps, &params);

    // ── 总结报告 ──
    render_summary(&results);
}

/// 收集所有需要交互的步骤的用户输入
pub fn collect_step_params(selected: &[StepKind], report: &AuditReport) -> ExecuteParams {
    let mut params = ExecuteParams::default();

    for step in selected {
        match step {
            StepKind::UserCreation => {
                // 列出已有 sudo 用户
                if !report.sudo_users.is_empty() {
                    println!(
                        "{} {}",
                        "ℹ️".yellow(),
                        crate::i18n::tr("cli_existing_sudo")
                            .replace("{users}", &report.sudo_users.join(", "))
                    );
                }

                if !Confirm::new()
                    .with_prompt(crate::i18n::tr("cli_create_user"))
                    .default(true)
                    .interact()
                    .unwrap_or(false)
                {
                    continue;
                }

                let username: String = Input::new()
                    .with_prompt(crate::i18n::tr("cli_username_prompt"))
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.is_empty() {
                            return Err(crate::i18n::tr("cli_username_empty"));
                        }
                        if system::user_exists(input) {
                            return Err(crate::i18n::tr("cli_username_exists"));
                        }
                        if !input
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                        {
                            return Err(crate::i18n::tr("cli_username_invalid"));
                        }
                        Ok(())
                    })
                    .interact()
                    .unwrap_or_else(|_| "admin".into());

                let lock_pw = Confirm::new()
                    .with_prompt(crate::i18n::tr("cli_lock_pw"))
                    .default(true)
                    .interact()
                    .unwrap_or(true);

                params.new_username = Some(username);
                params.lock_password = lock_pw;

                // 创建用户后，自动为该用户设置密钥
                params.ssh_key_username = params.new_username.clone();
                params.ssh_key_action = Some(SshKeyAction::GenerateNew);
            }
            StepKind::SshPortChange => {
                let current_port = report.ssh_port;
                let suggested = system::random_suggested_port();

                println!(
                    "{} {}",
                    "ℹ️".yellow(),
                    crate::i18n::tr("cli_current_port")
                        .replace("{port}", &if current_port == 22 {
                            crate::i18n::tr("cli_default_port").to_string()
                        } else {
                            current_port.to_string()
                        })
                );
                println!(
                    "{} {}",
                    "💡".bright_blue(),
                    crate::i18n::tr("cli_suggest_port")
                        .replace("{port}", &suggested.to_string())
                );

                let port_str: String = Input::new()
                    .with_prompt(crate::i18n::tr("cli_port_prompt"))
                    .default(suggested.to_string())
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input == "0" {
                            return Ok(());
                        }
                        let port: u16 = input.parse().map_err(|_| crate::i18n::tr("cli_port_invalid"))?;
                        if port == 0 {
                            return Err(crate::i18n::tr("cli_port_zero"));
                        }
                        Ok(())
                    })
                    .interact()
                    .unwrap_or_else(|_| "0".into());

                if let Ok(port) = port_str.parse::<u16>()
                    && port > 0
                    && port != current_port
                {
                    params.new_ssh_port = Some(port);
                }
            }
            StepKind::SshKeySetup => {
                // 如果已经在 UserCreation 中设置过密钥，跳过
                if params.ssh_key_action.is_some() {
                    continue;
                }

                // 确定目标用户
                let users = system::detect_sudo_users();
                let target_user = if users.is_empty() {
                    println!(
                        "{} {}",
                        "ℹ️".yellow(),
                        crate::i18n::tr("cli_manual_user")
                    );
                    let manual: String = Input::new()
                        .with_prompt(crate::i18n::tr("cli_user_prompt"))
                        .validate_with(|input: &String| -> Result<(), &str> {
                            if input.is_empty() {
                                return Err(crate::i18n::tr("cli_username_empty"));
                            }
                            if !input
                                .chars()
                                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                            {
                                return Err(crate::i18n::tr("cli_username_invalid"));
                            }
                            Ok(())
                        })
                        .interact()
                        .unwrap_or_else(|_| String::new());
                    if manual.is_empty() {
                        println!("{} {}", "⚠️".yellow(), crate::i18n::tr("cli_no_input"));
                        continue;
                    }
                    manual
                } else if users.len() == 1 {
                    users[0].clone()
                } else {
                    let selection = Select::new()
                        .with_prompt(crate::i18n::tr("cli_select_user"))
                        .items(&users)
                        .default(0)
                        .interact()
                        .unwrap_or(0);
                    users[selection].clone()
                };

                // 检查已有密钥
                if let Some(fingerprint) = system::get_key_fingerprint(&target_user) {
                    println!(
                        "{} {}",
                        "🔑".yellow(),
                        crate::i18n::tr("cli_key_found")
                            .replace("{user}", &target_user)
                            .replace("{fp}", &fingerprint)
                    );
                }

                let action_options = &[crate::i18n::tr("cli_key_generate"), crate::i18n::tr("cli_key_paste"), crate::i18n::tr("cli_key_skip")];
                let selection = Select::new()
                    .with_prompt(crate::i18n::tr("cli_key_action").replace("{user}", &target_user))
                    .items(action_options)
                    .default(0)
                    .interact()
                    .unwrap_or(2);

                match selection {
                    0 => {
                        params.ssh_key_username = Some(target_user);
                        params.ssh_key_action = Some(SshKeyAction::GenerateNew);
                    }
                    1 => {
                        let pub_key: String = Input::new()
                            .with_prompt(crate::i18n::tr("cli_key_prompt"))
                            .interact()
                            .unwrap_or_default();

                        if !pub_key.is_empty() {
                            params.ssh_key_username = Some(target_user);
                            params.ssh_key_action = Some(SshKeyAction::PasteKey(pub_key));
                        }
                    }
                    _ => {}
                }
            }
            _ => { /* 无交互需求的步骤 */ }
        }
    }

    params
}

/// 渲染审计报告
fn render_audit_report(report: &AuditReport) {
    println!("{} {}", "📊".bright_cyan(), crate::i18n::tr("cli_audit_done"));
    println!("{}", "─".repeat(50).dimmed());

    for item in &report.items {
        let icon = item.status.icon();
        let detail_color = match item.status {
            AuditStatus::Safe => "green",
            AuditStatus::Partial => "yellow",
            AuditStatus::Missing => "red",
            AuditStatus::NeedsUpdate => "yellow",
        };
        println!(
            "  {} {}: {}",
            icon,
            item.name.bold(),
            item.detail.color(detail_color)
        );
    }

    println!("{}", "─".repeat(50).dimmed());
    println!();
}

/// 步骤选择 UI
fn step_selection(report: &AuditReport) -> Vec<StepKind> {
    let all_steps = StepKind::all();

    let items: Vec<String> = all_steps
        .iter()
        .map(|step| {
            let status = step.check_default_status(report);
            let status_icon = status.icon();
            format!("{status_icon} {}", step.label())
        })
        .collect();

    println!(
        "{} {}\n",
        "📋".bright_blue(),
        crate::i18n::tr("cli_select_steps"),
    );
    println!(
        "{} {}\n",
        "💡".dimmed(),
        crate::i18n::tr("cli_hint_nav"),
    );

    let selections = MultiSelect::new()
        .items(&items)
        .defaults(
            &all_steps
                .iter()
                .map(|step| !matches!(step.check_default_status(report), AuditStatus::Safe))
                .collect::<Vec<_>>(),
        )
        .interact()
        .unwrap_or_default();

    selections.into_iter().map(|i| all_steps[i]).collect()
}

/// 渲染执行总结
fn render_summary(results: &[crate::domain::steps::StepResult]) {
    println!("\n{}", "=".repeat(50).bright_green());
    println!("{} {}", "📋".bright_green(), crate::i18n::tr("cli_summary_title"));
    println!("{}", "=".repeat(50).bright_green());

    let mut success_count = 0;
    let mut fail_count = 0;

    for result in results {
        if result.changes_made {
            print!("  {} {}: ", "✅".green(), result.kind.label().bold());
            for line in result.message.lines() {
                println!("{}", line.green());
                if line != result.message.lines().next().unwrap_or("") {
                    print!("           ");
                }
            }
            println!();
            success_count += 1;
        } else {
            println!(
                "  {} {}: {}",
                "❌".red(),
                result.kind.label().bold(),
                result.message.red()
            );
            fail_count += 1;
        }
    }

    println!("{}", "─".repeat(50).dimmed());
    println!(
        "  {}",
        crate::i18n::tr("cli_summary_total")
            .replace("{ok}", &success_count.to_string())
            .replace("{fail}", &fail_count.to_string())
            .green()
    );
    println!("{}", "=".repeat(50).bright_green());
    println!("{} {}", "📝".dimmed(), crate::i18n::tr("cli_log_saved"));
    println!();
}
