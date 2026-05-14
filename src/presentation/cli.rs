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
        eprintln!("{} 错误: {e}", "[!]".red());
        std::process::exit(1);
    }

    println!(
        "\n{} U2Secure - Linux 服务器安全加固工具 v0.1.0\n",
        "🔐".bright_green()
    );

    // ── 步骤 0：环境审计 ──
    println!("{} 正在执行环境审计...\n", "🔍".bright_blue());
    let report = orchestrator.audit();

    render_audit_report(&report);

    // ── 步骤选择 ──
    let selected_steps = step_selection(&report);

    if selected_steps.is_empty() {
        println!("\n{} 未选择任何步骤，退出。", "ℹ️".yellow());
        return;
    }

    // ── 为每个需要交互的步骤收集输入 ──
    println!("\n{} 开始收集配置参数...\n", "📝".bright_blue());

    // 确认后再收集交互输入
    println!("\n{} 以下步骤将被执行：", "📋".bright_blue());
    for s in &selected_steps {
        let status = s.check_default_status(&report);
        println!("  {} {}", status.icon(), s.label());
    }

    if !Confirm::new()
        .with_prompt("是否继续？")
        .default(false)
        .interact()
        .unwrap_or(false)
    {
        println!("\n{} 用户取消。", "ℹ️".yellow());
        return;
    }

    // ── 收集交互式步骤的参数 ──
    let params = collect_step_params(&selected_steps, &report);

    // ── 执行 ──
    println!("\n{} 开始执行加固步骤...\n", "⚙️".bright_green());
    let results = orchestrator.execute_steps(&report, &selected_steps, &params);

    // ── 总结报告 ──
    render_summary(&results);
}

/// 收集所有需要交互的步骤的用户输入
fn collect_step_params(selected: &[StepKind], report: &AuditReport) -> ExecuteParams {
    let mut params = ExecuteParams::default();

    for step in selected {
        match step {
            StepKind::UserCreation => {
                // 列出已有 sudo 用户
                if !report.sudo_users.is_empty() {
                    println!(
                        "{} 已有 sudo 用户: {}",
                        "ℹ️".yellow(),
                        report.sudo_users.join(", ")
                    );
                }

                if !Confirm::new()
                    .with_prompt("是否创建新的管理用户？")
                    .default(true)
                    .interact()
                    .unwrap_or(false)
                {
                    continue;
                }

                let username: String = Input::new()
                    .with_prompt("请输入新用户名")
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.is_empty() {
                            return Err("用户名不能为空");
                        }
                        if system::user_exists(input) {
                            return Err("用户已存在");
                        }
                        if !input
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                        {
                            return Err("用户名只能包含字母、数字、- 和 _");
                        }
                        Ok(())
                    })
                    .interact()
                    .unwrap_or_else(|_| "admin".into());

                let lock_pw = Confirm::new()
                    .with_prompt("锁定密码（强制密钥登录）？")
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
                    "{} 当前 SSH 端口: {}",
                    "ℹ️".yellow(),
                    if current_port == 22 {
                        "22（默认）".red().to_string()
                    } else {
                        current_port.to_string().green().to_string()
                    }
                );
                println!("{} 建议端口: {}", "💡".bright_blue(), suggested);

                let port_str: String = Input::new()
                    .with_prompt("请输入新 SSH 端口（输入 0 跳过）")
                    .default(suggested.to_string())
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input == "0" {
                            return Ok(());
                        }
                        let port: u16 = input.parse().map_err(|_| "请输入有效数字")?;
                        if port == 0 {
                            return Err("端口 0 无效");
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
                if users.is_empty() {
                    println!("{} 没有可用的 sudo 用户，跳过密钥设置", "⚠️".yellow());
                    continue;
                }

                let target_user = if users.len() == 1 {
                    users[0].clone()
                } else {
                    let selection = Select::new()
                        .with_prompt("选择要设置密钥的用户")
                        .items(&users)
                        .default(0)
                        .interact()
                        .unwrap_or(0);
                    users[selection].clone()
                };

                // 检查已有密钥
                if let Some(fingerprint) = system::get_key_fingerprint(&target_user) {
                    println!(
                        "{} 用户 {target_user} 已有公钥: {}",
                        "🔑".yellow(),
                        fingerprint.dimmed()
                    );
                }

                let action_options = &["生成新密钥对", "粘贴已有公钥", "跳过"];
                let selection = Select::new()
                    .with_prompt(format!("为 {target_user} 设置 SSH 密钥"))
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
                            .with_prompt("请粘贴公钥内容（ssh-ed25519 AAA...）")
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
    println!("{} 环境审计完成：", "📊".bright_cyan());
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
        "{} 请选择要执行的加固步骤（已安全配置的默认不勾选）：\n",
        "📋".bright_blue()
    );
    println!(
        "{} 提示：方向键上下移动，空格选择，回车确认\n",
        "💡".dimmed()
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
    println!("{} 本次加固总结报告", "📋".bright_green());
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
        "  总计: {} 成功, {} 失败/跳过",
        success_count.to_string().green(),
        fail_count.to_string().red()
    );
    println!("{}", "=".repeat(50).bright_green());
    println!("{} 日志已保存至 /var/log/secure-init.log", "📝".dimmed());
    println!();
}
