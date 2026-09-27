use colored::*;
use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::application::job::{JobEvent, StepRunner};
use crate::application::orchestrator::HardeningOrchestrator;
use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::mirror::PackageMirror;
use crate::domain::steps::{ExecuteParams, SshKeyAction, StepKind, StepOutcome, StepResult};
use crate::infrastructure::{artifacts, package_mirror, system};

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
    println!(
        "{} {}...\n",
        "🔍".bright_blue(),
        crate::i18n::tr("cli_auditing")
    );
    let report = orchestrator.audit();

    render_audit_report(&report);

    // ── 步骤选择 ──
    let selected_steps = step_selection(&report);

    if selected_steps.is_empty() {
        println!(
            "\n{} {}",
            "ℹ️".yellow(),
            crate::i18n::tr("cli_no_selection")
        );
        return;
    }

    // ── 确认执行清单 ──
    println!(
        "\n{} {}",
        "📋".bright_blue(),
        crate::i18n::tr("cli_will_execute")
    );
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
    println!(
        "\n{} {}\n",
        "📝".bright_blue(),
        crate::i18n::tr("cli_collecting")
    );
    let params = collect_step_params(&selected_steps, &report);

    // ── 临时软件源（涉及安装软件包时才询问）──
    let mut mirror = select_mirror(&selected_steps);

    // ── 执行（实时输出，长耗时步骤不会"假卡住"）──
    println!(
        "\n{} {}\n",
        "⚙️".bright_green(),
        crate::i18n::tr("cli_executing")
    );

    let log_path = orchestrator.logger().path().to_string();
    loop {
        let runner = StepRunner::new(orchestrator.logger()).with_mirror(mirror.clone());
        let mut mirror_failure = None;
        let mut on_event = |event: JobEvent| {
            if let JobEvent::MirrorFailed { reason } = &event {
                mirror_failure = Some(reason.clone());
            }
            print_event(&event);
        };
        let results = runner.run(&selected_steps, &params, &mut on_event);

        let Some(reason) = mirror_failure else {
            // ── 总结报告 ──
            render_summary(&results, &log_path);
            return;
        };

        // 软件源不可用：由用户决定重试 / 更换源 / 取消执行（不自动回退）
        println!("\n{} {}", "❌".red(), reason.red());
        let options = crate::presentation::mirror_failure_options();
        let choice = Select::new()
            .with_prompt(crate::i18n::tr("cli_mirror_failed_prompt"))
            .items(options)
            .default(0)
            .interact()
            .unwrap_or(2);
        match choice {
            0 => continue,
            1 => {
                mirror = select_mirror(&selected_steps);
                continue;
            },
            _ => {
                println!(
                    "\n{} {}",
                    "ℹ️".yellow(),
                    crate::i18n::tr("mirror_abort_hint")
                );
                return;
            },
        }
    }
}

/// 实时事件输出
fn print_event(event: &JobEvent) {
    match event {
        JobEvent::StepStarted {
            kind,
            index,
            total,
            live_log,
        } => {
            println!(
                "\n{} [{}] {}",
                format!("{}/{}", index + 1, total).dimmed(),
                "▶".bright_cyan(),
                kind.label().bold()
            );
            println!(
                "    {}",
                crate::i18n::tr("cli_live_log")
                    .replace("{log}", live_log)
                    .dimmed()
            );
        },
        JobEvent::StepFinished(result) => {
            let first = result.message.lines().next().unwrap_or("");
            match result.outcome {
                StepOutcome::Changed => println!("    {} {}", "✅".green(), first.green()),
                StepOutcome::Skipped => println!("    {} {}", "⏭".yellow(), first.yellow()),
                StepOutcome::Failed => println!("    {} {}", "❌".red(), first.red()),
            }
        },
        JobEvent::Log(message) => println!("    {} {}", "ℹ️".dimmed(), message.dimmed()),
        JobEvent::MirrorFailed { reason } => println!("    {} {}", "❌".red(), reason.red()),
        JobEvent::Interrupted => println!(
            "\n{} {}",
            "⚠️".yellow(),
            crate::i18n::tr("cli_interrupted").yellow()
        ),
        JobEvent::AllFinished => {},
    }
}

/// 询问临时软件源（仅在本次运行会安装/更新软件包时）
fn select_mirror(selected: &[StepKind]) -> PackageMirror {
    if !selected.iter().any(|s| s.touches_package_manager()) {
        return PackageMirror::Original;
    }

    println!(
        "\n{} {}",
        "🔎".bright_blue(),
        crate::i18n::tr("cli_mirror_probing")
    );

    let mirrors = PackageMirror::all();
    let mut items: Vec<String> = mirrors.iter().map(describe_mirror).collect();
    items.push(crate::i18n::tr("mirror_custom_entry").to_string());

    let selection = Select::new()
        .with_prompt(crate::i18n::tr("cli_mirror_prompt"))
        .items(&items)
        .default(0)
        .interact()
        .unwrap_or(0);

    if let Some(mirror) = mirrors.get(selection) {
        return mirror.clone();
    }

    // 自定义输入源（最多尝试 3 次，留空则回退原始源）
    for _ in 0..3 {
        let input: String = Input::new()
            .with_prompt(crate::i18n::tr("cli_mirror_custom_prompt"))
            .allow_empty(true)
            .interact()
            .unwrap_or_default();
        if input.trim().is_empty() {
            break;
        }
        match PackageMirror::custom(&input) {
            Ok(mirror) => return mirror,
            Err(e) => println!("{} {}", "⚠️".yellow(), e.message()),
        }
    }

    println!(
        "{} {}",
        "ℹ️".yellow(),
        crate::i18n::tr("tui_mirror_use_original")
    );
    PackageMirror::Original
}

fn describe_mirror(mirror: &PackageMirror) -> String {
    match mirror.probe_host() {
        None => crate::i18n::tr("mirror_original").to_string(),
        Some(_) => match package_mirror::probe_latency(mirror) {
            Some(latency) => format!(
                "{} ({}{}ms)",
                mirror.label(),
                crate::i18n::tr("mirror_latency_prefix"),
                latency.as_millis()
            ),
            None => format!(
                "{} ({})",
                mirror.label(),
                crate::i18n::tr("mirror_unreachable")
            ),
        },
    }
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
            },
            StepKind::SshPortChange => {
                let current_port = report.ssh_port;
                let suggested = system::random_suggested_port();

                println!(
                    "{} {}",
                    "ℹ️".yellow(),
                    crate::i18n::tr("cli_current_port").replace(
                        "{port}",
                        &if current_port == 22 {
                            crate::i18n::tr("cli_default_port").to_string()
                        } else {
                            current_port.to_string()
                        }
                    )
                );
                println!(
                    "{} {}",
                    "💡".bright_blue(),
                    crate::i18n::tr("cli_suggest_port").replace("{port}", &suggested.to_string())
                );

                let port_str: String = Input::new()
                    .with_prompt(crate::i18n::tr("cli_port_prompt"))
                    .default(suggested.to_string())
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input == "0" {
                            return Ok(());
                        }
                        let port: u16 = input
                            .parse()
                            .map_err(|_| crate::i18n::tr("cli_port_invalid"))?;
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
            },
            StepKind::SshKeySetup => {
                // 如果已经在 UserCreation 中设置过密钥，跳过
                if params.ssh_key_action.is_some() {
                    continue;
                }

                // 确定目标用户
                let users = system::detect_sudo_users();
                let target_user = if users.is_empty() {
                    println!("{} {}", "ℹ️".yellow(), crate::i18n::tr("cli_manual_user"));
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

                let action_options = &[
                    crate::i18n::tr("cli_key_generate"),
                    crate::i18n::tr("cli_key_paste"),
                    crate::i18n::tr("cli_key_skip"),
                ];
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
                    },
                    1 => {
                        let pub_key: String = Input::new()
                            .with_prompt(crate::i18n::tr("cli_key_prompt"))
                            .interact()
                            .unwrap_or_default();

                        if !pub_key.is_empty() {
                            params.ssh_key_username = Some(target_user);
                            params.ssh_key_action = Some(SshKeyAction::PasteKey(pub_key));
                        }
                    },
                    _ => {},
                }
            },
            _ => { /* 无交互需求的步骤 */ },
        }
    }

    params
}

/// 渲染审计报告
fn render_audit_report(report: &AuditReport) {
    println!(
        "{} {}",
        "📊".bright_cyan(),
        crate::i18n::tr("cli_audit_done")
    );
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
            let suffix = if step.is_opt_in() {
                format!("  {}", crate::i18n::tr("step_opt_in_tag"))
            } else {
                String::new()
            };
            format!("{} {}{}", status.icon(), step.label(), suffix)
        })
        .collect();

    println!(
        "{} {}\n",
        "📋".bright_blue(),
        crate::i18n::tr("cli_select_steps"),
    );
    println!("{} {}", "💡".dimmed(), crate::i18n::tr("cli_hint_nav"));
    println!("{} {}\n", "💡".dimmed(), crate::i18n::tr("cli_hint_opt_in"));

    let selections = MultiSelect::new()
        .items(&items)
        .defaults(
            &all_steps
                .iter()
                .map(|step| step.default_checked(report))
                .collect::<Vec<_>>(),
        )
        .interact()
        .unwrap_or_default();

    selections.into_iter().map(|i| all_steps[i]).collect()
}

/// 渲染执行总结（成功 / 跳过 / 失败 三态）
fn render_summary(results: &[StepResult], log_path: &str) {
    println!("\n{}", "=".repeat(50).bright_green());
    println!(
        "{} {}",
        "📋".bright_green(),
        crate::i18n::tr("cli_summary_title")
    );
    println!("{}", "=".repeat(50).bright_green());

    let mut changed = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for result in results {
        match result.outcome {
            StepOutcome::Changed => changed += 1,
            StepOutcome::Skipped => skipped += 1,
            StepOutcome::Failed => failed += 1,
        }
        let (icon, color) = match result.outcome {
            StepOutcome::Changed => ("✅", "green"),
            StepOutcome::Skipped => ("⏭", "yellow"),
            StepOutcome::Failed => ("❌", "red"),
        };
        println!(
            "  {} {} [{}]",
            icon,
            result.kind.label().bold(),
            result.outcome.label().color(color)
        );
        for line in result.message.lines() {
            println!("      {}", line.color(color));
        }
        for artifact in &result.artifacts {
            println!(
                "      {} {}",
                crate::i18n::tr("cli_artifact").dimmed(),
                artifact.dimmed()
            );
        }
        println!();
    }

    println!("{}", "─".repeat(50).dimmed());
    println!(
        "  {}",
        crate::i18n::tr("cli_summary_total")
            .replace("{ok}", &changed.to_string())
            .replace("{skip}", &skipped.to_string())
            .replace("{fail}", &failed.to_string())
            .green()
    );
    println!("{}", "=".repeat(50).bright_green());
    println!(
        "{} {}",
        "📝".dimmed(),
        crate::i18n::tr("cli_log_saved").replace("{log}", log_path)
    );
    println!(
        "{} {}",
        "📂".dimmed(),
        crate::i18n::tr("cli_report_dir").replace("{dir}", &artifacts::dir_display())
    );
    println!(
        "{} {}",
        "💡".dimmed(),
        crate::i18n::tr("cli_report_view").replace("{dir}", &artifacts::dir_display())
    );
    println!();
}
