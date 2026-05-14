use colored::*;
use dialoguer::{Confirm, MultiSelect};

use crate::application::orchestrator::HardeningOrchestrator;
use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::steps::StepKind;

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

    // ── 确认执行 ──
    println!("\n{} 以下步骤将被执行：", "📋".bright_blue());
    for s in &selected_steps {
        println!("  - {}", s.label());
    }

    if !Confirm::new()
        .with_prompt("是否继续执行？")
        .default(false)
        .interact()
        .unwrap_or(false)
    {
        println!("\n{} 用户取消。", "ℹ️".yellow());
        return;
    }

    // ── 执行 ──
    println!("\n{} 开始执行加固步骤...\n", "⚙️".bright_green());
    let results = orchestrator.execute_steps(&report, &selected_steps);

    // ── 总结报告 ──
    render_summary(&results);
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

            // 修复 format! 用法
            let status_icon = status.icon();
            format!("{status_icon} {}", step.label())
        })
        .collect();

    println!("{} 请选择要执行的加固步骤（已安全配置的默认不勾选）：\n", "📋".bright_blue());
    println!("{} 提示：方向键上下移动，空格选择，回车确认\n", "💡".dimmed());

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

    selections
        .into_iter()
        .map(|i| all_steps[i])
        .collect()
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
            println!(
                "  {} {}: {}",
                "✅".green(),
                result.kind.label().bold(),
                result.message.green()
            );
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
    println!(
        "{} 日志已保存至 /var/log/secure-init.log",
        "📝".dimmed()
    );
    println!();
}
