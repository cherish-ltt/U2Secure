use std::io::Write;

use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::audit::{AuditReport, AuditStatus};
use crate::domain::errors::DomainError;
use crate::domain::steps::StepKind;
use crate::i18n::tr;
use crate::infrastructure::system;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    Json,
}

impl Format {
    fn parse(args: &[String]) -> Result<Option<Self>, DomainError> {
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            [] => Ok(Some(Self::Text)),
            ["--format", "text"] => Ok(Some(Self::Text)),
            ["--format", "json"] => Ok(Some(Self::Json)),
            ["-h" | "--help"] => Ok(None),
            _ => Err(DomainError::AuditFailed(tr("audit_usage").trim().into())),
        }
    }
}

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u32,
    tool_version: &'static str,
    collected_at: &'a str,
    check_scope: [&'static str; 9],
    is_root: bool,
    package_manager: &'static str,
    checks: Vec<Check>,
}

#[derive(Serialize)]
struct Check {
    id: &'static str,
    status: &'static str,
    details: Value,
}

/// Arguments exclude the `audit` subcommand itself.
pub fn run(args: &[String]) -> Result<(), DomainError> {
    run_with(args, system::audit_readonly, &mut std::io::stdout().lock())
}

fn run_with(
    args: &[String],
    collect: impl FnOnce() -> Result<AuditReport, DomainError>,
    writer: &mut impl Write,
) -> Result<(), DomainError> {
    let Some(format) = Format::parse(args)? else {
        return write_output(writer, tr("audit_usage").as_bytes());
    };
    let report = collect()?;
    let collected_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    render(&report, format, &collected_at, writer)
}

fn render(
    report: &AuditReport,
    format: Format,
    collected_at: &str,
    writer: &mut impl Write,
) -> Result<(), DomainError> {
    let bytes = match format {
        Format::Json => {
            let mut bytes =
                serde_json::to_vec_pretty(&document(report, collected_at)).map_err(|error| {
                    DomainError::AuditFailed(
                        tr("audit_serialize_failed").replace("{err}", &error.to_string()),
                    )
                })?;
            bytes.push(b'\n');
            bytes
        },
        Format::Text => render_text(report, collected_at).into_bytes(),
    };
    write_output(writer, &bytes)
}

fn write_output(writer: &mut impl Write, bytes: &[u8]) -> Result<(), DomainError> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|error| {
            DomainError::AuditFailed(tr("audit_output_failed").replace("{err}", &error.to_string()))
        })
}

fn document<'a>(report: &AuditReport, collected_at: &'a str) -> Document<'a> {
    Document {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION"),
        collected_at,
        check_scope: [
            "local-read-only",
            "apt-cache-age-not-package-upgrades",
            "debian-ubuntu-reboot-marker-not-complete-patch-activation",
            "sudo-wheel-members-not-complete-sudo-policy",
            "ssh-global-only-no-connection-or-key-verification",
            "ssh-include-match-multiple-ports-unverified",
            "firewall-chains-not-complete-rules-or-atomic-snapshot",
            "tool-presence-not-security-scans",
            "ssh-restart-timestamp-heuristic",
        ],
        is_root: report.is_root,
        package_manager: report.package_manager.name(),
        checks: StepKind::all()
            .iter()
            .map(|&kind| Check {
                id: kind.slug(),
                status: status_code(report.status_for(kind)),
                details: details(report, kind),
            })
            .collect(),
    }
}

fn status_code(status: AuditStatus) -> &'static str {
    match status {
        AuditStatus::Safe => "safe",
        AuditStatus::Partial => "partial",
        AuditStatus::Missing => "missing",
        AuditStatus::NeedsUpdate => "needs_update",
    }
}

fn details(report: &AuditReport, kind: StepKind) -> Value {
    match kind {
        StepKind::SystemUpdate => json!({
            "apt_cache_recent": report.system_up_to_date,
            "reboot_hint": {
                "status": report.reboot_hint.status(),
                "source": report.reboot_hint.source(),
            },
        }),
        StepKind::UserCreation => json!({"sudo_users": report.sudo_users}),
        StepKind::SshRootLogin => json!({
            "global_config_verified": report.ssh_config_verified,
            "root_login_restricted": report.ssh_config_verified.then_some(report.root_login_disabled),
        }),
        StepKind::SshPortChange => json!({
            "global_config_verified": report.ssh_config_verified,
            "port": report.ssh_config_verified.then_some(report.ssh_port),
        }),
        StepKind::SshPasswordAuth => json!({
            "global_config_verified": report.ssh_config_verified,
            "password_auth_disabled": report.ssh_config_verified.then_some(report.password_auth_disabled),
        }),
        StepKind::SshKeySetup => json!({"keys_verified": false}),
        StepKind::Ufw => json!({"enabled": report.ufw_enabled}),
        StepKind::Fail2ban => json!({"installed": report.fail2ban_installed}),
        StepKind::AutoUpdates => json!({"enabled": report.auto_updates_enabled}),
        StepKind::SecurityScan => {
            json!({"lynis_installed": report.lynis_installed, "scan_executed": false})
        },
        StepKind::LogAudit => json!({
            "logwatch_installed": report.logwatch_installed,
            "aide_installed": report.aide_installed,
            "scan_executed": false,
        }),
        StepKind::RestartSsh => {
            json!({"restart_needed_hint": report.ssh_restart_needed, "live_settings_verified": false})
        },
    }
}

fn render_text(report: &AuditReport, collected_at: &str) -> String {
    let mut text = format!(
        "{}\n{}\n{}\n",
        tr("audit_report_header")
            .replace("{version}", env!("CARGO_PKG_VERSION"))
            .replace("{collected_at}", collected_at),
        tr("audit_report_scope"),
        tr("audit_detail_pkg").replace("{pkg}", report.package_manager.name()),
    );
    for &kind in StepKind::all() {
        let status = tr(match report.status_for(kind) {
            AuditStatus::Safe => "audit_status_safe",
            AuditStatus::Partial => "audit_status_partial",
            AuditStatus::Missing => "audit_status_missing",
            AuditStatus::NeedsUpdate => "audit_status_needs_update",
        });
        text.push_str(&format!(
            "\n{} [{}] {}: {}\n",
            kind.slug(),
            status,
            kind.label(),
            text_detail(report, kind),
        ));
        if let Some(scope) = match kind {
            StepKind::SystemUpdate => Some("audit_scope_cache"),
            StepKind::UserCreation => Some("audit_scope_accounts"),
            StepKind::SshRootLogin | StepKind::SshPortChange | StepKind::SshPasswordAuth => {
                Some("audit_scope_ssh")
            },
            StepKind::SshKeySetup => Some("audit_scope_keys"),
            StepKind::Ufw => Some("audit_scope_ufw"),
            StepKind::SecurityScan | StepKind::LogAudit => Some("audit_scope_installed"),
            StepKind::RestartSsh => Some("audit_scope_restart"),
            _ => None,
        } {
            text.push_str(&format!("  {}\n", tr(scope)));
        }
    }
    text
}

fn text_detail(report: &AuditReport, kind: StepKind) -> String {
    if kind.modifies_ssh_config() && !report.ssh_config_verified {
        return tr("audit_detail_unverified").into();
    }
    let yes_no = |value| tr(if value { "audit_yes" } else { "audit_no" });
    let flag = |value, yes, no| tr(if value { yes } else { no }).to_string();
    match kind {
        StepKind::SystemUpdate => format!(
            "{}; {}",
            flag(
                report.system_up_to_date,
                "audit_detail_sys_uptodate",
                "audit_detail_cache_not_recent",
            ),
            crate::i18n::reboot_hint(report.reboot_hint),
        ),
        StepKind::UserCreation => {
            if report.sudo_users.is_empty() {
                tr("audit_detail_sudo_missing").into()
            } else {
                tr("audit_detail_sudo_ok").replace("{users}", &report.sudo_users.join(", "))
            }
        },
        StepKind::SshRootLogin => flag(
            report.root_login_disabled,
            "audit_detail_root_restricted",
            "audit_detail_root_missing_cfg",
        ),
        StepKind::SshPortChange => {
            tr("audit_ssh_global").replace("{ports}", &report.ssh_port.to_string())
        },
        StepKind::SshPasswordAuth => flag(
            report.password_auth_disabled,
            "audit_detail_pw_disabled",
            "audit_detail_pw_missing",
        ),
        StepKind::SshKeySetup => tr("audit_detail_unverified").into(),
        StepKind::Ufw => flag(
            report.ufw_enabled,
            "audit_detail_ufw_enabled",
            "audit_detail_ufw_missing",
        ),
        StepKind::Fail2ban => flag(
            report.fail2ban_installed,
            "audit_detail_fb_installed",
            "audit_detail_fb_missing",
        ),
        StepKind::AutoUpdates => flag(
            report.auto_updates_enabled,
            "audit_detail_au_enabled",
            "audit_detail_au_missing",
        ),
        StepKind::SecurityScan => flag(
            report.lynis_installed,
            "audit_detail_fb_installed",
            "audit_detail_fb_missing",
        ),
        StepKind::LogAudit => tr("audit_detail_log_tools")
            .replace("{logwatch}", yes_no(report.logwatch_installed))
            .replace("{aide}", yes_no(report.aide_installed)),
        StepKind::RestartSsh => {
            tr("audit_detail_restart").replace("{needed}", yes_no(report.ssh_restart_needed))
        },
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
