use std::io::Read;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use crate::domain::audit::PackageManager;
use crate::domain::errors::DomainError;

pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIG_LIMIT: u64 = 1024 * 1024;

fn probe(program: &str, args: &[&str]) -> Result<Option<Output>, DomainError> {
    match super::capture::output(
        Command::new(program).args(args).env("LC_ALL", "C"),
        PROBE_TIMEOUT,
    ) {
        Ok(output) => Ok(Some(output)),
        Err(DomainError::CommandUnavailable(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn failed(program: &str) -> DomainError {
    DomainError::AuditFailed(crate::i18n::tr("audit_probe_failed").replace("{program}", program))
}

fn text(output: &Output, program: &str) -> Result<String, DomainError> {
    String::from_utf8(output.stdout.clone()).map_err(|_| failed(program))
}

pub(super) fn is_root() -> Result<bool, DomainError> {
    let output = probe("id", &["-u"])?.ok_or_else(|| failed("id"))?;
    if !output.status.success() {
        return Err(failed("id"));
    }
    text(&output, "id")?
        .trim()
        .parse::<u32>()
        .map(|uid| uid == 0)
        .map_err(|_| failed("id"))
}

pub(super) fn which(program: &str) -> Result<bool, DomainError> {
    let output = probe("which", &[program])?.ok_or_else(|| failed("which"))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(failed("which")),
    }
}

pub(super) fn package_manager() -> Result<PackageManager, DomainError> {
    for (program, manager) in [
        ("apt", PackageManager::Apt),
        ("yum", PackageManager::Yum),
        ("dnf", PackageManager::Dnf),
    ] {
        if which(program)? {
            return Ok(manager);
        }
    }
    Ok(PackageManager::Unknown)
}

pub(super) fn sudo_users() -> Result<Vec<String>, DomainError> {
    for group in ["sudo", "wheel"] {
        let output = probe("getent", &["group", group])?.ok_or_else(|| failed("getent"))?;
        if output.status.code() == Some(2) {
            continue;
        }
        if !output.status.success() {
            return Err(failed("getent"));
        }
        let line = text(&output, "getent")?;
        let fields: Vec<_> = line.trim().split(':').collect();
        if fields.len() != 4 {
            return Err(failed("getent"));
        }
        let mut users = Vec::new();
        for user in fields[3]
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            let output = probe("id", &["-u", user])?.ok_or_else(|| failed("id"))?;
            if !output.status.success() {
                return Err(failed("id"));
            }
            let uid = text(&output, "id")?
                .trim()
                .parse::<u32>()
                .map_err(|_| failed("id"))?;
            if uid >= 1000 {
                users.push(user.to_string());
            }
        }
        return Ok(users);
    }
    Ok(Vec::new())
}

pub(super) fn ufw_enabled(root: &Path) -> Result<bool, DomainError> {
    if !which("ufw")? {
        return Ok(false);
    }
    let ipv6 = ufw_uses_ipv6(root)?;
    if !ufw_chains_present("iptables-save", "ufw")? {
        return Ok(false);
    }
    if ipv6 && !ufw_chains_present("ip6tables-save", "ufw6")? {
        return Err(failed("ip6tables-save"));
    }
    Ok(true)
}

fn ufw_uses_ipv6(root: &Path) -> Result<bool, DomainError> {
    let mut defaults = std::collections::HashMap::new();
    for name in ["etc/default/ufw", "etc/ufw/ufw.conf"] {
        let config = read_config(&root.join(name))?.ok_or_else(|| failed("ufw config"))?;
        for line in config.lines() {
            let Some((key, value)) = line.trim_end().split_once('=') else {
                continue;
            };
            let word = |ch: char| ch.is_alphanumeric() || ch == '_';
            // UFW accepts a word assignment at column zero, not shell syntax.
            if key.is_empty()
                || !key.chars().all(word)
                || !value
                    .strip_prefix('"')
                    .unwrap_or(value)
                    .chars()
                    .next()
                    .is_some_and(word)
            {
                continue;
            }
            let value = value.split('=').next().unwrap_or(value);
            defaults.insert(
                key.to_lowercase(),
                value.trim_matches(['"', '\'']).to_lowercase(),
            );
        }
    }
    for policy in [
        "default_input_policy",
        "default_output_policy",
        "default_forward_policy",
    ] {
        if !matches!(
            defaults.get(policy).map(String::as_str),
            Some("accept" | "drop" | "reject")
        ) {
            return Err(failed("ufw config"));
        }
    }
    Ok(defaults.get("ipv6").is_some_and(|value| value == "yes")
        && root
            .join("proc/sys/net/ipv6")
            .try_exists()
            .map_err(|error| DomainError::AuditFailed(error.to_string()))?)
}

fn ufw_chains_present(program: &str, prefix: &str) -> Result<bool, DomainError> {
    // Unlike `ufw status`, save does not create a lock file. Do not request unloaded tables.
    let output = probe(program, &["-M", "/bin/false"])?.ok_or_else(|| failed(program))?;
    if !output.status.success() || !output.stderr.iter().all(u8::is_ascii_whitespace) {
        return Err(failed(program));
    }
    let content = text(&output, program)?;
    let mut table = None;
    let mut filter_seen = false;
    let mut chains = [false; 3];
    let mut quote = None;
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if quote.is_some() {
            update_rule_quote(line, &mut quote);
            continue;
        }
        if line.starts_with("# Table ") {
            return Err(failed(program));
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('*') {
            if table.is_some()
                || name.is_empty()
                || name.contains(char::is_whitespace)
                || (name == "filter" && filter_seen)
            {
                return Err(failed(program));
            }
            filter_seen |= name == "filter";
            table = Some(name);
        } else if line == "COMMIT" && table.is_some() {
            table = None;
        } else if let Some(chain) = line.strip_prefix(':').filter(|_| table.is_some()) {
            let fields: Vec<_> = chain.split_whitespace().collect();
            if fields.len() != 3
                || !fields[2]
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .and_then(|value| value.split_once(':'))
                    .is_some_and(|(packets, bytes)| {
                        packets.parse::<u64>().is_ok() && bytes.parse::<u64>().is_ok()
                    })
            {
                return Err(failed(program));
            }
            if table == Some("filter") {
                for (index, direction) in ["input", "output", "forward"].iter().enumerate() {
                    chains[index] |= fields[0] == format!("{prefix}-user-{direction}");
                }
            }
        } else if table.is_some() && line.starts_with("-A ") {
            update_rule_quote(line, &mut quote);
        } else {
            return Err(failed(program));
        }
    }
    if table.is_some() {
        return Err(failed(program));
    }
    Ok(chains.iter().all(|present| *present))
}

fn update_rule_quote(line: &str, quote: &mut Option<char>) {
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            chars.next();
        } else if *quote == Some(ch) {
            *quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            *quote = Some(ch);
        }
    }
}

pub(super) fn read_config(path: &Path) -> Result<Option<String>, DomainError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DomainError::AuditFailed(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| DomainError::AuditFailed(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > CONFIG_LIMIT {
        return Err(failed("config"));
    }
    let mut bytes = Vec::new();
    file.take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| DomainError::AuditFailed(error.to_string()))?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        return Err(failed("config"));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| failed("config"))
}

pub(super) fn auto_updates_enabled(root: &Path) -> Result<bool, DomainError> {
    if let Some(output) = probe("systemctl", &["is-enabled", "unattended-upgrades"])? {
        match (output.status.code(), text(&output, "systemctl")?.trim()) {
            (
                Some(0),
                "enabled" | "enabled-runtime" | "static" | "alias" | "indirect" | "generated"
                | "transient",
            ) => return Ok(true),
            (
                Some(1),
                "disabled" | "masked" | "masked-runtime" | "linked" | "linked-runtime"
                | "transient",
            )
            | (Some(4), "not-found") => {},
            _ => return Err(failed("systemctl")),
        }
    }
    Ok(
        read_config(&root.join("etc/apt/apt.conf.d/20auto-upgrades"))?.is_some_and(|content| {
            content.contains("APT::Periodic::Update-Package-Lists \"1\"")
                || content.contains("APT::Periodic::Unattended-Upgrade \"1\"")
        }),
    )
}

pub(super) fn system_up_to_date(root: &Path) -> bool {
    for name in ["var/lib/apt/lists", "var/cache/apt/pkgcache.bin"] {
        if let Ok(metadata) = root.join(name).metadata()
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = modified.elapsed()
        {
            return elapsed.as_secs() < 604800;
        }
    }
    false
}

pub(super) fn ssh_restart_needed(root: &Path) -> Result<bool, DomainError> {
    let Ok(modified) = root
        .join("etc/ssh/sshd_config")
        .metadata()
        .and_then(|m| m.modified())
    else {
        return Ok(false);
    };
    let mut pid = None;
    for name in ["run/sshd.pid", "var/run/sshd.pid"] {
        if let Some(content) = read_config(&root.join(name))?
            && let Ok(value) = content.trim().parse::<u32>()
            && value > 0
        {
            pid = Some(value);
            break;
        }
    }
    if pid.is_none() {
        for unit in ["sshd", "ssh"] {
            if let Some(output) = probe("systemctl", &["show", "-p", "MainPID", "--value", unit])?
                && output.status.success()
                && let Ok(value) = text(&output, "systemctl")?.trim().parse::<u32>()
                && value > 0
            {
                pid = Some(value);
                break;
            }
        }
    }
    Ok(pid.is_some_and(|pid| {
        root.join(format!("proc/{pid}"))
            .metadata()
            .and_then(|m| m.modified())
            .map(|started| modified > started)
            .unwrap_or(true)
    }))
}

#[cfg(all(test, unix))]
#[path = "audit_tests.rs"]
mod tests;
