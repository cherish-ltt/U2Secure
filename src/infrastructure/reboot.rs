use std::path::Path;

use crate::domain::audit::RebootHint;
use crate::domain::errors::DomainError;

pub fn detect(root: &Path) -> Result<RebootHint, DomainError> {
    let release = match super::audit::read_config(&root.join("etc/os-release"))? {
        Some(release) => Some(release),
        None => super::audit::read_config(&root.join("usr/lib/os-release"))?,
    };
    let Some(release) = release else {
        return Ok(RebootHint::Unsupported);
    };
    let Some(value) = release
        .lines()
        .filter_map(|line| line.trim().strip_prefix("ID="))
        .next_back()
    else {
        return Ok(RebootHint::Unsupported);
    };
    let id = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    if id.is_empty()
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(DomainError::AuditFailed(
            crate::i18n::tr("reboot_os_release_invalid").into(),
        ));
    }
    let source = match id {
        "debian" => "/run/reboot-required",
        "ubuntu" => "/var/run/reboot-required",
        _ => return Ok(RebootHint::Unsupported),
    };
    match std::fs::symlink_metadata(root.join(&source[1..])) {
        Ok(_) => Ok(RebootHint::Found(source)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(RebootHint::NotFound(source))
        },
        Err(error) => Err(DomainError::AuditFailed(format!("{source}: {error}"))),
    }
}

#[cfg(test)]
#[path = "reboot_tests.rs"]
mod tests;
