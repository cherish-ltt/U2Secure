use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::errors::DomainError;
use crate::domain::undo::UndoAction;
use crate::infrastructure::{backup, batch_record, rollback};

#[derive(Clone)]
pub struct Ufw {
    config_dir: PathBuf,
    program: PathBuf,
}

impl Default for Ufw {
    fn default() -> Self {
        Self::new("/etc/ufw", "ufw")
    }
}

impl Ufw {
    pub fn new(config_dir: impl Into<PathBuf>, program: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            program: program.into(),
        }
    }

    fn run(&self, args: &[&str]) -> Result<String, DomainError> {
        let output = Command::new(&self.program)
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!("ufw {}: {e}", args.join(" ")))
            })?;
        if !output.status.success() {
            return Err(DomainError::SystemCommandFailed(format!(
                "ufw {}: {}: {}{}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn enabled(&self) -> Result<bool, DomainError> {
        let status = self.run(&["status"])?;
        match status.lines().next() {
            Some("Status: active") => Ok(true),
            Some("Status: inactive") => Ok(false),
            _ => Err(DomainError::ParseError(format!(
                "{}: {status}",
                crate::i18n::tr("err_ufw_status")
            ))),
        }
    }

    pub fn allow_port(&self, port: u16, enable: bool) -> Result<bool, DomainError> {
        let was_enabled = self.enabled()?;
        if !was_enabled && !enable {
            return Ok(false);
        }
        let snapshot = Snapshot::capture(&self.config_dir)?;
        let before = snapshot.current_bytes()?;
        let undo_firewall = self.clone();
        let paths = snapshot.files.clone();
        rollback::register_tracked(
            UndoAction::try_new(
                crate::i18n::tr("undo_ufw_restore").into(),
                Box::new(move || snapshot.restore(&undo_firewall, was_enabled)),
            ),
            "ufw_restore",
            &paths,
        );
        self.run(&["allow", &port.to_string()])?;
        if !was_enabled && enable {
            self.run(&["--force", "enable"])?;
        }
        if self.enabled()? != (was_enabled || enable) {
            return Err(DomainError::SystemCommandFailed(
                crate::i18n::tr("err_ufw_status").into(),
            ));
        }
        Ok(!was_enabled || before != read_configs(&self.config_dir)?)
    }
}

const FILES: [&str; 3] = ["user.rules", "user6.rules", "ufw.conf"];

struct Snapshot {
    files: Vec<(PathBuf, Option<PathBuf>)>,
}

impl Snapshot {
    fn capture(dir: &Path) -> Result<Self, DomainError> {
        let mut files = Vec::new();
        for name in FILES {
            let original = dir.join(name);
            let saved = backup::backup_file(&original)?;
            files.push((original, saved));
        }
        Ok(Self { files })
    }

    fn current_bytes(&self) -> Result<Vec<Option<Vec<u8>>>, DomainError> {
        self.files
            .iter()
            .map(|(path, _)| read_optional(path))
            .collect()
    }

    fn restore(self, firewall: &Ufw, was_enabled: bool) -> Result<(), DomainError> {
        let unchanged = self.files.iter().all(|(path, saved)| {
            let current = read_optional(path);
            let old = saved.as_ref().map_or(Ok(None), |path| read_optional(path));
            matches!((current, old), (Ok(current), Ok(old)) if current == old)
        });
        if unchanged && firewall.enabled().ok() == Some(was_enabled) {
            for (original, saved) in &self.files {
                batch_record::backup_unchanged(original, saved.as_deref());
            }
            return self.cleanup();
        }
        // Disable before restoring ufw.conf: disable itself rewrites that file.
        let mut failures = Vec::new();
        if !was_enabled && let Err(error) = firewall.run(&["--force", "disable"]) {
            failures.push(error.to_string());
        }
        for (original, saved) in &self.files {
            let result = if let Some(saved) = saved {
                std::fs::copy(saved, original).map(|_| ())
            } else {
                match std::fs::remove_file(original) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    result => result,
                }
            };
            batch_record::backup_restored(original, saved.as_deref(), &result);
            if let Err(error) = result {
                failures.push(format!("{}: {error}", original.display()));
            }
        }
        if failures.is_empty()
            && was_enabled
            && let Err(error) = firewall.run(&["reload"])
        {
            failures.push(error.to_string());
        }
        match firewall.enabled() {
            Ok(enabled) if enabled == was_enabled => {},
            Ok(_) => failures.push(crate::i18n::tr("err_ufw_status").into()),
            Err(error) => failures.push(error.to_string()),
        }
        if !failures.is_empty() {
            return Err(DomainError::SystemCommandFailed(format!(
                "{}; {:?}",
                failures.join("; "),
                self.files
            )));
        }
        self.cleanup()
    }

    fn cleanup(self) -> Result<(), DomainError> {
        for (original, saved) in self.files {
            let result = saved.as_ref().map_or(Ok(()), std::fs::remove_file);
            batch_record::backup_cleaned(&original, saved.as_deref(), &result);
            if let Some(saved) = saved {
                result.map_err(|e| {
                    DomainError::SystemCommandFailed(format!("{}: {e}", saved.display()))
                })?;
            }
        }
        Ok(())
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, DomainError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(DomainError::ParseError(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

fn read_configs(dir: &Path) -> Result<Vec<Option<Vec<u8>>>, DomainError> {
    FILES
        .iter()
        .map(|name| read_optional(&dir.join(name)))
        .collect()
}
