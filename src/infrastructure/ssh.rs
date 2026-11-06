use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::errors::DomainError;
use crate::domain::ssh_context::{SshAuthentication, SshContext};
use crate::infrastructure::{backup, rollback};

pub const CONFIG_PATH: &str = "/etc/ssh/sshd_config";

#[derive(Debug)]
pub struct EffectiveConfig {
    pub ports: Vec<u16>,
    pub password_auth_disabled: bool,
    pub root_login_disabled: bool,
    pub verified: bool,
    values: Vec<(String, String)>,
}

impl EffectiveConfig {
    fn parse(output: &str, content: &str) -> Result<Self, DomainError> {
        let values: Vec<_> = output
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        let get = |key: &str| {
            values
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .ok_or_else(|| invalid_config(key))
        };
        let mut ports = values
            .iter()
            .filter(|(key, _)| key == "port")
            .map(|(_, value)| value.parse::<u16>().map_err(|_| invalid_config("Port")))
            .collect::<Result<Vec<_>, _>>()?;
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() || ports.contains(&0) {
            return Err(invalid_config("Port"));
        }
        let password_auth_disabled =
            get("passwordauthentication")? == "no" && get("kbdinteractiveauthentication")? == "no";
        let root_login_disabled = matches!(
            get("permitrootlogin")?,
            "no" | "prohibit-password" | "without-password"
        );
        // -T without -C describes global settings, not every possible Match context.
        let verified = ports.len() == 1
            && !content
                .lines()
                .any(|line| matches!(keyword(line).as_str(), "include" | "match"));
        Ok(Self {
            ports,
            password_auth_disabled,
            root_login_disabled,
            verified,
            values,
        })
    }

    fn matches(&self, key: &str, value: &str) -> bool {
        if key.eq_ignore_ascii_case("Port") {
            return value
                .parse::<u16>()
                .ok()
                .is_some_and(|port| self.ports == [port]);
        }
        self.values.iter().any(|(name, actual)| {
            name == &key.to_ascii_lowercase()
                && (actual.eq_ignore_ascii_case(value)
                    || (name == "permitrootlogin"
                        && value == "prohibit-password"
                        && actual == "without-password"))
        })
    }
}

pub struct SshConfig {
    path: PathBuf,
    program: PathBuf,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self::new(CONFIG_PATH, "sshd")
    }
}

impl SshConfig {
    pub fn new(path: impl Into<PathBuf>, program: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            program: program.into(),
        }
    }

    pub fn effective(&self) -> Result<EffectiveConfig, DomainError> {
        let content =
            super::audit::read_config(&self.path)?.ok_or_else(|| invalid_config("sshd_config"))?;
        self.effective_at(&self.path, &content)
    }

    pub fn effective_for(&self, context: &SshContext) -> Result<SshAuthentication, DomainError> {
        super::audit::read_config(&self.path)?.ok_or_else(|| invalid_config("sshd_config"))?;
        let mut command = Command::new(&self.program);
        command
            .arg("-T")
            .arg("-f")
            .arg(&self.path)
            .arg("-C")
            .arg(context.connection_spec());
        let output = self.read_output(&mut command, "-T -C")?;
        let value = |key: &str, allowed: &[&str]| {
            let values: Vec<_> = output
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter(|(name, _)| *name == key)
                .map(|(_, value)| value.trim())
                .collect();
            match values.as_slice() {
                [value] if allowed.contains(value) => Ok((*value).to_string()),
                _ => Err(invalid_config(key)),
            }
        };
        Ok(SshAuthentication {
            password_authentication: value("passwordauthentication", &["yes", "no"])?,
            kbd_interactive_authentication: value("kbdinteractiveauthentication", &["yes", "no"])?,
            permit_root_login: value(
                "permitrootlogin",
                &[
                    "yes",
                    "no",
                    "prohibit-password",
                    "without-password",
                    "forced-commands-only",
                ],
            )?,
        })
    }

    fn check(&self, path: &Path, flag: &str) -> Result<String, DomainError> {
        self.read_output(
            Command::new(&self.program).arg(flag).arg("-f").arg(path),
            flag,
        )
    }

    fn read_output(&self, command: &mut Command, flag: &str) -> Result<String, DomainError> {
        let output = super::capture::output(command, super::audit::PROBE_TIMEOUT)?;
        if output.status.code().is_none() {
            return Err(DomainError::AuditFailed(
                crate::i18n::tr("audit_probe_failed").replace("{program}", "sshd"),
            ));
        }
        if !output.status.success() {
            return Err(DomainError::SystemCommandFailed(format!(
                "sshd {flag}: {}: {}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        String::from_utf8(output.stdout).map_err(|e| invalid_config(&e.to_string()))
    }

    fn effective_at(&self, path: &Path, content: &str) -> Result<EffectiveConfig, DomainError> {
        EffectiveConfig::parse(&self.check(path, "-T")?, content)
    }

    pub fn update(&self, settings: &[(&str, &str)]) -> Result<Option<String>, DomainError> {
        let content = std::fs::read_to_string(&self.path).map_err(read_error)?;
        let current = self.effective_at(&self.path, &content)?;
        if settings
            .iter()
            .all(|&(key, value)| current.matches(key, value))
        {
            return Ok(None);
        }
        let updated = render_global(&content, settings);
        let mut candidate = tempfile::Builder::new()
            .prefix(".u2secure-sshd-")
            .tempfile_in(self.path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(write_error)?;
        candidate
            .write_all(updated.as_bytes())
            .map_err(write_error)?;
        self.check(candidate.path(), "-t")?;
        let effective = self.effective_at(candidate.path(), &updated)?;
        for &(key, value) in settings {
            if !effective.matches(key, value) {
                return Err(invalid_config(&format!("{key} {value}")));
            }
        }
        if content == updated {
            return Ok(None);
        }
        let saved = backup::backup_file(&self.path)?.ok_or_else(|| invalid_config(CONFIG_PATH))?;
        rollback::register_file_backup(
            crate::i18n::tr("undo_file_restore").replace("{key}", "sshd_config"),
            saved.to_string_lossy().into_owned(),
            self.path.to_string_lossy().into_owned(),
        );
        std::fs::write(&self.path, updated).map_err(write_error)?;
        Ok(Some(
            crate::i18n::tr("result_sshd_global_set").replace("{bak}", &saved.to_string_lossy()),
        ))
    }
}

fn keyword(line: &str) -> String {
    line.trim()
        .split([' ', '\t', '='])
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_ascii_lowercase()
}

fn render_global(content: &str, settings: &[(&str, &str)]) -> String {
    let mut output = String::new();
    for &(key, value) in settings {
        output.push_str(&format!("{key} {value}\n"));
    }
    let mut global = true;
    for line in content.lines() {
        let key = keyword(line);
        if key == "match" {
            global = false;
        }
        let replaced = settings.iter().any(|(name, _)| {
            key.eq_ignore_ascii_case(name)
                || (name.eq_ignore_ascii_case("KbdInteractiveAuthentication")
                    && key == "challengeresponseauthentication")
        });
        if !global || !replaced {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn invalid_config(detail: &str) -> DomainError {
    DomainError::ParseError(format!(
        "{}: {detail}",
        crate::i18n::tr("err_sshd_effective")
    ))
}

fn read_error(error: std::io::Error) -> DomainError {
    DomainError::ParseError(format!("{}: {error}", crate::i18n::tr("err_read")))
}

fn write_error(error: std::io::Error) -> DomainError {
    DomainError::SystemCommandFailed(format!("{}: {error}", crate::i18n::tr("err_write")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EFFECTIVE: &str = "port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\n";

    #[test]
    fn global_render_preserves_match_and_canonicalizes_aliases() {
        let original = "pOrT 22\nPort 2200\nChallengeResponseAuthentication yes\nKbdInteractiveAuthentication yes\nInclude extras/*.conf\nMatch User restricted\n PasswordAuthentication yes\n";
        let changed = render_global(
            original,
            &[("Port", "2222"), ("KbdInteractiveAuthentication", "no")],
        );
        assert_eq!(
            changed,
            "Port 2222\nKbdInteractiveAuthentication no\nInclude extras/*.conf\nMatch User restricted\n PasswordAuthentication yes\n"
        );
        assert_eq!(
            render_global(
                &changed,
                &[("Port", "2222"), ("KbdInteractiveAuthentication", "no")]
            ),
            changed
        );
    }

    #[test]
    fn effective_audit_is_global_and_fail_closed() {
        let config = EffectiveConfig::parse(EFFECTIVE, "# Include example\nPort 2222\n").unwrap();
        assert!(config.verified && config.password_auth_disabled && config.root_login_disabled);
        for original in [
            "Include *.conf",
            "mAtCh User admin",
            "\"Include\" extra.conf",
        ] {
            assert!(
                !EffectiveConfig::parse(EFFECTIVE, original)
                    .unwrap()
                    .verified
            );
        }
        let multiple = EffectiveConfig::parse(&format!("{EFFECTIVE}port 22\n"), "").unwrap();
        assert!(!multiple.verified);
        assert!(!multiple.matches("Port", "2222"));
        assert!(EffectiveConfig::parse("port 2222", "").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn validated_updates_restore_original_and_reject_failures_before_writing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sshd_config");
        let program = dir.path().join("fake-sshd");
        let original =
            "PasswordAuthentication yes\nMatch User restricted\n PasswordAuthentication no\n";
        std::fs::write(&path, original).unwrap();
        std::fs::write(&program, r#"#!/bin/sh
[ "$2" = -f ] || exit 50
[ -f "$3" ] || exit 51
[ "$1" = -t ] && exit 0
awk '
BEGIN { port=22; password="yes"; keyboard="yes"; root="yes" }
tolower($1)=="match" { exit }
tolower($1)=="port" && !p++ { port=$2 }
tolower($1)=="passwordauthentication" && !a++ { password=$2 }
tolower($1)=="kbdinteractiveauthentication" && !k++ { keyboard=$2 }
tolower($1)=="permitrootlogin" && !r++ { root=$2 }
END { print "port " port; print "passwordauthentication " password; print "kbdinteractiveauthentication " keyboard; print "permitrootlogin " root }
' "$3"
"#).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ssh = SshConfig::new(&path, &program);
        assert!(ssh.update(&[("Port", "2222")]).unwrap().is_some());
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("Port 2222\n")
        );
        assert!(
            ssh.update(&[
                ("PasswordAuthentication", "no"),
                ("KbdInteractiveAuthentication", "no")
            ])
            .unwrap()
            .is_some()
        );
        assert!(
            ssh.update(&[
                ("PasswordAuthentication", "no"),
                ("KbdInteractiveAuthentication", "no")
            ])
            .unwrap()
            .is_none()
        );
        let configured = std::fs::read_to_string(&path).unwrap();
        let repeated = ssh.update(&[("Port", "2222")]);
        rollback::undo_all();
        assert!(
            repeated.unwrap().is_none(),
            "matching effective settings must not be reordered"
        );
        assert!(configured.starts_with("PasswordAuthentication no\n"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        for script in [
            "#!/bin/sh\necho invalid >&2\nexit 42\n".to_string(),
            format!("#!/bin/sh\n[ \"$1\" = -t ] && exit 0\nprintf '%s' '{EFFECTIVE}port 22\n'\n"),
        ] {
            std::fs::write(&program, script).unwrap();
            assert!(ssh.update(&[("Port", "2222")]).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        }
        std::fs::write(&program, "#!/bin/sh\nkill -KILL $$\n").unwrap();
        assert!(matches!(ssh.effective(), Err(DomainError::AuditFailed(_))));
        assert!(
            SshConfig::new(&path, dir.path().join("missing-command"))
                .effective()
                .is_err()
        );
    }
}
