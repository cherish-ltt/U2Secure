use std::process::{Command, Output};
use std::time::Duration;

use crate::domain::errors::DomainError;
use crate::infrastructure::system::{self, StreamStatus};

pub fn restart_ssh(log_path: &str) -> Result<String, DomainError> {
    restart_ssh_with(
        |args| Command::new("systemctl").args(args).output(),
        |unit| {
            system::run_streaming_argv(
                &["systemctl".into(), "restart".into(), unit.into()],
                &[],
                log_path,
                Duration::from_secs(120),
            )
        },
    )
    .map_err(|e| {
        DomainError::SystemCommandFailed(
            crate::i18n::tr("result_see_log")
                .replace("{msg}", &e.to_string())
                .replace("{log}", log_path),
        )
    })
}

fn restart_ssh_with(
    mut command: impl FnMut(&[&str]) -> std::io::Result<Output>,
    restart: impl FnOnce(&str) -> Result<StreamStatus, DomainError>,
) -> Result<String, DomainError> {
    let unit = select_unit(&mut command)?;
    let status = restart(unit).map_err(|e| {
        DomainError::SystemCommandFailed(format!(
            "{} ({unit}): {e}",
            crate::i18n::tr("err_ssh_restart")
        ))
    })?;
    if !status.is_success() {
        return Err(DomainError::SystemCommandFailed(format!(
            "{} ({unit}): {}",
            crate::i18n::tr("err_ssh_restart"),
            status.describe()
        )));
    }
    let output = query(&mut command, &["is-active", unit])?;
    if !output.status.success() || output.stdout.trim_ascii() != b"active" {
        return Err(DomainError::SystemCommandFailed(format!(
            "{} ({unit}): {}",
            crate::i18n::tr("err_ssh_not_active"),
            output_details(&output)
        )));
    }
    Ok("active".into())
}

fn select_unit(
    command: &mut impl FnMut(&[&str]) -> std::io::Result<Output>,
) -> Result<&'static str, DomainError> {
    for unit in ["sshd.service", "ssh.service"] {
        let output = query(command, &["show", "--property=LoadState", unit])?;
        // A missing unit can make `show` exit nonzero; only its explicit load state permits fallback.
        if output.stdout.trim_ascii() == b"LoadState=not-found" {
            continue;
        }
        if output.status.success() && output.stdout.trim_ascii() == b"LoadState=loaded" {
            return Ok(unit);
        }
        return Err(DomainError::SystemCommandFailed(format!(
            "{} ({unit}): {}",
            crate::i18n::tr("err_ssh_service_state"),
            output_details(&output)
        )));
    }
    Err(DomainError::SystemCommandFailed(
        crate::i18n::tr("err_ssh_service_missing").into(),
    ))
}

fn query(
    command: &mut impl FnMut(&[&str]) -> std::io::Result<Output>,
    args: &[&str],
) -> Result<Output, DomainError> {
    command(args)
        .map_err(|e| DomainError::SystemCommandFailed(format!("systemctl {}: {e}", args.join(" "))))
}

fn output_details(output: &Output) -> String {
    format!(
        "{}; {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn restarts_ssh_when_sshd_unit_is_missing() {
        for missing_code in [0, 1] {
            let result = restart_ssh_with(
                |args| {
                    Ok(match args {
                        ["show", "--property=LoadState", "sshd.service"] => {
                            output(missing_code, "LoadState=not-found\n", "")
                        },
                        ["show", "--property=LoadState", "ssh.service"] => {
                            output(0, "LoadState=loaded\n", "")
                        },
                        ["is-active", "ssh.service"] => output(0, "active\n", ""),
                        _ => panic!("unexpected command {args:?}"),
                    })
                },
                |unit| {
                    assert_eq!(unit, "ssh.service");
                    Ok(StreamStatus::Success)
                },
            );
            assert_eq!(result.unwrap(), "active");
        }
    }

    #[test]
    fn rejects_inactive_service_after_restart() {
        for (code, state) in [
            (3, "inactive"),
            (3, "failed"),
            (0, "inactive"),
            (3, "active"),
        ] {
            let result = restart_ssh_with(
                |args| {
                    Ok(match args {
                        ["show", "--property=LoadState", "sshd.service"] => {
                            output(0, "LoadState=loaded\n", "")
                        },
                        ["is-active", "sshd.service"] => output(code, state, "status error"),
                        _ => panic!("unexpected command {args:?}"),
                    })
                },
                |unit| {
                    assert_eq!(unit, "sshd.service");
                    Ok(StreamStatus::Success)
                },
            );
            let err = result.unwrap_err().to_string();
            assert!(err.contains("sshd.service"));
            assert!(err.contains(state));
            assert!(err.contains("status error"));
        }
    }

    #[test]
    fn restarts_and_checks_sshd_without_querying_other_units() {
        let mut queries = Vec::new();
        let result = restart_ssh_with(
            |args| {
                queries.push(args.join(" "));
                Ok(match args {
                    ["show", "--property=LoadState", "sshd.service"] => {
                        output(0, "LoadState=loaded\n", "")
                    },
                    ["is-active", "sshd.service"] => output(0, "active\n", ""),
                    _ => panic!("unexpected command {args:?}"),
                })
            },
            |unit| {
                assert_eq!(unit, "sshd.service");
                Ok(StreamStatus::Success)
            },
        );
        assert_eq!(result.unwrap(), "active");
        assert_eq!(queries.len(), 2);
    }

    #[test]
    fn existing_service_restart_failures_never_fall_back() {
        for status in [
            StreamStatus::Failed(Some(1)),
            StreamStatus::TimedOut,
            StreamStatus::Cancelled,
        ] {
            let result = restart_ssh_with(
                |args| {
                    assert_eq!(args, ["show", "--property=LoadState", "sshd.service"]);
                    Ok(output(0, "LoadState=loaded\n", ""))
                },
                |unit| {
                    assert_eq!(unit, "sshd.service");
                    Ok(status)
                },
            );
            let err = result.unwrap_err().to_string();
            assert!(err.contains("sshd.service"));
            assert!(err.contains(&status.describe()));
        }
    }

    #[test]
    fn missing_both_units_does_not_restart() {
        let mut queries = Vec::new();
        let result = restart_ssh_with(
            |args| {
                queries.push(args.join(" "));
                Ok(output(1, "LoadState=not-found\n", ""))
            },
            |_| panic!("must not restart missing services"),
        );
        assert!(result.is_err());
        assert_eq!(
            queries,
            [
                "show --property=LoadState sshd.service",
                "show --property=LoadState ssh.service"
            ]
        );
    }

    #[test]
    fn invalid_or_unavailable_load_state_never_falls_back() {
        for (code, state) in [
            (0, "LoadState=masked"),
            (0, "LoadState=error"),
            (0, ""),
            (1, "LoadState=loaded"),
        ] {
            let result = restart_ssh_with(
                |args| {
                    assert_eq!(args, ["show", "--property=LoadState", "sshd.service"]);
                    Ok(output(code, state, "load error"))
                },
                |_| panic!("must not restart unavailable service"),
            );
            let err = result.unwrap_err().to_string();
            assert!(err.contains("load error"));
            assert!(err.contains("sshd.service"));
        }
        let result = restart_ssh_with(
            |args| {
                assert_eq!(args, ["show", "--property=LoadState", "sshd.service"]);
                Err(std::io::Error::other("cannot start systemctl"))
            },
            |_| panic!("must not restart without a unit"),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot start systemctl")
        );
    }

    #[test]
    fn failed_status_query_is_not_success() {
        let result = restart_ssh_with(
            |args| match args {
                ["show", "--property=LoadState", "sshd.service"] => {
                    Ok(output(0, "LoadState=loaded\n", ""))
                },
                ["is-active", "sshd.service"] => Err(std::io::Error::other("status unavailable")),
                _ => panic!("unexpected command {args:?}"),
            },
            |_| Ok(StreamStatus::Success),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("status unavailable")
        );
    }
}
