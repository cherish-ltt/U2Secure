use std::process::{Command, Output};
use std::time::Duration;

use crate::domain::errors::DomainError;

#[cfg(unix)]
const OUTPUT_LIMIT: usize = 1024 * 1024;

#[cfg(unix)]
pub(crate) fn output(command: &mut Command, timeout: Duration) -> Result<Output, DomainError> {
    use std::os::fd::AsFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    use super::rollback::INTERRUPTED;
    use super::system::{command_status, stop_command};

    let program = command.get_program().to_string_lossy().into_owned();
    let cancelled = || {
        DomainError::AuditFailed(crate::i18n::tr("capture_cancel").replace("{program}", &program))
    };
    if INTERRUPTED.load(Ordering::SeqCst) {
        return Err(cancelled());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DomainError::CommandUnavailable(program.clone())
            } else {
                capture_error("capture_spawn", &program, error)
            }
        })?;
    let mut status = None;
    let result = (|| {
        let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take())
        else {
            return Err(DomainError::AuditFailed(
                crate::i18n::tr("capture_missing_pipe").into(),
            ));
        };
        for fd in [stdout.as_fd(), stderr.as_fd()] {
            fcntl_getfl(fd)
                .and_then(|flags| fcntl_setfl(fd, flags | OFlags::NONBLOCK))
                .map_err(|error| capture_error("capture_pipe", &program, error))?;
        }
        let started = Instant::now();
        let mut out = Vec::new();
        let mut err = Vec::new();
        loop {
            if INTERRUPTED.load(Ordering::SeqCst) {
                return Err(cancelled());
            }
            if started.elapsed() >= timeout {
                return Err(DomainError::AuditFailed(
                    crate::i18n::tr("capture_timeout").replace("{program}", &program),
                ));
            }
            let stdout_drained = read_available(&mut stdout, &mut out, err.len(), &program)?;
            let stderr_drained = read_available(&mut stderr, &mut err, out.len(), &program)?;
            if status.is_none() {
                status = command_status(&mut child)
                    .map_err(|error| capture_error("capture_wait", &program, error))?;
                if status.is_some() {
                    continue;
                }
            }
            if stdout_drained && stderr_drained {
                if let Some(status) = status {
                    // The leader is reaped; a detached pipe holder must not keep us waiting.
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    if let Err(error) = result {
        return match status.is_none().then(|| stop_command(&mut child)) {
            Some(Err(cleanup)) => Err(DomainError::AuditFailed(format!("{error}; {cleanup}"))),
            _ => Err(error),
        };
    }
    result
}

#[cfg(unix)]
fn read_available(
    pipe: &mut impl std::io::Read,
    bytes: &mut Vec<u8>,
    other_len: usize,
    program: &str,
) -> Result<bool, DomainError> {
    let mut buffer = [0; 8192];
    for _ in 0..8 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + other_len + count > OUTPUT_LIMIT {
                    return Err(DomainError::AuditFailed(
                        crate::i18n::tr("capture_limit")
                            .replace("{program}", program)
                            .replace("{limit}", &OUTPUT_LIMIT.to_string()),
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) => return Err(capture_error("capture_read", program, error)),
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn capture_error(key: &'static str, program: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::AuditFailed(
        crate::i18n::tr(key)
            .replace("{program}", program)
            .replace("{err}", &error.to_string()),
    )
}

#[cfg(not(unix))]
pub(crate) fn output(_command: &mut Command, _timeout: Duration) -> Result<Output, DomainError> {
    Err(DomainError::AuditFailed(
        crate::i18n::tr("capture_unsupported").into(),
    ))
}

#[cfg(all(test, unix))]
#[path = "capture_tests.rs"]
mod tests;
