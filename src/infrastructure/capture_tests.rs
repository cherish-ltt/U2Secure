use std::fs;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::*;
use crate::infrastructure::rollback::INTERRUPTED;

#[test]
fn capture_is_bounded_and_does_not_create_files() {
    for case in [
        "normal",
        "large",
        "timeout",
        "cancel",
        "limit",
        "leader-exit",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "infrastructure::capture::tests::isolated_capture_case",
                "--nocapture",
            ])
            .current_dir(dir.path())
            .env("PATH", dir.path())
            .env("U2SECURE_CAPTURE_CASE", case)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() >= Duration::from_secs(40) {
                let killed = child.kill();
                let waited = child.wait();
                panic!("{case}: isolated test timed out; kill={killed:?}, wait={waited:?}");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(status.success(), "{case}: {status}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0, "{case}");
    }
}

#[test]
fn isolated_capture_case() {
    let Ok(case) = std::env::var("U2SECURE_CAPTURE_CASE") else {
        return;
    };
    match case.as_str() {
        "normal" => {
            let result = output(
                Command::new("/bin/sh").args([
                    "-c",
                    "read value && exit 8; printf '%s' \"$1\"; printf error >&2; exit 7",
                    "fixture",
                    "two words",
                ]),
                Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(result.status.code(), Some(7));
            assert_eq!(result.stdout, b"two words");
            assert_eq!(result.stderr, b"error");
            assert!(matches!(
                output(&mut Command::new("missing-fixture"), Duration::from_secs(1)),
                Err(DomainError::CommandUnavailable(program)) if program == "missing-fixture"
            ));
            assert!(matches!(
                output(
                    &mut Command::new(std::env::current_dir().unwrap()),
                    Duration::from_secs(1),
                ),
                Err(DomainError::AuditFailed(_))
            ));
        },
        "large" => {
            let out = "o".repeat(16384);
            let err = "e".repeat(16384);
            for count in [16, 32, 33] {
                let result = output(
                    Command::new("/bin/sh").args([
                        "-c",
                        "i=0; while [ \"$i\" -lt \"$3\" ]; do printf '%s' \"$1\"; printf '%s' \"$2\" >&2; i=$((i + 1)); done",
                        "fixture",
                        &out,
                        &err,
                        &count.to_string(),
                    ]),
                    Duration::from_secs(10),
                );
                if count <= 32 {
                    let result = result.unwrap();
                    assert!(result.status.success());
                    assert_eq!(result.stdout, out.repeat(count).as_bytes());
                    assert_eq!(result.stderr, err.repeat(count).as_bytes());
                } else {
                    let expected = crate::i18n::tr("capture_limit")
                        .replace("{program}", "/bin/sh")
                        .replace("{limit}", &OUTPUT_LIMIT.to_string());
                    assert!(
                        matches!(result, Err(DomainError::AuditFailed(reason)) if reason == expected)
                    );
                }
            }
        },
        "timeout" | "cancel" | "limit" | "leader-exit" => {
            let marker = std::env::current_dir().unwrap().join("survived");
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                match case.as_str() {
                    "limit" => {
                        "(/bin/sleep 0.6; printf bad > \"$1\") & while :; do printf '%s' \"$2\"; printf '%s' \"$2\" >&2; done"
                    },
                    "leader-exit" => {
                        "(/bin/sleep 0.6; printf bad > \"$1\") & printf complete; exit 0"
                    },
                    _ => "(/bin/sleep 0.6; printf bad > \"$1\") & wait",
                },
                "fixture",
            ]);
            command.arg(&marker).arg("x".repeat(32768));
            let cancellation = (case == "cancel").then(|| {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(100));
                    INTERRUPTED.store(true, Ordering::SeqCst);
                })
            });
            let started = Instant::now();
            let result = output(
                &mut command,
                if case == "timeout" {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(5)
                },
            );
            if let Some(cancellation) = cancellation {
                cancellation.join().unwrap();
                assert!(matches!(
                    output(&mut Command::new("/bin/sh"), Duration::from_secs(1)),
                    Err(DomainError::AuditFailed(_))
                ));
                INTERRUPTED.store(false, Ordering::SeqCst);
            }
            if case == "leader-exit" {
                let result = result.unwrap();
                assert!(result.status.success());
                assert_eq!(result.stdout, b"complete");
            } else {
                let key = match case.as_str() {
                    "timeout" => "capture_timeout",
                    "cancel" => "capture_cancel",
                    _ => "capture_limit",
                };
                let expected = crate::i18n::tr(key)
                    .replace("{program}", "/bin/sh")
                    .replace("{limit}", &OUTPUT_LIMIT.to_string());
                assert!(
                    matches!(result, Err(DomainError::AuditFailed(reason)) if reason == expected)
                );
            }
            assert!(started.elapsed() < Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(800));
            assert!(!marker.exists(), "{case}: descendant survived capture");
        },
        _ => panic!("unknown capture fixture"),
    }
}

#[test]
fn interrupted_reads_do_not_mark_pipe_drained() {
    struct InterruptedPipe {
        interruptions: usize,
        remaining: &'static [u8],
    }
    impl std::io::Read for InterruptedPipe {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.interruptions > 0 {
                self.interruptions -= 1;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            std::io::Read::read(&mut self.remaining, bytes)
        }
    }
    let mut pipe = InterruptedPipe {
        interruptions: 8,
        remaining: b"remaining-output",
    };
    let mut bytes = Vec::new();
    assert!(!read_available(&mut pipe, &mut bytes, 0, "fixture").unwrap());
    assert!(bytes.is_empty());
    assert!(read_available(&mut pipe, &mut bytes, 0, "fixture").unwrap());
    assert_eq!(bytes, b"remaining-output");
}

#[test]
fn pipe_read_errors_are_reported_without_losing_captured_bytes() {
    struct BrokenPipe;
    impl std::io::Read for BrokenPipe {
        fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture-read-error"))
        }
    }
    let mut bytes = b"existing-output".to_vec();
    let expected = crate::i18n::tr("capture_read")
        .replace("{program}", "fixture")
        .replace("{err}", "fixture-read-error");
    assert!(matches!(
        read_available(&mut BrokenPipe, &mut bytes, 0, "fixture"),
        Err(DomainError::AuditFailed(reason)) if reason == expected
    ));
    assert_eq!(bytes, b"existing-output");
}
