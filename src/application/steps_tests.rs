use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;
use crate::domain::steps::StepOutcome;

struct Fixture {
    dir: tempfile::TempDir,
    bin: PathBuf,
}

impl Fixture {
    fn new(step: &str, mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(dir.path().join("cron")).unwrap();
        fs::write(dir.path().join("config"), "ORIGINAL CONFIG\n").unwrap();
        fs::write(dir.path().join("database"), "READY DATABASE").unwrap();
        let fixture = Self { dir, bin };
        fixture.script("which", "[ -f \"$FIXTURE_BIN/$1.available\" ]");
        for pm in ["apt", "yum", "dnf"] {
            fixture.script(
                pm,
                r#"case " $* " in
  *" update "*) [ "$FIXTURE_MODE" != update-fails ] || exit 9 ;;
  *" upgrade "*) [ "$FIXTURE_MODE" != upgrade-fails ] || exit 8 ;;
  *" install "*)
    [ "$FIXTURE_MODE" != install-fails ] || exit 7
    [ "$FIXTURE_MODE" != unverified ] || exit 0
    for package do :; done
    case "$package" in
      fail2ban) binary=fail2ban-server ;;
      unattended-upgrades) binary=unattended-upgrade ;;
      *) binary=$package ;;
    esac
    : > "$FIXTURE_BIN/$binary.available"
    ;;
esac
exit 0"#,
            );
        }
        fixture.script(
            "systemctl",
            r#"case "$1" in
  show)
    [ "$FIXTURE_MODE" != no-service ] || { echo LoadState=not-found; exit 4; }
    echo LoadState=loaded ;;
  is-active)
    [ "$FIXTURE_MODE" != inactive ] || { echo inactive; exit 3; }
    echo active ;;
  is-enabled)
    [ "$FIXTURE_MODE" = timer ] || exit 1
    echo enabled ;;
  enable|restart)
    [ "$FIXTURE_MODE" != service-fails ] || { echo SERVICE_FAILURE >&2; exit 6; } ;;
esac"#,
        );
        fixture.script("dpkg-query", "exit 1");
        fixture.script("rpm", "exit 1");
        fixture.script("getent", "echo sudo:x:27:");
        fixture.script("sshd", r#"[ "$FIXTURE_MODE" != syntax-fails ] || { echo BAD_SYNTAX >&2; exit 5; }
printf 'port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\n'"#);
        fixture.script(
            "lynis",
            r#"[ "$FIXTURE_MODE" != scan-fails ] || exit 6
while [ "$#" -gt 0 ]; do
  case "$1" in
    --logfile) shift; printf 'AUDIT LOG\n' > "$1" ;;
    --report-file)
      shift
      if [ "$FIXTURE_MODE" != no-report ]; then
        printf 'hardening_index=81\nwarning[]=one\nsuggestion[]=two\n' > "$1"
      fi ;;
  esac
  shift
done
[ "$FIXTURE_MODE" != warnings ] || exit 78
exit 0"#,
        );
        fixture.script(
            "logwatch",
            "[ \"$FIXTURE_MODE\" != report-fails ] || exit 6\nprintf 'DAILY REPORT\\n'",
        );
        fixture.available(match mode {
            "yum" => "yum",
            "dnf" => "dnf",
            "unknown" => "nothing",
            _ => "apt",
        });
        let installed = !matches!(mode, "unknown" | "install-fails" | "unverified" | "install");
        if installed {
            match step {
                "fail2ban" => fixture.available("fail2ban-server"),
                "auto" => fixture.available("unattended-upgrade"),
                "scan" => fixture.available("lynis"),
                "audit" => {
                    fixture.available("logwatch");
                    fixture.available("aide");
                },
                _ => {},
            }
        }
        if mode == "existing-cron" {
            fs::write(fixture.root().join("cron/00logwatch"), "DISTRO").unwrap();
            fs::write(fixture.root().join("cron/aide"), "DISTRO").unwrap();
        } else if mode == "backup-cron" {
            for name in ["99u2secure-logwatch", "99u2secure-aide"] {
                fs::write(fixture.root().join("cron").join(name), "OLD CRON").unwrap();
            }
        }
        if mode == "spawn-fails" {
            fs::remove_file(fixture.bin.join("sshd")).unwrap();
        }
        fixture
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn available(&self, name: &str) {
        fs::write(self.bin.join(format!("{name}.available")), "").unwrap();
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.bin.join(name);
        fs::write(&path, format!("#!/bin/sh\nprintf '%s|%s|%s\\n' '{name}' \"${{DEBIAN_FRONTEND:-}}\" \"$*\" >> \"$FIXTURE_ROOT/calls\"\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn run(&self, step: &str, mode: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "application::steps::tests::isolated_step_child",
                "--nocapture",
            ])
            .env("PATH", &self.bin)
            .env("FIXTURE_BIN", &self.bin)
            .env("FIXTURE_ROOT", self.root())
            .env("FIXTURE_STEP", step)
            .env("FIXTURE_MODE", mode)
            .env_remove("DEBIAN_FRONTEND")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{step}/{mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn scenarios(step: &str, modes: &[&str]) {
    for mode in modes {
        Fixture::new(step, mode).run(step, mode);
    }
}

#[test]
fn update_checks_each_command_and_package_manager_environment() {
    scenarios(
        "update",
        &[
            "unknown",
            "ok",
            "yum",
            "dnf",
            "update-fails",
            "upgrade-fails",
        ],
    );
}

#[test]
fn services_verify_installation_write_backups_and_report_failures() {
    for step in ["fail2ban", "auto"] {
        scenarios(
            step,
            &[
                "unknown",
                "install-fails",
                "unverified",
                "install",
                "ok",
                "service-fails",
                "write-fails",
            ],
        );
    }
    scenarios("auto", &["yum"]);
}

#[test]
fn security_scan_preserves_reports_and_accepts_warning_exit() {
    scenarios(
        "scan",
        &[
            "unknown",
            "install-fails",
            "unverified",
            "install",
            "ok",
            "warnings",
            "scan-fails",
            "no-report",
        ],
    );
}

#[test]
fn log_audit_reports_partial_failures_and_preserves_daily_jobs() {
    scenarios(
        "audit",
        &[
            "unknown",
            "install-fails",
            "unverified",
            "install",
            "ok",
            "report-fails",
            "config-fails",
            "existing-cron",
            "backup-cron",
            "timer",
        ],
    );
}

#[test]
fn restart_reports_syntax_service_and_activation_outcomes() {
    scenarios(
        "restart",
        &[
            "unauthorized",
            "syntax-fails",
            "spawn-fails",
            "no-service",
            "service-fails",
            "inactive",
            "cancelled",
            "ok",
        ],
    );
}

#[test]
fn missing_inputs_fail_before_system_changes() {
    scenarios("preconditions", &["ok"]);
}

#[test]
fn isolated_step_child() {
    let Ok(step) = std::env::var("FIXTURE_STEP") else {
        return;
    };
    let mode = std::env::var("FIXTURE_MODE").unwrap();
    let root = PathBuf::from(std::env::var_os("FIXTURE_ROOT").unwrap());
    let params = ExecuteParams {
        report_dir: Some(root.display().to_string()),
        live_log: Some(root.join("live.log").display().to_string()),
        apply_ssh_changes: mode != "unauthorized",
        ssh_restart_required: true,
        ..Default::default()
    };
    match step.as_str() {
        "update" => check_update(&params, &root, &mode),
        "fail2ban" | "auto" => check_service(&step, &params, &root, &mode),
        "scan" => check_scan(&params, &root, &mode),
        "audit" => check_audit(&params, &root, &mode),
        "restart" => check_restart(&params, &mode),
        "preconditions" => check_preconditions(),
        _ => panic!("unknown fixture"),
    }
    assert!(rollback::undo_all().is_empty());
}

fn check_update(params: &ExecuteParams, root: &Path, mode: &str) {
    let result = SystemUpdateStep.execute(params).unwrap();
    let calls = fs::read_to_string(root.join("calls")).unwrap();
    if mode == "unknown" {
        assert_eq!(result.outcome, StepOutcome::Skipped);
        assert!(result.artifacts.is_empty());
        return;
    }
    assert_eq!(result.is_failed(), mode.ends_with("fails"));
    assert_eq!(result.artifacts, vec![params.live_log.clone().unwrap()]);
    assert_eq!(calls.contains("|upgrade "), mode != "update-fails");
    if matches!(mode, "yum" | "dnf") {
        assert!(!calls.contains("noninteractive"));
    } else {
        assert!(calls.contains("apt|noninteractive|-o APT::Update::Error-Mode=any update"));
    }
    if result.is_failed() {
        assert!(result.message.contains(params.live_log.as_ref().unwrap()));
    }
}

fn check_service(step: &str, params: &ExecuteParams, root: &Path, mode: &str) {
    let config = if mode == "write-fails" {
        root.join("missing/config")
    } else {
        root.join("config")
    };
    let result = if step == "auto" {
        AutoUpdatesStep.execute_at(params, config.to_str().unwrap())
    } else {
        Fail2banStep.execute_at(params, &config)
    };
    if mode == "write-fails" {
        assert!(result.is_err());
        return;
    }
    let result = result.unwrap();
    let expected = match mode {
        "unknown" | "yum" => StepOutcome::Skipped,
        "install-fails" | "unverified" | "service-fails" => StepOutcome::Failed,
        _ => StepOutcome::Changed,
    };
    assert_eq!(result.outcome, expected);
    let configured = matches!(mode, "install" | "ok" | "service-fails");
    if configured {
        let content = fs::read_to_string(&config).unwrap();
        assert!(content.contains(if step == "auto" {
            "APT::Periodic::Unattended-Upgrade \"1\";"
        } else {
            "[sshd]\nenabled = true\nport = "
        }));
        assert!(rollback::undo_depth() > 0);
        assert!(rollback::undo_all().is_empty());
    }
    assert_eq!(fs::read_to_string(&config).unwrap(), "ORIGINAL CONFIG\n");
    let calls = fs::read_to_string(root.join("calls")).unwrap();
    assert_eq!(calls.contains("systemctl||enable --now"), configured);
}

fn check_scan(params: &ExecuteParams, root: &Path, mode: &str) {
    let result = SecurityScanStep.execute(params).unwrap();
    match mode {
        "unknown" => assert_eq!(result.outcome, StepOutcome::Skipped),
        "install-fails" | "unverified" | "scan-fails" => assert!(result.is_failed()),
        _ => {
            assert!(result.is_changed());
            assert_eq!(result.artifacts.len(), 3);
            assert!(
                result
                    .artifacts
                    .iter()
                    .all(|p| Path::new(p).starts_with(root))
            );
            if mode != "no-report" {
                assert!(result.message.contains("81"));
                assert_eq!(
                    fs::metadata(&result.artifacts[2])
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            } else {
                assert!(result.message.contains('?'));
            }
        },
    }
    if mode == "scan-fails" {
        assert_eq!(result.artifacts.len(), 3);
        assert!(result.message.contains(params.live_log.as_ref().unwrap()));
    }
}

fn check_audit(params: &ExecuteParams, root: &Path, mode: &str) {
    let cron = root.join("cron");
    let result = LogAuditStep
        .execute_with(
            params,
            &cron,
            |_, _| {
                if mode == "config-fails" {
                    return Err("CONFIG_RESOLUTION_FAILED".into());
                }
                Ok(aide::AidePlan {
                    source: "fixture",
                    config: Some(root.join("config")),
                    database_in: root.join("database"),
                    database_out: root.join("database.new"),
                })
            },
            |cron| aide_check_scheduled_at(cron, &root.join("vendor-cron")),
        )
        .unwrap();
    if mode == "unknown" {
        assert_eq!(result.outcome, StepOutcome::Skipped);
        return;
    }
    assert_eq!(
        result.is_failed(),
        matches!(
            mode,
            "install-fails" | "unverified" | "report-fails" | "config-fails"
        )
    );
    assert!(
        result
            .artifacts
            .iter()
            .all(|p| Path::new(p).starts_with(root))
    );
    if mode == "existing-cron" {
        assert_eq!(
            fs::read_to_string(cron.join("00logwatch")).unwrap(),
            "DISTRO"
        );
        assert!(!cron.join("99u2secure-logwatch").exists());
        assert!(!cron.join("99u2secure-aide").exists());
    }
    if mode == "config-fails" {
        assert!(result.message.contains("CONFIG_RESOLUTION_FAILED"));
    }
    if mode == "timer" {
        assert!(!cron.join("99u2secure-aide").exists());
    }
    if mode == "ok" {
        for name in ["99u2secure-logwatch", "99u2secure-aide"] {
            assert_eq!(
                fs::metadata(cron.join(name)).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert!(result.message.contains("database"));
    }
    assert!(rollback::undo_all().is_empty());
    if mode == "backup-cron" {
        for name in ["99u2secure-logwatch", "99u2secure-aide"] {
            assert_eq!(fs::read_to_string(cron.join(name)).unwrap(), "OLD CRON");
        }
    }
}

fn check_restart(params: &ExecuteParams, mode: &str) {
    rollback::INTERRUPTED.store(mode == "cancelled", std::sync::atomic::Ordering::SeqCst);
    let result = RestartSshStep.execute(params);
    rollback::INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
    if matches!(mode, "syntax-fails" | "spawn-fails") {
        let error = result.unwrap_err().to_string();
        if mode == "syntax-fails" {
            assert!(error.contains("BAD_SYNTAX"));
        }
        return;
    }
    let result = result.unwrap();
    assert_eq!(result.is_changed(), mode == "ok");
    assert_eq!(
        result.ssh_activation_attempted,
        matches!(mode, "ok" | "service-fails" | "inactive")
    );
    assert_eq!(result.is_failed(), !matches!(mode, "ok" | "unauthorized"));
}

fn check_preconditions() {
    let empty = ExecuteParams::default();
    for kind in [
        StepKind::UserCreation,
        StepKind::SshPortChange,
        StepKind::SshKeySetup,
        StepKind::SshRootLogin,
        StepKind::SshPasswordAuth,
    ] {
        assert!(matches!(
            step_for(kind).execute(&empty),
            Err(DomainError::PreconditionFailed(_))
        ));
    }
    assert!(
        SshPortChangeStep
            .execute(&ExecuteParams {
                new_ssh_port: Some(0),
                ..Default::default()
            })
            .is_err()
    );
    assert!(
        SshKeySetupStep
            .execute(&ExecuteParams {
                ssh_key_username: Some("fixture".into()),
                ..Default::default()
            })
            .is_err()
    );
}
