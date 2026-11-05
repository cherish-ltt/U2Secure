#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use u2secure::i18n::tr;

fn audit(args: &[&str], id_body: Option<&str>) -> (Output, bool) {
    let commands = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let marker = commands.path().join("id-called");
    if let Some(body) = id_body {
        let id = commands.path().join("id");
        fs::write(
            &id,
            format!("#!/bin/sh\nprintf called > \"$AUDIT_CLI_PROBE_LOG\"\n{body}\n"),
        )
        .unwrap();
        fs::set_permissions(id, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_u2secure"))
        .arg("audit")
        .args(args)
        .current_dir(working.path())
        .env("PATH", commands.path())
        .env("AUDIT_CLI_PROBE_LOG", &marker)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        fs::read_dir(working.path()).unwrap().count(),
        0,
        "audit created files in its working directory"
    );
    let called = marker.exists();
    assert_eq!(
        fs::read_dir(commands.path()).unwrap().count(),
        usize::from(id_body.is_some()) + usize::from(called),
        "audit created files beyond the injected command and marker"
    );
    (output, called)
}

#[test]
fn help_exits_without_collecting_or_creating_files() {
    for flag in ["-h", "--help"] {
        let (output, called) = audit(&[flag], Some("exit 17"));
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, tr("audit_usage").as_bytes());
        assert!(output.stderr.is_empty());
        assert!(!called);
    }
}

#[test]
fn invalid_arguments_exit_before_collection() {
    for args in [
        vec!["--format"],
        vec!["--format", "yaml"],
        vec!["--format", "json", "extra"],
        vec!["--format", "json", "--format", "text"],
        vec!["--help", "--format", "json"],
        vec!["unknown"],
    ] {
        let (output, called) = audit(&args, Some("exit 17"));
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(tr("audit_usage").trim()));
        assert!(!called, "{args:?}");
    }
}

#[test]
fn non_root_and_failed_uid_probes_emit_only_diagnostics() {
    for args in [vec![], vec!["--format", "json"]] {
        for body in [
            Some("printf '1000\\n'"),
            Some("printf PRIVATE_PROBE_OUTPUT >&2; exit 17"),
            Some("printf invalid-uid"),
            None,
        ] {
            let (output, called) = audit(&args, body);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(called, body.is_some());
            let diagnostic = String::from_utf8(output.stderr).unwrap();
            if body == Some("printf '1000\\n'") {
                assert!(diagnostic.contains(tr("err_permission_denied")));
            } else {
                assert!(diagnostic.contains(&tr("audit_probe_failed").replace("{program}", "id")));
            }
            assert!(!diagnostic.contains("PRIVATE_PROBE_OUTPUT"));
        }
    }
}
