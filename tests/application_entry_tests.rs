#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;

use u2secure::application::job::{JobEvent, StepRunner};
use u2secure::domain::mirror::PackageMirror;
use u2secure::domain::steps::{ExecuteParams, StepKind, StepOutcome};
use u2secure::infrastructure::logger::FileLogger;

#[test]
fn synchronous_and_background_entrypoints_keep_plan_order_and_mirror_logs() {
    let dir = tempfile::tempdir().unwrap();
    let which = dir.path().join("which");
    fs::write(&which, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(which, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_entry_child", "--nocapture"])
        .env("PATH", dir.path())
        .env("ENTRY_ROOT", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn isolated_entry_child() {
    let Ok(root) = std::env::var("ENTRY_ROOT") else {
        return;
    };
    let runner = || {
        StepRunner::new(Arc::new(FileLogger::with_path(format!("{root}/job.log"))))
            .with_report_dir(&root)
            .with_mirror(PackageMirror::Tsinghua)
    };
    let selected = [
        StepKind::RestartSsh,
        StepKind::SystemUpdate,
        StepKind::SystemUpdate,
    ];
    let mut events = vec![];
    let results = runner().run(&selected, &ExecuteParams::default(), &mut |event| {
        events.push(event)
    });
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].kind, StepKind::SystemUpdate);
    assert_eq!(results[1].kind, StepKind::RestartSsh);
    assert!(
        results
            .iter()
            .all(|result| result.outcome == StepOutcome::Skipped)
    );
    assert!(
        matches!(events.first(), Some(JobEvent::Log(message)) if message == u2secure::i18n::tr("mirror_not_applied"))
    );
    assert!(matches!(events.last(), Some(JobEvent::AllFinished)));
    let handle = runner().spawn(selected.to_vec(), ExecuteParams::default());
    assert_eq!(handle.total, 2);
    let events: Vec<_> = handle.rx.iter().collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, JobEvent::StepFinished(_)))
            .count(),
        2
    );
    assert!(handle.drain().is_empty());
    assert!(handle.is_disconnected());
    handle.join();
}
