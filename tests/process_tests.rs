#![cfg(unix)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use u2secure::infrastructure::rollback::INTERRUPTED;
use u2secure::infrastructure::system::{StreamStatus, run_streaming_watchdog};

static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn watchdog_stops_descendants_without_touching_other_tasks() {
    let _guard = PROCESS_TEST.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let unrelated = dir.path().join("unrelated");
    let mut other = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 0.5; printf ok > \"$1\"", "test"])
        .arg(&unrelated)
        .spawn()
        .unwrap();
    let mut survivors = Vec::new();
    for expected in [
        StreamStatus::TimedOut,
        StreamStatus::Cancelled,
        StreamStatus::NoResponse,
    ] {
        let marker = dir.path().join(format!("{expected:?}"));
        let argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "(sleep 0.6; printf survived > \"$1\") & wait".into(),
            "test".into(),
            marker.display().to_string(),
        ];
        let cancel = (expected == StreamStatus::Cancelled).then(|| {
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(250));
                INTERRUPTED.store(true, Ordering::SeqCst);
            })
        });
        let status = run_streaming_watchdog(
            &argv,
            &[],
            &dir.path().join("command.log").display().to_string(),
            if expected == StreamStatus::TimedOut {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(5)
            },
            (expected == StreamStatus::NoResponse).then_some(Duration::from_millis(100)),
        );
        if let Some(cancel) = cancel {
            cancel.join().unwrap();
        }
        INTERRUPTED.store(false, Ordering::SeqCst);
        assert_eq!(status.unwrap(), expected);
        std::thread::sleep(Duration::from_millis(800));
        if marker.exists() {
            survivors.push(expected);
        }
    }
    assert!(other.wait().unwrap().success());
    assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "ok");
    assert!(survivors.is_empty(), "descendants survived: {survivors:?}");
}

#[test]
fn streaming_preserves_output_and_exit_status() {
    let _guard = PROCESS_TEST.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (script, expected) in [
        ("printf complete", StreamStatus::Success),
        ("printf failed >&2; exit 17", StreamStatus::Failed(Some(17))),
    ] {
        let log = dir.path().join("command.log");
        let status = run_streaming_watchdog(
            &["/bin/sh".into(), "-c".into(), script.into()],
            &[],
            log.to_str().unwrap(),
            Duration::from_secs(5),
            None,
        )
        .unwrap();
        assert_eq!(status, expected);
        assert!(
            std::fs::read_to_string(log)
                .unwrap()
                .contains(if expected.is_success() {
                    "complete"
                } else {
                    "failed"
                })
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn leader_exit_does_not_leave_background_writers() {
    let _guard = PROCESS_TEST.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("background");
    let status = run_streaming_watchdog(
        &[
            "/bin/sh".into(),
            "-c".into(),
            "(sleep 0.6; printf bad > \"$1\") & exit 0".into(),
            "test".into(),
            marker.display().to_string(),
        ],
        &[],
        dir.path().join("log").to_str().unwrap(),
        Duration::from_secs(5),
        None,
    )
    .unwrap();
    assert_eq!(status, StreamStatus::Success);
    std::thread::sleep(Duration::from_millis(800));
    assert!(!marker.exists());
}
