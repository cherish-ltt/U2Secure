use super::*;

#[test]
fn mirror_failure_records_unexecuted_plan_without_changing_retry_events() {
    let dir = tempfile::tempdir().unwrap();
    let runner = StepRunner::new(Arc::new(FileLogger::with_path(dir.path().join("log"))))
        .with_report_dir(dir.path().display().to_string());
    let mut events = vec![];
    let results = runner.run_steps_with_prepare(
        select_steps(&[StepKind::SystemUpdate]),
        &ExecuteParams::default(),
        &mut |event| events.push(event),
        |_| {
            crate::infrastructure::batch_record::mirror_log("/fixture/mirror.log");
            Err("mirror fixture".into())
        },
    );
    assert!(results.is_empty());
    assert!(matches!(
        events.first(),
        Some(JobEvent::MirrorFailed { .. })
    ));
    assert!(matches!(events.last(), Some(JobEvent::AllFinished)));
    let path = events
        .iter()
        .find_map(|event| match event {
            JobEvent::BatchRecord { result: Ok(path) } => Some(path),
            _ => None,
        })
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(record["status"], "mirror_failed");
    assert_eq!(record["disposition"], "no_steps_executed");
    assert_eq!(record["steps"][0]["execution"], "not_executed");
    assert!(record["steps"][0]["outcome"].is_null());
    assert_eq!(record["mirror_log"]["path"], "/fixture/mirror.log");
    assert_eq!(record["mirror_log"]["may_be_shared"], true);
}
