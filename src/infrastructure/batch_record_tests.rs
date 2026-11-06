use super::*;

#[test]
fn write_and_flush_failures_never_return_a_successful_record() {
    struct BrokenWriter(bool);
    impl Write for BrokenWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("fixture-write"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fixture-flush"))
        }
    }
    let record = BatchRecord::begin([StepKind::SystemUpdate].into_iter(), "fixture.log");
    for flush in [false, true] {
        let error = write_document(&mut BrokenWriter(flush), &record).unwrap_err();
        assert!(error.to_string().contains(if flush {
            "fixture-flush"
        } else {
            "fixture-write"
        }));
    }
}

#[test]
fn publish_is_exclusive_and_keeps_existing_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let record = BatchRecord::begin([StepKind::Ufw].into_iter(), "fixture.log");
    let path = record.save(dir.path()).unwrap();
    let first = std::fs::read(&path).unwrap();
    assert!(record.save(dir.path()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), first);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn synchronization_failure_never_returns_a_published_success_path() {
    for file_sync in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let record = BatchRecord::begin([StepKind::Ufw].into_iter(), "fixture.log");
        let result = record.save_with(
            dir.path(),
            |temporary| {
                write_document(temporary, &record)?;
                if file_sync {
                    Err(io::Error::other("fixture-file-sync"))
                } else {
                    Ok(())
                }
            },
            |_| Err(io::Error::other("fixture-directory-sync")),
        );
        assert!(result.unwrap_err().to_string().contains(if file_sync {
            "fixture-file-sync"
        } else {
            "fixture-directory-sync"
        }));
        let paths: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        if file_sync {
            assert!(paths.is_empty());
        } else {
            assert_eq!(paths.len(), 1);
            let path = paths[0].as_ref().unwrap().path();
            assert_eq!(path.extension().unwrap(), "json");
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(saved["batch_id"], record.batch_id);
        }
    }
}

#[test]
fn restoration_cleanup_and_missing_backup_are_separate_facts() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("config");
    let saved = dir.path().join("saved");
    std::fs::write(&saved, "CONFIG_MUST_NOT_BE_ARCHIVED").unwrap();
    let record = BatchRecord::begin([StepKind::Ufw].into_iter(), "fixture.log");
    backup_captured(&original, &Ok(Some(saved.clone())));
    let sequence = undo_registered("file_restore", &[(original.clone(), Some(saved.clone()))]);
    undo_started(sequence);
    backup_restored(&original, Some(&saved), &Ok(()));
    backup_cleaned(
        &original,
        Some(&saved),
        &Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    undo_finished(
        sequence,
        Some(&Err(DomainError::SystemCommandFailed(
            "PRIVATE_OUTPUT".into(),
        ))),
    );
    let missing = dir.path().join("already-deleted");
    backup_captured(&original, &Ok(Some(missing)));
    let path = record.finish(dir.path()).unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_OUTPUT"));
    assert!(!String::from_utf8_lossy(&bytes).contains("CONFIG_MUST_NOT_BE_ARCHIVED"));
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["backups"][0]["restore"], "restored");
    assert_eq!(record["backups"][0]["cleanup"], "failed");
    assert_eq!(record["backups"][0]["retention"], "present");
    assert_eq!(record["backups"][1]["retention"], "missing");
    assert_eq!(record["undo_actions"][0]["outcome"], "returned_error");
}

#[test]
fn failed_and_absent_captures_do_not_invent_backups() {
    let dir = tempfile::tempdir().unwrap();
    let record = BatchRecord::begin([StepKind::Ufw].into_iter(), "fixture.log");
    backup_captured(&dir.path().join("absent"), &Ok(None));
    backup_captured(
        &dir.path().join("denied"),
        &Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    let path = record.finish(dir.path()).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(record["backups"][0]["original_state"], "absent");
    assert_eq!(record["backups"][0]["creation"], "not_needed");
    assert_eq!(record["backups"][1]["creation"], "failed");
    assert_eq!(record["backups"][1]["capture_error"], "PermissionDenied");
}
