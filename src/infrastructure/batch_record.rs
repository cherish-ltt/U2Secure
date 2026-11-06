use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::Serialize;

use crate::domain::errors::DomainError;
use crate::domain::steps::{StepKind, StepOutcome, StepResult};

thread_local! {
    static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct Trace {
    step: Option<usize>,
    undo: Option<usize>,
    rollback_order: usize,
    mirror_log: Option<PathReference>,
    backups: Vec<BackupRecord>,
    undo_actions: Vec<UndoRecord>,
}

#[derive(Serialize)]
struct BackupRecord {
    sequence: usize,
    step: Option<usize>,
    original_path: PathBuf,
    backup_path: Option<PathBuf>,
    original_state: &'static str,
    creation: &'static str,
    capture_error: Option<String>,
    undo_sequence: Option<usize>,
    restore: &'static str,
    restore_error: Option<String>,
    cleanup: &'static str,
    cleanup_error: Option<String>,
    retention: &'static str,
}

#[derive(Serialize)]
struct UndoRecord {
    sequence: usize,
    step: Option<usize>,
    kind: &'static str,
    outcome: &'static str,
    error_class: Option<&'static str>,
    rollback_order: Option<usize>,
}

#[derive(Serialize)]
struct StepRecord {
    order: usize,
    id: &'static str,
    execution: &'static str,
    outcome: Option<&'static str>,
    reported_outcome: Option<&'static str>,
    final_disposition: &'static str,
    ssh_restart_required: bool,
    ssh_activation_attempted: bool,
    live_log: Option<PathReference>,
    artifacts: Vec<PathReference>,
}

#[derive(Serialize)]
struct PathReference {
    path: String,
    may_be_shared: bool,
}

impl PathReference {
    fn new(path: String) -> Self {
        Self {
            path,
            may_be_shared: true,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct BatchRecord {
    schema_version: u8,
    batch_id: String,
    started_at: String,
    finished_at: Option<String>,
    pub status: &'static str,
    pub disposition: &'static str,
    pub ssh_activation_attempted: bool,
    scope: [&'static str; 4],
    log: PathReference,
    mirror_log: Option<PathReference>,
    steps: Vec<StepRecord>,
    backups: Vec<BackupRecord>,
    undo_actions: Vec<UndoRecord>,
}

impl BatchRecord {
    pub fn begin(plan: impl Iterator<Item = StepKind>, log: &str) -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let started = Utc::now();
        TRACE.with(|trace| *trace.borrow_mut() = Some(Trace::default()));
        Self {
            schema_version: 1,
            batch_id: format!(
                "{}-{}-{}",
                started.format("%Y%m%dT%H%M%S%.9fZ"),
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            started_at: started.to_rfc3339(),
            finished_at: None,
            status: "completed",
            disposition: "retained",
            ssh_activation_attempted: false,
            scope: [
                "only_registered_undo_results; other_system_changes_unknown",
                "step_outcomes_are_original_results_not_final_system_state",
                "path_references_may_be_shared_and_are_not_archived",
                "backup_retention_is_observed_at_batch_finish_not_a_restore_guarantee",
            ],
            log: PathReference::new(log.into()),
            mirror_log: None,
            steps: plan
                .enumerate()
                .map(|(index, kind)| StepRecord {
                    order: index + 1,
                    id: kind.slug(),
                    execution: "not_executed",
                    outcome: None,
                    reported_outcome: None,
                    final_disposition: "not_executed",
                    ssh_restart_required: false,
                    ssh_activation_attempted: false,
                    live_log: None,
                    artifacts: vec![],
                })
                .collect(),
            backups: vec![],
            undo_actions: vec![],
        }
    }

    pub fn step_started(&mut self, index: usize, live_log: &str) {
        TRACE.with_borrow_mut(|trace| {
            if let Some(trace) = trace {
                trace.step = Some(index + 1);
            }
        });
        self.steps[index].live_log = Some(PathReference::new(live_log.into()));
    }

    pub fn step_returned(&mut self, index: usize, result: &StepResult, execution: &'static str) {
        let step = &mut self.steps[index];
        step.execution = execution;
        step.outcome = (execution != "returned_error").then(|| outcome(result.outcome));
        step.ssh_restart_required = result.ssh_restart_required;
        step.ssh_activation_attempted = result.ssh_activation_attempted;
        step.artifacts = result
            .artifacts
            .iter()
            .cloned()
            .map(PathReference::new)
            .collect();
    }

    pub fn step_reported(&mut self, index: usize, result: &StepResult) {
        self.steps[index].reported_outcome = Some(outcome(result.outcome));
    }

    pub fn finish(mut self, directory: &Path) -> io::Result<PathBuf> {
        if let Some(trace) = TRACE.with(|trace| trace.borrow_mut().take()) {
            self.mirror_log = trace.mirror_log;
            self.backups = trace.backups;
            self.undo_actions = trace.undo_actions;
        }
        for backup in &mut self.backups {
            backup.retention = match &backup.backup_path {
                None => "no_backup",
                Some(path) => match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_file() => "present",
                    Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
                    _ => "unknown",
                },
            };
        }
        for step in &mut self.steps {
            if step.execution != "not_executed" {
                step.final_disposition = if self
                    .undo_actions
                    .iter()
                    .any(|undo| undo.step == Some(step.order) && undo.rollback_order.is_some())
                {
                    "registered_undo_attempted_other_changes_unknown"
                } else if step.outcome == Some("skipped") {
                    "no_change_reported"
                } else if self.disposition == "registered_undo_attempted_other_changes_unknown"
                    || step.outcome == Some("failed")
                    || step.execution == "returned_error"
                {
                    "unknown_partial_changes"
                } else {
                    self.disposition
                };
            }
        }
        self.finished_at = Some(Utc::now().to_rfc3339());
        self.save(directory)
    }

    fn save(&self, directory: &Path) -> io::Result<PathBuf> {
        self.save_with(
            directory,
            |temporary| {
                write_document(temporary, self)?;
                temporary.as_file().sync_all()
            },
            |path| File::open(path)?.sync_all(),
        )
    }

    fn save_with(
        &self,
        directory: &Path,
        write_and_sync: impl FnOnce(&mut tempfile::NamedTempFile) -> io::Result<()>,
        sync_directory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<PathBuf> {
        let mut temporary = tempfile::Builder::new()
            .prefix(".batch-")
            .tempfile_in(directory)?;
        write_and_sync(&mut temporary)?;
        let path = directory.join(format!("batch-{}.json", self.batch_id));
        temporary
            .persist_noclobber(&path)
            .map_err(|error| error.error)?;
        sync_directory(directory)?;
        Ok(path)
    }
}

impl Drop for BatchRecord {
    fn drop(&mut self) {
        TRACE.with(|trace| trace.borrow_mut().take());
    }
}

fn write_document(writer: &mut impl Write, record: &BatchRecord) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn outcome(value: StepOutcome) -> &'static str {
    match value {
        StepOutcome::Changed => "changed",
        StepOutcome::Skipped => "skipped",
        StepOutcome::Failed => "failed",
    }
}

pub(crate) fn mirror_log(path: &str) {
    TRACE.with_borrow_mut(|trace| {
        if let Some(trace) = trace {
            trace.mirror_log = Some(PathReference::new(path.into()));
        }
    });
}

pub(crate) fn backup_captured(original: &Path, result: &io::Result<Option<PathBuf>>) {
    TRACE.with_borrow_mut(|trace| {
        let Some(trace) = trace else { return };
        let (saved, original_state, creation, error) = match result {
            Ok(Some(saved)) => (Some(saved.clone()), "present", "created", None),
            Ok(None) => (None, "absent", "not_needed", None),
            Err(error) => (
                None,
                "unknown",
                "failed",
                Some(format!("{:?}", error.kind())),
            ),
        };
        trace.backups.push(BackupRecord {
            sequence: trace.backups.len() + 1,
            step: trace.step,
            original_path: original.into(),
            backup_path: saved,
            original_state,
            creation,
            capture_error: error,
            undo_sequence: None,
            restore: "not_attempted",
            restore_error: None,
            cleanup: "not_attempted",
            cleanup_error: None,
            retention: "unknown",
        });
    });
}

pub(crate) fn undo_registered(
    kind: &'static str,
    paths: &[(PathBuf, Option<PathBuf>)],
) -> Option<usize> {
    TRACE.with_borrow_mut(|trace| {
        let trace = trace.as_mut()?;
        let sequence = trace.undo_actions.len() + 1;
        trace.undo_actions.push(UndoRecord {
            sequence,
            step: trace.step,
            kind,
            outcome: "not_executed",
            error_class: None,
            rollback_order: None,
        });
        for (original, saved) in paths {
            if let Some(backup) = trace.backups.iter_mut().rev().find(|backup| {
                backup.original_path == *original
                    && backup.backup_path == *saved
                    && backup.undo_sequence.is_none()
            }) {
                backup.undo_sequence = Some(sequence);
            } else {
                trace.backups.push(BackupRecord {
                    sequence: trace.backups.len() + 1,
                    step: trace.step,
                    original_path: original.clone(),
                    backup_path: saved.clone(),
                    original_state: "unknown",
                    creation: "registered_existing",
                    capture_error: None,
                    undo_sequence: Some(sequence),
                    restore: "not_attempted",
                    restore_error: None,
                    cleanup: "not_attempted",
                    cleanup_error: None,
                    retention: "unknown",
                });
            }
        }
        Some(sequence)
    })
}

pub(crate) fn undo_started(sequence: Option<usize>) {
    TRACE.with_borrow_mut(|trace| {
        let Some(trace) = trace else { return };
        trace.undo = sequence;
        if let Some(sequence) = sequence {
            trace.rollback_order += 1;
            trace.undo_actions[sequence - 1].rollback_order = Some(trace.rollback_order);
        }
    });
}

pub(crate) fn undo_finished(sequence: Option<usize>, result: Option<&Result<(), DomainError>>) {
    TRACE.with_borrow_mut(|trace| {
        let Some(trace) = trace else { return };
        let Some(sequence) = sequence else { return };
        let record = &mut trace.undo_actions[sequence - 1];
        record.outcome = match result {
            None => "discarded_without_execution",
            Some(Ok(())) => "returned_ok",
            Some(Err(error)) => {
                record.error_class = Some(match error {
                    DomainError::PermissionDenied => "permission_denied",
                    DomainError::SystemCommandFailed(_) => "system_command_failed",
                    DomainError::AuditFailed(_) => "audit_failed",
                    DomainError::CommandUnavailable(_) => "command_unavailable",
                    DomainError::ParseError(_) => "parse_error",
                    DomainError::PreconditionFailed(_) => "precondition_failed",
                    DomainError::UserAborted => "user_aborted",
                });
                "returned_error"
            },
        };
        trace.undo = None;
    });
}

pub(crate) fn backup_restored(original: &Path, saved: Option<&Path>, result: &io::Result<()>) {
    update_backup(original, saved, |backup| match result {
        Ok(()) => backup.restore = "restored",
        Err(error) => {
            backup.restore = "failed";
            backup.restore_error = Some(format!("{:?}", error.kind()));
        },
    });
}

pub(crate) fn backup_unchanged(original: &Path, saved: Option<&Path>) {
    update_backup(original, saved, |backup| backup.restore = "already_matched");
}

pub(crate) fn backup_cleaned(original: &Path, saved: Option<&Path>, result: &io::Result<()>) {
    update_backup(original, saved, |backup| match result {
        Ok(()) => {
            backup.cleanup = if saved.is_some() {
                "removed"
            } else {
                "not_applicable"
            }
        },
        Err(error) => {
            backup.cleanup = "failed";
            backup.cleanup_error = Some(format!("{:?}", error.kind()));
        },
    });
}

fn update_backup(original: &Path, saved: Option<&Path>, update: impl FnOnce(&mut BackupRecord)) {
    TRACE.with_borrow_mut(|trace| {
        let Some(trace) = trace else { return };
        if let Some(backup) = trace.backups.iter_mut().find(|backup| {
            backup.original_path == original
                && backup.backup_path.as_deref() == saved
                && backup.undo_sequence == trace.undo
        }) {
            update(backup);
        }
    });
}

#[cfg(test)]
#[path = "batch_record_tests.rs"]
mod tests;
