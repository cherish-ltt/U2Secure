use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::domain::errors::DomainError;
use crate::domain::undo::UndoAction;
use crate::infrastructure::batch_record;

struct RegisteredUndo {
    action: UndoAction,
    sequence: Option<usize>,
}

/// 全局 undo 栈
static UNDO_STACK: LazyLock<Mutex<Vec<RegisteredUndo>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// 是否正在执行回退（防止重入）
pub static UNDO_RUNNING: AtomicBool = AtomicBool::new(false);

/// 用户是否按了 Ctrl+C
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// 初始化 Ctrl+C 信号处理器
///
/// 仅设置 INTERRUPTED 标记，不在此处执行回退。
/// 实际回退由 `StepRunner` 在检测到中断标记后触发，
/// 避免信号上下文的 Mutex 锁竞争和死锁风险。
///
/// 注册失败时返回错误由调用方处理（不 panic）。
pub fn init_signal_handler() -> Result<(), DomainError> {
    ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    })
    .map_err(|e| {
        DomainError::SystemCommandFailed(
            crate::i18n::tr("err_setup_signal").replace("{err}", &e.to_string()),
        )
    })
}

/// 注册一个撤销操作
pub fn register_undo(action: UndoAction) {
    register_tracked(action, "custom", &[]);
}

pub(crate) fn register_tracked(
    action: UndoAction,
    kind: &'static str,
    backups: &[(PathBuf, Option<PathBuf>)],
) {
    if let Ok(mut stack) = UNDO_STACK.lock() {
        let sequence = batch_record::undo_registered(kind, backups);
        stack.push(RegisteredUndo { action, sequence });
    }
}

/// 手动触发全部回退（用于步骤失败时）
pub fn undo_all() -> Vec<String> {
    undo_since(0)
}

pub(crate) fn discard_since(checkpoint: usize) {
    if let Ok(mut stack) = UNDO_STACK.lock() {
        for registered in stack.iter().skip(checkpoint) {
            batch_record::undo_finished(registered.sequence, None);
        }
        stack.truncate(checkpoint);
    }
}

pub(crate) fn undo_since(checkpoint: usize) -> Vec<String> {
    if UNDO_RUNNING.swap(true, Ordering::SeqCst) {
        return vec![]; // 防止重入
    }

    let actions = UNDO_STACK
        .lock()
        .map(|mut stack| stack.split_off(checkpoint))
        .map_err(|e| e.to_string());

    let mut failures = vec![];
    if let Ok(mut actions) = actions {
        actions.reverse();
        for registered in actions {
            let action = registered.action;
            eprintln!("  ⮐ {}", action.description);
            let description = action.description.clone();
            batch_record::undo_started(registered.sequence);
            let result = action.execute();
            batch_record::undo_finished(registered.sequence, Some(&result));
            if let Err(error) = result {
                let message = format!("{description}: {error}");
                eprintln!("{message}");
                failures.push(message);
            }
        }
    } else if let Err(error) = actions {
        failures.push(error);
    }

    // 重置标记，允许后续正常调用 undo_all
    UNDO_RUNNING.store(false, Ordering::SeqCst);
    failures
}

/// 获取当前 undo 栈深度（用于日志和测试）
#[allow(dead_code)]
pub fn undo_depth() -> usize {
    UNDO_STACK.lock().map(|s| s.len()).unwrap_or(0)
}

/// 注册文件备份撤销操作（备份 → 后续可恢复）
pub fn register_file_backup(description: String, backup_path: String, original_path: String) {
    let paths = [(
        PathBuf::from(&original_path),
        Some(PathBuf::from(&backup_path)),
    )];
    register_tracked(
        UndoAction::try_new(
            description,
            Box::new(move || {
                let result = std::fs::copy(&backup_path, &original_path).map(|_| ());
                batch_record::backup_restored(
                    Path::new(&original_path),
                    Some(Path::new(&backup_path)),
                    &result,
                );
                result.map_err(|e| {
                    DomainError::SystemCommandFailed(
                        crate::i18n::tr("err_restore_backup")
                            .replace("{backup}", &backup_path)
                            .replace("{path}", &original_path)
                            .replace("{err}", &e.to_string()),
                    )
                })?;
                let result = std::fs::remove_file(&backup_path);
                batch_record::backup_cleaned(
                    Path::new(&original_path),
                    Some(Path::new(&backup_path)),
                    &result,
                );
                result.map_err(|e| {
                    DomainError::SystemCommandFailed(
                        crate::i18n::tr("err_cleanup_backup")
                            .replace("{backup}", &backup_path)
                            .replace("{path}", &original_path)
                            .replace("{err}", &e.to_string()),
                    )
                })
            }),
        ),
        "file_restore",
        &paths,
    );
}

/// 注册包移除撤销操作
pub fn register_package_remove(description: String, package: String) {
    register_tracked(
        UndoAction::new(
            description,
            Box::new(move || {
                // 尝试 apt/yum/dnf remove
                for pm in &["apt", "yum", "dnf"] {
                    let _ = std::process::Command::new(pm)
                        .args(["remove", "-y", &package])
                        .output();
                }
            }),
        ),
        "package_remove_best_effort",
        &[],
    );
}

/// 注册用户删除撤销操作
pub fn register_user_remove(username: String) {
    register_tracked(
        UndoAction::try_new(
            crate::i18n::tr("undo_user_remove").replace("{user}", &username),
            Box::new(move || {
                let failure = |detail: String| {
                    DomainError::SystemCommandFailed(
                        crate::i18n::tr("err_user_remove")
                            .replace("{user}", &username)
                            .replace("{err}", &detail),
                    )
                };
                let output = std::process::Command::new("userdel")
                    .args(["-r", &username])
                    .output()
                    .map_err(|e| failure(e.to_string()))?;
                if !output.status.success() {
                    return Err(failure(format!(
                        "{}; {}{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                Ok(())
            }),
        ),
        "user_remove",
        &[],
    );
}

/// 注册命令执行撤销操作
pub fn register_command_undo(description: String, cmd: Vec<String>) {
    register_tracked(
        UndoAction::new(
            description,
            Box::new(move || {
                if cmd.len() > 1 {
                    let _ = std::process::Command::new(&cmd[0]).args(&cmd[1..]).output();
                }
            }),
        ),
        "command_best_effort",
        &[],
    );
}

#[cfg(all(test, unix))]
#[path = "rollback_tests.rs"]
mod tests;
