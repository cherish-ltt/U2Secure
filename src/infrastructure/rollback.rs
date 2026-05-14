use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::domain::undo::UndoAction;

/// 全局 undo 栈
static UNDO_STACK: LazyLock<Mutex<Vec<UndoAction>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// 是否正在执行回退（防止重入）
pub static UNDO_RUNNING: AtomicBool = AtomicBool::new(false);

/// 用户是否按了 Ctrl+C
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// 初始化 Ctrl+C 信号处理器
///
/// 仅设置 INTERRUPTED 标记，不在此处执行回退。
/// 实际回退在主线程 `execute_steps` 循环中由业务逻辑触发，
/// 避免信号上下文的 Mutex 锁竞争和死锁风险。
pub fn init_signal_handler() {
    ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    })
    .expect("设置 Ctrl+C 处理器失败");
}

/// 注册一个撤销操作
pub fn register_undo(action: UndoAction) {
    if let Ok(mut stack) = UNDO_STACK.lock() {
        stack.push(action);
    }
}

/// 手动触发全部回退（用于步骤失败时）
pub fn undo_all() {
    if UNDO_RUNNING.swap(true, Ordering::SeqCst) {
        return; // 防止重入
    }

    let actions = UNDO_STACK
        .lock()
        .map(|mut stack| std::mem::take(&mut *stack))
        .ok();

    if let Some(mut actions) = actions {
        actions.reverse();
        for action in actions {
            eprintln!("  ⮐  回退: {}", action.description);
            action.execute();
        }
    }

    // 重置标记，允许后续正常调用 undo_all
    UNDO_RUNNING.store(false, Ordering::SeqCst);
}

/// 获取当前 undo 栈深度（用于日志和测试）
#[allow(dead_code)]
pub fn undo_depth() -> usize {
    UNDO_STACK.lock().map(|s| s.len()).unwrap_or(0)
}

/// 注册文件备份撤销操作（备份 → 后续可恢复）
pub fn register_file_backup(description: String, backup_path: String, original_path: String) {
    register_undo(UndoAction::new(
        description,
        Box::new(move || {
            let _ = std::fs::copy(&backup_path, &original_path);
            let _ = std::fs::remove_file(&backup_path);
        }),
    ));
}

/// 注册包移除撤销操作
pub fn register_package_remove(
    description: String,
    package: String,
) {
    register_undo(UndoAction::new(
        description,
        Box::new(move || {
            // 尝试 apt/yum/dnf remove
            for pm in &["apt", "yum", "dnf"] {
                let _ = std::process::Command::new(pm)
                    .args(["remove", "-y", &package])
                    .output();
            }
        }),
    ));
}

/// 注册用户删除撤销操作
pub fn register_user_remove(username: String) {
    register_undo(UndoAction::new(
        format!("删除用户 '{username}'"),
        Box::new(move || {
            let _ = std::process::Command::new("userdel")
                .args(["-r", &username])
                .output();
        }),
    ));
}

/// 注册命令执行撤销操作
pub fn register_command_undo(description: String, cmd: Vec<String>) {
    register_undo(UndoAction::new(
        description,
        Box::new(move || {
            if cmd.len() > 1 {
                let _ = std::process::Command::new(&cmd[0])
                    .args(&cmd[1..])
                    .output();
            }
        }),
    ));
}
