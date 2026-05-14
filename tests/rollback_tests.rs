use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use u2secure::domain::undo::UndoAction;
use u2secure::infrastructure::rollback;

// ---------------------------------------------------------------------------
// UndoAction 基础功能测试（无全局状态，可并行）
// ---------------------------------------------------------------------------

#[test]
fn test_undo_action_execute() {
    let executed = Arc::new(AtomicBool::new(false));
    let flag = executed.clone();

    let action = UndoAction::new("测试撤销".into(), Box::new(move || {
        flag.store(true, Ordering::SeqCst);
    }));

    assert!(!executed.load(Ordering::SeqCst));
    action.execute();
    assert!(executed.load(Ordering::SeqCst));
}

#[test]
fn test_undo_action_description() {
    let action = UndoAction::new("描述文本".into(), Box::new(|| {}));
    assert_eq!(action.description, "描述文本");
}

// ---------------------------------------------------------------------------
// 所有依赖全局 UNDO_STACK 的测试合并为一个大测试，
// 顺序执行避免并行竞争。
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_manager_global_workflow() {
    // ── 1. 空栈不 panic ──
    rollback::undo_all();

    // ── 2. LIFO 回退顺序 ──
    let flag1 = Arc::new(AtomicBool::new(false));
    let flag2 = Arc::new(AtomicBool::new(false));
    let f1 = flag1.clone();
    let f2 = flag2.clone();

    rollback::register_undo(UndoAction::new("撤销 1".into(), Box::new(move || {
        f1.store(true, Ordering::SeqCst);
    })));
    rollback::register_undo(UndoAction::new("撤销 2".into(), Box::new(move || {
        f2.store(true, Ordering::SeqCst);
    })));

    rollback::undo_all();
    assert!(flag2.load(Ordering::SeqCst), "undo2 应先执行（LIFO）");
    assert!(flag1.load(Ordering::SeqCst), "undo1 应后执行");

    // ── 3. 防止重复执行 ──
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    rollback::register_undo(UndoAction::new("计数".into(), Box::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    })));
    rollback::undo_all();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    rollback::undo_all(); // 应被 UNDO_RUNNING 拦截
    assert_eq!(count.load(Ordering::SeqCst), 1, "不应重复执行撤销");

    // ── 4. 重入保护 ──
    let reentry_count = Arc::new(AtomicUsize::new(0));
    let rc = reentry_count.clone();
    rollback::register_undo(UndoAction::new("自旋".into(), Box::new(move || {
        rc.fetch_add(1, Ordering::SeqCst);
        rollback::undo_all(); // 尝试重入
    })));
    rollback::undo_all();
    assert_eq!(reentry_count.load(Ordering::SeqCst), 1, "重入应被阻止");

    // ── 5. register_file_backup ──
    let tmp = tempfile::NamedTempFile::new().expect("创建临时文件失败");
    let path = tmp.path().to_str().unwrap().to_string();
    let backup_path = format!("{path}.bak");

    std::fs::write(&path, "原始内容").unwrap();
    std::fs::copy(&path, &backup_path).unwrap();
    std::fs::write(&path, "修改后内容").unwrap();

    rollback::register_file_backup(
        "恢复测试文件".into(),
        backup_path.clone(),
        path.clone(),
    );

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "修改后内容");
    rollback::undo_all();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "原始内容",
        "文件应被恢复为备份内容"
    );
    assert!(
        !std::path::Path::new(&backup_path).exists(),
        "备份文件应在恢复后被删除"
    );

    // ── 6. register_command_undo ──
    let tmp2 = tempfile::NamedTempFile::new().expect("创建临时文件失败");
    let path2 = tmp2.path().to_str().unwrap().to_string();

    std::fs::write(&path2, "待删除").unwrap();
    assert!(std::path::Path::new(&path2).exists());

    rollback::register_command_undo(
        "删除测试文件".into(),
        vec!["rm".into(), "-f".into(), path2.clone()],
    );

    rollback::undo_all();
    assert!(
        !std::path::Path::new(&path2).exists(),
        "rm 命令应删除文件"
    );
}
