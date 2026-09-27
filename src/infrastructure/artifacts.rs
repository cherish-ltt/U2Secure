//! 扫描产物的持久化目录
//!
//! 所有长耗时/扫描类步骤把完整输出写入该目录，UI 只展示摘要 + 路径，
//! 用户可以随时用 `less` 查看完整结果。
//!
//! 目录优先级：`/var/log/u2secure` → `./u2secure-reports` → 系统临时目录。

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chrono::Local;

/// 首选报告目录
pub const PRIMARY_DIR: &str = "/var/log/u2secure";
/// 首选目录不可写时的当前目录回退
pub const FALLBACK_DIR: &str = "./u2secure-reports";

static DIR: OnceLock<PathBuf> = OnceLock::new();

/// 获取（并创建）报告目录，进程内只解析一次
pub fn dir() -> PathBuf {
    DIR.get_or_init(|| {
        let candidates = [
            PathBuf::from(PRIMARY_DIR),
            PathBuf::from(FALLBACK_DIR),
            std::env::temp_dir().join("u2secure-reports"),
        ];
        first_writable(&candidates).unwrap_or_else(|| std::env::temp_dir().join("u2secure-reports"))
    })
    .clone()
}

/// 每步实时输出文件所在目录（<报告目录>/steps）
pub fn steps_dir() -> String {
    let path = dir().join("steps");
    let _ = std::fs::create_dir_all(&path);
    restrict_permissions(&path);
    path.to_string_lossy().to_string()
}

/// 目录路径字符串（用于展示给用户）
pub fn dir_display() -> String {
    dir().to_string_lossy().to_string()
}

/// 依次尝试创建候选目录，返回第一个真正可写的
fn first_writable(candidates: &[PathBuf]) -> Option<PathBuf> {
    for candidate in candidates {
        if std::fs::create_dir_all(candidate).is_ok() && is_writable(candidate) {
            restrict_permissions(candidate);
            return Some(candidate.clone());
        }
    }
    None
}

fn is_writable(path: &Path) -> bool {
    let probe = path.join(".u2secure-write-test");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        },
        Err(_) => false,
    }
}

/// 报告可能包含主机敏感信息，尽量收紧权限（失败不致命）
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// 收紧单个文件权限（0644 → 0600）
pub fn restrict_file(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// 时间戳后缀：20250927-183000
pub fn stamp() -> String {
    Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// 日期后缀：2025-09-27
pub fn date_stamp() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

/// 生成 `<dir>/<prefix>-<stamp>.<ext>` 形式的产物路径
pub fn path_for(prefix: &str, ext: &str) -> String {
    dir()
        .join(format!("{prefix}-{}.{ext}", stamp()))
        .to_string_lossy()
        .to_string()
}

/// 读取文件尾部（用于 UI 实时预览）
pub fn read_tail(path: &str, max_lines: usize, max_bytes: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(max_bytes);
    if start > 0 {
        file.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut buf = Vec::new();
    file.take(max_bytes).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).to_string();
    // 若从中间截断，丢弃首个不完整行
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let start_idx = lines.len().saturating_sub(max_lines);
    Some(lines[start_idx..].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_first_writable_prefers_existing_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ok = tmp.path().join("ok");
        let dir = first_writable(std::slice::from_ref(&ok)).expect("should pick writable dir");
        assert_eq!(dir, ok);
        assert!(dir.is_dir());
    }

    #[test]
    fn test_stamp_format() {
        let stamp = stamp();
        // YYYYmmdd-HHMMSS
        assert_eq!(stamp.len(), 15);
        assert_eq!(&stamp[8..9], "-");
        let date = date_stamp();
        assert_eq!(date.len(), 10);
    }

    #[test]
    fn test_read_tail_returns_last_lines() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("sample.log");
        let mut file = std::fs::File::create(&path).expect("create");
        for i in 1..=100 {
            writeln!(file, "line-{i}").expect("write");
        }
        let tail = read_tail(&path.to_string_lossy(), 3, 8192).expect("tail");
        assert_eq!(tail, "line-98\nline-99\nline-100");
    }

    #[test]
    fn test_read_tail_missing_file_is_none() {
        assert!(read_tail("/nonexistent/u2secure/nope.log", 3, 1024).is_none());
    }
}
