use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use chrono::Local;

/// 简单文件日志器，线程安全
pub struct FileLogger {
    file: Mutex<std::fs::File>,
}

impl FileLogger {
    /// 创建日志器，优先写入 `/var/log/secure-init.log`，失败则 fallback 到当前目录
    pub fn new() -> Self {
        let path = if let Ok(f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/secure-init.log")
        {
            f
        } else {
            // fallback
            let local_path = Path::new("./secure-init.log");
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(local_path)
                .expect("无法创建日志文件")
        };
        Self {
            file: Mutex::new(path),
        }
    }

    /// 写入一行日志（自动加时间戳）
    pub fn log(&self, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{}] {}\n", timestamp, message);
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{}", line.trim());
            let _ = f.flush();
        }
    }

    /// 记录操作日志（脱敏：隐藏公钥内容，只保留指纹）
    pub fn log_operation(&self, step: &str, detail: &str) {
        // 简单脱敏：替换公钥内容
        let sanitized = sanitize_detail(detail);
        self.log(&format!("[操作] {}: {}", step, sanitized));
    }
}

impl Default for FileLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// 脱敏：将可能的公钥内容替换为 [KEY_REDACTED]
fn sanitize_detail(detail: &str) -> String {
    let mut result = detail.to_string();
    // 替换 ssh-rsa/ssh-ed25519 开头的公钥行
    if let Some(start) = result.find("ssh-ed25519 ") {
        if let Some(end) = result[start..]
            .find('\n')
            .or_else(|| result[start..].find('\r'))
        {
            let abs_end = start + end;
            result.replace_range(start..abs_end, "ssh-ed25519 [KEY_REDACTED]");
        } else {
            result.replace_range(start.., "ssh-ed25519 [KEY_REDACTED]");
        }
    }
    if let Some(start) = result.find("ssh-rsa ") {
        if let Some(end) = result[start..]
            .find('\n')
            .or_else(|| result[start..].find('\r'))
        {
            let abs_end = start + end;
            result.replace_range(start..abs_end, "ssh-rsa [KEY_REDACTED]");
        } else {
            result.replace_range(start.., "ssh-rsa [KEY_REDACTED]");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_ed25519_key() {
        let detail = "设置公钥: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host";
        let sanitized = sanitize_detail(detail);
        assert!(sanitized.contains("[KEY_REDACTED]"));
        assert!(!sanitized.contains("AAAAC3NzaC1lZDI1NTE5AAAAI"));
    }

    #[test]
    fn test_sanitize_rsa_key() {
        let detail = "设置公钥: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host";
        let sanitized = sanitize_detail(detail);
        assert!(sanitized.contains("[KEY_REDACTED]"));
        assert!(!sanitized.contains("AAAAB3NzaC1yc2EAAAADAQABAAABAQ"));
    }

    #[test]
    fn test_no_false_positive() {
        let detail = "配置完成，SSH 端口已修改为 2222";
        let sanitized = sanitize_detail(detail);
        assert_eq!(sanitized, detail);
    }
}
