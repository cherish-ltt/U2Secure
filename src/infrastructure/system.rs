use std::path::Path;
use std::process::Command;

use crate::domain::audit::{AuditItem, AuditReport, AuditStatus, PackageManager};
use crate::domain::errors::DomainError;

/// 执行 shell 命令并返回 stdout
pub fn run_cmd(program: &str, args: &[&str]) -> Result<String, DomainError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("无法执行 {program}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "{program} 返回非零退出码: {stderr}"
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 检测是否以 root 运行
pub fn detect_is_root() -> bool {
    // 使用 id -u 更可靠
    run_cmd("id", &["-u"])
        .map(|uid| uid.trim() == "0")
        .unwrap_or(false)
}

/// 检测包管理器
pub fn detect_package_manager() -> PackageManager {
    if which("apt") {
        PackageManager::Apt
    } else if which("yum") {
        PackageManager::Yum
    } else if which("dnf") {
        PackageManager::Dnf
    } else {
        PackageManager::Unknown
    }
}

/// 检查命令是否存在
pub fn which(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 解析 sshd_config 中的某个指令值（取最后出现的一个）
pub fn sshd_config_get(key: &str) -> Option<String> {
    let path = Path::new("/etc/ssh/sshd_config");
    let content = std::fs::read_to_string(path).ok()?;
    let mut value = None;
    for line in content.lines() {
        let line = line.trim();
        // 跳过注释
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(stripped) = line.strip_prefix(key)
            && (stripped.starts_with(' ') || stripped.starts_with('\t')) {
                value = Some(stripped.trim().to_string());
            }
    }
    value
}

/// 获取 SSH 端口
pub fn detect_ssh_port() -> u16 {
    sshd_config_get("Port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(22)
}

/// 检测是否禁止密码登录
pub fn detect_password_auth_disabled() -> bool {
    let password = sshd_config_get("PasswordAuthentication")
        .map(|v| v.eq_ignore_ascii_case("no"))
        .unwrap_or(false);
    let challenge = sshd_config_get("ChallengeResponseAuthentication")
        .map(|v| v.eq_ignore_ascii_case("no"))
        .unwrap_or(false);
    password && challenge
}

/// 检测是否禁止 root 登录
pub fn detect_root_login_disabled() -> bool {
    sshd_config_get("PermitRootLogin")
        .map(|v| {
            v.eq_ignore_ascii_case("no") || v.eq_ignore_ascii_case("prohibit-password")
        })
        .unwrap_or(false)
}

/// 获取非 root 的 sudo 用户列表
pub fn detect_sudo_users() -> Vec<String> {
    // 尝试从 sudo group 获取
    let output = Command::new("getent")
        .args(["group", "sudo"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                Some(s)
            } else {
                None
            }
        })
        .or_else(|| {
            // fallback: 读 wheel group
            Command::new("getent")
                .args(["group", "wheel"])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).to_string())
                    } else {
                        None
                    }
                })
        });

    match output {
        Some(line) => {
            // format: "sudo:x:27:user1,user2"
            if let Some(colon_pos) = line.rfind(':') {
                let after = &line[colon_pos + 1..].trim();
                if after.is_empty() {
                    return vec![];
                }
                let users: Vec<String> = after
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                // 过滤掉 UID < 1000 的系统用户
                users
                    .into_iter()
                    .filter(|u| {
                        let uid = get_user_uid(u);
                        uid >= 1000
                    })
                    .collect()
            } else {
                vec![]
            }
        }
        None => vec![],
    }
}

fn get_user_uid(username: &str) -> u32 {
    Command::new("id")
        .args(["-u", username])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout);
                s.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// 检测 fail2ban 是否已安装
pub fn detect_fail2ban_installed() -> bool {
    which("fail2ban-server")
}

/// 检测 UFW 是否已启用
pub fn detect_ufw_enabled() -> bool {
    let output = Command::new("ufw")
        .arg("status")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

    match output {
        Some(s) => s.contains("active") || s.contains("Status: active"),
        None => false,
    }
}

/// 检测自动安全更新是否已启用
pub fn detect_auto_updates_enabled() -> bool {
    // Debian/Ubuntu: 检查 unattended-upgrades 服务
    let systemd = Command::new("systemctl")
        .args(["is-enabled", "unattended-upgrades"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if systemd {
        return true;
    }

    // 检查配置文件
    let path = Path::new("/etc/apt/apt.conf.d/20auto-upgrades");
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(path) {
            return content.contains("APT::Periodic::Update-Package-Lists \"1\"")
                || content.contains("APT::Periodic::Unattended-Upgrade \"1\"");
        }

    false
}

/// 检测系统包列表是否最新（缓存小于 7 天即认为最新）
pub fn detect_system_up_to_date() -> bool {
    // 对于 apt，检查缓存文件时间戳
    let cache_paths = [
        "/var/lib/apt/lists",
        "/var/cache/apt/pkgcache.bin",
    ];

    for path_str in &cache_paths {
        let path = Path::new(path_str);
        if let Ok(metadata) = path.metadata()
            && let Ok(modified) = metadata.modified()
                && let Ok(elapsed) = modified.elapsed() {
                    // 7 天 = 604800 秒
                    return elapsed.as_secs() < 604800;
                }
    }

    // 如果什么也查不到，保守返回 false
    false
}

/// 执行完整的系统审计，返回 AuditReport
pub fn run_full_audit() -> AuditReport {
    let is_root = detect_is_root();
    let package_manager = detect_package_manager();
    let ssh_port = detect_ssh_port();
    let password_auth_disabled = detect_password_auth_disabled();
    let root_login_disabled = detect_root_login_disabled();
    let sudo_users = detect_sudo_users();
    let fail2ban_installed = detect_fail2ban_installed();
    let ufw_enabled = detect_ufw_enabled();
    let auto_updates_enabled = detect_auto_updates_enabled();
    let system_up_to_date = detect_system_up_to_date();

    let mut items = vec![];

    items.push(if is_root {
        AuditItem::safe("当前用户权限", "已以 root 运行".into())
    } else {
        AuditItem::missing("当前用户权限", "非 root 用户，需要 root 权限".into())
    });

    items.push(AuditItem {
        name: "包管理器",
        status: AuditStatus::Safe,
        detail: format!("检测到 {}", package_manager.name()),
    });

    items.push(if ssh_port != 22 {
        AuditItem::safe("SSH 端口", format!("已自定义为 {ssh_port}"))
    } else {
        AuditItem::missing("SSH 端口", "默认端口 22".into())
    });

    items.push(if password_auth_disabled {
        AuditItem::safe("密码登录", "已禁用".into())
    } else {
        AuditItem::missing("密码登录", "密码登录未禁用".into())
    });

    items.push(if root_login_disabled {
        AuditItem::safe("root 登录", "已禁止".into())
    } else {
        AuditItem::missing("root 登录", "root 登录未禁止".into())
    });

    items.push(if sudo_users.is_empty() {
        AuditItem::missing("sudo 用户", "未检测到非 root 管理用户".into())
    } else {
        AuditItem::safe("sudo 用户", format!("已存在: {}", sudo_users.join(", ")))
    });

    items.push(if fail2ban_installed {
        AuditItem::safe("Fail2ban", "已安装".into())
    } else {
        AuditItem::missing("Fail2ban", "未安装".into())
    });

    items.push(if ufw_enabled {
        AuditItem::safe("UFW 防火墙", "已启用".into())
    } else {
        AuditItem::missing("UFW 防火墙", "未启用".into())
    });

    items.push(if auto_updates_enabled {
        AuditItem::safe("自动安全更新", "已启用".into())
    } else {
        AuditItem::missing("自动安全更新", "未启用".into())
    });

    items.push(if system_up_to_date {
        AuditItem::safe("系统更新状态", "缓存未过期".into())
    } else {
        AuditItem::needs_update("系统更新状态", "缓存已过期，建议更新".into())
    });

    AuditReport {
        items,
        is_root,
        package_manager,
        ssh_port,
        password_auth_disabled,
        root_login_disabled,
        sudo_users,
        fail2ban_installed,
        ufw_enabled,
        auto_updates_enabled,
        system_up_to_date,
    }
}

/// 创建系统用户，加入 sudo 组，返回创建是否成功
pub fn create_system_user(username: &str) -> Result<(), DomainError> {
    // 创建用户
    let output = Command::new("useradd")
        .args(["-m", "-s", "/bin/bash", username])
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("useradd 失败: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "useradd 失败: {stderr}"
        )));
    }

    // 加入 sudo 组
    let _ = Command::new("usermod")
        .args(["-aG", "sudo", username])
        .output();

    // 创建 .ssh 目录
    let _ = Command::new("mkdir")
        .args(["-p", &format!("/home/{username}/.ssh")])
        .output();

    let _ = Command::new("chown")
        .args(["-R", &format!("{username}:{username}"), &format!("/home/{username}/.ssh")])
        .output();

    let _ = Command::new("chmod")
        .args(["700", &format!("/home/{username}/.ssh")])
        .output();

    Ok(())
}

/// 锁定用户密码（强制密钥登录）
pub fn lock_user_password(username: &str) -> Result<(), DomainError> {
    let output = Command::new("passwd")
        .args(["-l", username])
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("passwd -l 失败: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "锁定密码失败: {stderr}"
        )));
    }
    Ok(())
}

/// 为用户生成 ED25519 密钥对，返回公钥路径
pub fn generate_ssh_keypair(username: &str) -> Result<String, DomainError> {
    let home = if username == "root" {
        "/root".to_string()
    } else {
        format!("/home/{username}")
    };
    let key_path = format!("{home}/.ssh/id_ed25519");
    let pub_key_path = format!("{key_path}.pub");

    let output = Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            "-f", &key_path,
            "-N", "",  // 空密码
            "-q",
        ])
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("ssh-keygen 失败: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "ssh-keygen 失败: {stderr}"
        )));
    }

    // 修正权限
    let _ = Command::new("chown")
        .args([&format!("{username}:{username}"), &key_path, &pub_key_path])
        .output();

    Ok(pub_key_path)
}

/// 将公钥追加到用户的 authorized_keys
pub fn add_authorized_key(username: &str, pub_key: &str) -> Result<(), DomainError> {
    let home = if username == "root" {
        "/root".to_string()
    } else {
        format!("/home/{username}")
    };

    let ssh_dir = format!("{home}/.ssh");
    let auth_keys = format!("{ssh_dir}/authorized_keys");

    // 确保 .ssh 目录存在
    let _ = Command::new("mkdir")
        .args(["-p", &ssh_dir])
        .output();

    // 追加公钥（不覆盖已有密钥）
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&auth_keys)
        .map_err(|e| DomainError::SystemCommandFailed(format!("打开 authorized_keys 失败: {e}")))?;
    writeln!(file, "{}", pub_key)
        .map_err(|e| DomainError::SystemCommandFailed(format!("追加公钥失败: {e}")))?;

    let _ = Command::new("chmod")
        .args(["600", &auth_keys])
        .output();

    let _ = Command::new("chown")
        .args([&format!("{username}:{username}"), &auth_keys])
        .output();

    Ok(())
}

/// 获取可用随机端口（1024-65535 范围内的建议值）
pub fn random_suggested_port() -> u16 {
    // 基于时间戳生成一个伪随机端口，避开常见服务端口
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42);

    // 范围 1024-65535 之间的建议端口，避开 22, 80, 443, 3306, 5432, 6379, 8080, 8443
    let base = 1024 + (seed % 64511) as u16;
    let common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443];
    if common_ports.contains(&base) {
        ((base as u32 + 100) % 64511 + 1024) as u16
    } else {
        base
    }
}

/// 获取用户 authorized_keys 中第一条公钥的 SHA256 指纹
pub fn get_key_fingerprint(username: &str) -> Option<String> {
    let home = if username == "root" {
        "/root".to_string()
    } else {
        format!("/home/{username}")
    };
    let auth_keys = format!("{home}/.ssh/authorized_keys");

    if !std::path::Path::new(&auth_keys).exists() {
        return None;
    }

    let content = std::fs::read_to_string(&auth_keys).ok()?;
    // 找第一条非注释、非空行
    let first_key = content.lines().find(|line| {
        let t = line.trim();
        !t.is_empty() && !t.starts_with('#')
    })?;
    let first_key = first_key.trim();

    // 使用 tempfile 创建安全临时文件（避免 TOCTOU 竞争 & 固定路径风险）
    use std::io::Write;
    let mut tmp_file = tempfile::Builder::new()
        .prefix("u2secure_key_")
        .tempfile()
        .ok()?;
    writeln!(tmp_file, "{first_key}").ok()?;

    let output = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(tmp_file.path().as_os_str())
        .output()
        .ok()?;
    // tmp_file 在此处 drop，自动删除临时文件

    if !output.status.success() {
        // fallback: 返回公钥类型 + 前 40 字符
        let parts: Vec<&str> = first_key.split_whitespace().collect();
        let kind = parts.first().unwrap_or(&"unknown");
        let truncated = if first_key.len() > 47 {
            format!("{}...", &first_key[..47])
        } else {
            first_key.to_string()
        };
        return Some(format!("({kind}) {truncated}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() { None } else { Some(stdout) }
}

/// 检查用户是否已存在
pub fn user_exists(username: &str) -> bool {
    Command::new("id")
        .arg(username)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}


