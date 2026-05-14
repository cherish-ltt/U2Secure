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
