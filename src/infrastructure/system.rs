use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::domain::audit::{AuditItem, AuditReport, AuditStatus, PackageManager};
use crate::domain::errors::DomainError;
use crate::infrastructure::rollback;

/// 轮询子进程状态的间隔
const POLL_INTERVAL: Duration = Duration::from_millis(200);

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

/// 长耗时外部命令的执行结局
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// 正常退出（退出码 0）
    Success,
    /// 非零退出
    Failed(Option<i32>),
    /// 超时被终止
    TimedOut,
    /// 用户中断（Ctrl+C）被终止
    Cancelled,
}

impl StreamStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Failed(code) => *code,
            _ => None,
        }
    }
}

/// 运行长耗时命令：`argv[0]` 为可执行文件，stdout/stderr 实时写入 `log_path`，
/// 支持超时与 Ctrl+C 取消。
///
/// 与 `Command::output()` 的区别：
/// - 输出落盘，用户可随时查看，UI 可尾随显示（不再"假卡住"）
/// - 超时/中断时终止子进程，不会无限等待
pub fn run_streaming_argv(
    argv: &[String],
    envs: &[(&str, &str)],
    log_path: &str,
    timeout: Duration,
) -> Result<StreamStatus, DomainError> {
    use std::io::Write;

    let Some((program, args)) = argv.split_first() else {
        return Err(DomainError::SystemCommandFailed("空命令".into()));
    };

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| {
            DomainError::SystemCommandFailed(format!("无法写入执行日志 {log_path}: {e}"))
        })?;
    let mut header = file.try_clone().map_err(|e| {
        DomainError::SystemCommandFailed(format!("无法写入执行日志 {log_path}: {e}"))
    })?;
    let _ = writeln!(
        header,
        "\n===== [{}] $ {} =====",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        argv.join(" ")
    );

    let stderr_file = file.try_clone().map_err(|e| {
        DomainError::SystemCommandFailed(format!("无法写入执行日志 {log_path}: {e}"))
    })?;
    let mut child = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|e| DomainError::SystemCommandFailed(format!("无法执行 {program}: {e}")))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(if status.success() {
                    StreamStatus::Success
                } else {
                    StreamStatus::Failed(status.code())
                });
            },
            Ok(None) => {},
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DomainError::SystemCommandFailed(format!(
                    "等待 {program} 结束时出错: {e}"
                )));
            },
        }

        if rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(StreamStatus::Cancelled);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(StreamStatus::TimedOut);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// 便捷封装：以 `program + args` 形式运行长耗时命令
pub fn run_streaming(
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    log_path: &str,
    timeout: Duration,
) -> Result<StreamStatus, DomainError> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.to_string());
    argv.extend(args.iter().map(|a| a.to_string()));
    run_streaming_argv(&argv, envs, log_path, timeout)
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
            && (stripped.starts_with(' ') || stripped.starts_with('\t'))
        {
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
        .map(|v| v.eq_ignore_ascii_case("no") || v.eq_ignore_ascii_case("prohibit-password"))
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
        },
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
        && let Ok(content) = std::fs::read_to_string(path)
    {
        return content.contains("APT::Periodic::Update-Package-Lists \"1\"")
            || content.contains("APT::Periodic::Unattended-Upgrade \"1\"");
    }

    false
}

/// 检测 lynis 是否已安装（步骤 10）
pub fn detect_lynis_installed() -> bool {
    which("lynis")
}

/// 检测 logwatch 是否已安装（步骤 11）
pub fn detect_logwatch_installed() -> bool {
    which("logwatch")
}

/// 检测 aide 是否已安装（步骤 11）
pub fn detect_aide_installed() -> bool {
    which("aide") || which("aide.wrapper")
}

/// 运行中的 sshd 主进程 PID
fn sshd_main_pid() -> Option<u32> {
    // Debian/Ubuntu: /run/sshd.pid
    for path in ["/run/sshd.pid", "/var/run/sshd.pid"] {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Ok(pid) = content.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }
    // systemd: 取 MainPID
    for unit in ["sshd", "ssh"] {
        if let Ok(value) = run_cmd("systemctl", &["show", "-p", "MainPID", "--value", unit])
            && let Ok(pid) = value.trim().parse::<u32>()
            && pid > 0
        {
            return Some(pid);
        }
    }
    None
}

/// 判断 sshd_config 是否比运行中的服务更新（即步骤 12 是否真的需要重启）
///
/// 依赖 procfs 中 `/proc/<pid>` 的时间戳等于进程启动时间这一特性。
/// 无法判定时保守返回 false（不做无意义的重启）。
pub fn detect_ssh_restart_needed() -> bool {
    let Ok(config_mtime) = std::fs::metadata("/etc/ssh/sshd_config").and_then(|m| m.modified())
    else {
        return false;
    };
    let Some(pid) = sshd_main_pid() else {
        return false;
    };
    match std::fs::metadata(format!("/proc/{pid}")).and_then(|m| m.modified()) {
        Ok(started) => config_mtime > started,
        // 无法读取进程启动时间时，保守认为需要重启（配置已改但无法确认是否生效）
        Err(_) => true,
    }
}

/// 系统包列表是否最新（缓存小于 7 天即认为最新）
pub fn detect_system_up_to_date() -> bool {
    // 对于 apt，检查缓存文件时间戳
    let cache_paths = ["/var/lib/apt/lists", "/var/cache/apt/pkgcache.bin"];

    for path_str in &cache_paths {
        let path = Path::new(path_str);
        if let Ok(metadata) = path.metadata()
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = modified.elapsed()
        {
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
    let lynis_installed = detect_lynis_installed();
    let logwatch_installed = detect_logwatch_installed();
    let aide_installed = detect_aide_installed();
    let ssh_restart_needed = detect_ssh_restart_needed();

    let mut items = vec![];

    items.push(if is_root {
        AuditItem::safe(
            crate::i18n::tr("audit_root"),
            crate::i18n::tr("audit_detail_root_ok").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_root"),
            crate::i18n::tr("audit_detail_root_missing").into(),
        )
    });

    items.push(AuditItem {
        name: crate::i18n::tr("audit_pkg_mgr"),
        status: AuditStatus::Safe,
        detail: crate::i18n::tr("audit_detail_pkg").replace("{pkg}", package_manager.name()),
    });

    items.push(if ssh_port != 22 {
        AuditItem::safe(
            crate::i18n::tr("audit_ssh_port"),
            crate::i18n::tr("audit_detail_port_safe").replace("{port}", &ssh_port.to_string()),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_ssh_port"),
            crate::i18n::tr("audit_detail_port_missing").into(),
        )
    });

    items.push(if password_auth_disabled {
        AuditItem::safe(
            crate::i18n::tr("audit_password_auth"),
            crate::i18n::tr("audit_detail_pw_disabled").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_password_auth"),
            crate::i18n::tr("audit_detail_pw_missing").into(),
        )
    });

    items.push(if root_login_disabled {
        AuditItem::safe(
            crate::i18n::tr("audit_root_login"),
            crate::i18n::tr("audit_detail_root_disabled").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_root_login"),
            crate::i18n::tr("audit_detail_root_missing_cfg").into(),
        )
    });

    items.push(if sudo_users.is_empty() {
        AuditItem::missing(
            crate::i18n::tr("audit_sudo_users"),
            crate::i18n::tr("audit_detail_sudo_missing").into(),
        )
    } else {
        AuditItem::safe(
            crate::i18n::tr("audit_sudo_users"),
            crate::i18n::tr("audit_detail_sudo_ok").replace("{users}", &sudo_users.join(", ")),
        )
    });

    items.push(if fail2ban_installed {
        AuditItem::safe(
            crate::i18n::tr("audit_fail2ban"),
            crate::i18n::tr("audit_detail_fb_installed").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_fail2ban"),
            crate::i18n::tr("audit_detail_fb_missing").into(),
        )
    });

    items.push(if ufw_enabled {
        AuditItem::safe(
            crate::i18n::tr("audit_ufw"),
            crate::i18n::tr("audit_detail_ufw_enabled").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_ufw"),
            crate::i18n::tr("audit_detail_ufw_missing").into(),
        )
    });

    items.push(if auto_updates_enabled {
        AuditItem::safe(
            crate::i18n::tr("audit_auto_updates"),
            crate::i18n::tr("audit_detail_au_enabled").into(),
        )
    } else {
        AuditItem::missing(
            crate::i18n::tr("audit_auto_updates"),
            crate::i18n::tr("audit_detail_au_missing").into(),
        )
    });

    items.push(if system_up_to_date {
        AuditItem::safe(
            crate::i18n::tr("audit_sys_update"),
            crate::i18n::tr("audit_detail_sys_uptodate").into(),
        )
    } else {
        AuditItem::needs_update(
            crate::i18n::tr("audit_sys_update"),
            crate::i18n::tr("audit_detail_sys_needs_update").into(),
        )
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
        lynis_installed,
        logwatch_installed,
        aide_installed,
        ssh_restart_needed,
    }
}

/// 创建系统用户，加入管理员组，返回创建是否成功
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

    // 加入管理员组：Debian/Ubuntu 为 sudo，RHEL 系为 wheel
    add_to_admin_group(username)?;

    // 创建 .ssh 目录并设置权限（失败会导致密钥登录不可用，必须显式报错）
    let ssh_dir = format!("/home/{username}/.ssh");
    let _ = Command::new("mkdir").args(["-p", &ssh_dir]).output();

    let chown = Command::new("chown")
        .args(["-R", &format!("{username}:{username}"), &ssh_dir])
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("chown 失败: {e}")))?;
    if !chown.status.success() {
        let stderr = String::from_utf8_lossy(&chown.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "chown {ssh_dir} 失败: {stderr}"
        )));
    }

    let chmod = Command::new("chmod")
        .args(["700", &ssh_dir])
        .output()
        .map_err(|e| DomainError::SystemCommandFailed(format!("chmod 失败: {e}")))?;
    if !chmod.status.success() {
        let stderr = String::from_utf8_lossy(&chmod.stderr);
        return Err(DomainError::SystemCommandFailed(format!(
            "chmod 700 {ssh_dir} 失败: {stderr}"
        )));
    }

    Ok(())
}

/// 把用户加入 sudo/wheel 组，两者都失败才报错
fn add_to_admin_group(username: &str) -> Result<(), DomainError> {
    let mut last_err = String::new();
    for group in ["sudo", "wheel"] {
        match Command::new("usermod")
            .args(["-aG", group, username])
            .output()
        {
            Ok(o) if o.status.success() => return Ok(()),
            Ok(o) => last_err = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(DomainError::SystemCommandFailed(format!(
        "将用户 {username} 加入 sudo/wheel 组失败: {last_err}"
    )))
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
            "-t", "ed25519", "-f", &key_path, "-N", "", // 空密码
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
    let _ = Command::new("mkdir").args(["-p", &ssh_dir]).output();

    // 追加公钥（不覆盖已有密钥）
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&auth_keys)
        .map_err(|e| DomainError::SystemCommandFailed(format!("打开 authorized_keys 失败: {e}")))?;
    writeln!(file, "{}", pub_key)
        .map_err(|e| DomainError::SystemCommandFailed(format!("追加公钥失败: {e}")))?;

    let _ = Command::new("chmod").args(["600", &auth_keys]).output();

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
        // fallback: 返回公钥类型 + 前 47 个字符（按 char 边界截断，避免多字节 panic）
        let parts: Vec<&str> = first_key.split_whitespace().collect();
        let kind = parts.first().unwrap_or(&"unknown");
        let truncated: String = first_key.chars().take(47).collect();
        let suffix = if first_key.chars().count() > 47 {
            "..."
        } else {
            ""
        };
        return Some(format!("({kind}) {truncated}{suffix}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

/// 检查用户是否已存在
pub fn user_exists(username: &str) -> bool {
    Command::new("id")
        .arg(username)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 获取用户 home 目录路径
pub fn home_dir(username: &str) -> String {
    if username == "root" {
        "/root".to_string()
    } else {
        // 尝试从 /etc/passwd 读取
        if let Ok(output) = Command::new("getent").args(["passwd", username]).output()
            && output.status.success()
        {
            let line = String::from_utf8_lossy(&output.stdout);
            // passwd 格式: username:x:UID:GID:...:HOME:SHELL
            if let Some(home) = line.trim().split(':').nth(5)
                && !home.is_empty()
            {
                return home.to_string();
            }
        }
        // fallback: 默认 /home/{username}
        format!("/home/{username}")
    }
}
