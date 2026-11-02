use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::domain::audit::{AuditItem, AuditReport, AuditStatus, PackageManager};
use crate::domain::errors::DomainError;
use crate::infrastructure::{rollback, ssh};

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
    /// 超过约定时间没有任何输出（对端无响应）
    NoResponse,
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

    /// 人类可读的失败原因（成功时为空串）
    pub fn describe(&self) -> String {
        match self {
            Self::Success => String::new(),
            Self::TimedOut => crate::i18n::tr("result_cmd_timeout").to_string(),
            Self::NoResponse => crate::i18n::tr("result_cmd_no_response").to_string(),
            Self::Cancelled => crate::i18n::tr("result_cancelled").to_string(),
            Self::Failed(code) => crate::i18n::tr("result_exit_code").replace(
                "{code}",
                &code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            ),
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
    run_streaming_watchdog(argv, envs, log_path, timeout, None)
}

/// 同 [`run_streaming_argv`]，但支持"无输出看门狗"：
/// 连续 `stall_timeout` 没有任何新输出时判定对端无响应并终止子进程。
pub fn run_streaming_watchdog(
    argv: &[String],
    envs: &[(&str, &str)],
    log_path: &str,
    timeout: Duration,
    stall_timeout: Option<Duration>,
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
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(stderr_file));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| DomainError::SystemCommandFailed(format!("无法执行 {program}: {e}")))?;

    let started = Instant::now();
    // 看门狗：记录输出文件的长度与修改时间，长时间无新输出判定为对端无响应
    let mut last_progress = Instant::now();
    let mut last_size = std::fs::metadata(log_path).map(|m| m.len()).unwrap_or(0);
    loop {
        match command_status(&mut child) {
            Ok(Some(status)) => {
                return Ok(if status.success() {
                    StreamStatus::Success
                } else {
                    StreamStatus::Failed(status.code())
                });
            },
            Ok(None) => {},
            Err(e) => {
                stop_command(&mut child)?;
                return Err(DomainError::SystemCommandFailed(format!(
                    "等待 {program} 结束时出错: {e}"
                )));
            },
        }

        if let Some(stall) = stall_timeout {
            let size = std::fs::metadata(log_path)
                .map(|m| m.len())
                .unwrap_or(last_size);
            if size != last_size {
                last_size = size;
                last_progress = Instant::now();
            } else if last_progress.elapsed() >= stall {
                stop_command(&mut child)?;
                return Ok(StreamStatus::NoResponse);
            }
        }

        if rollback::INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst) {
            stop_command(&mut child)?;
            return Ok(StreamStatus::Cancelled);
        }
        if started.elapsed() >= timeout {
            stop_command(&mut child)?;
            return Ok(StreamStatus::TimedOut);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn command_status(
    child: &mut std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
    // Keep the leader waitable until its group is signalled, preventing PID reuse.
    let status = waitid(
        WaitId::Pid(Pid::from_child(child)),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )?;
    if status.is_none() {
        return Ok(None);
    }
    stop_command(child).map_err(std::io::Error::other)?;
    child.wait().map(Some)
}

#[cfg(not(target_os = "linux"))]
fn command_status(
    child: &mut std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    child.try_wait()
}

fn stop_command(child: &mut std::process::Child) -> Result<(), DomainError> {
    #[cfg(unix)]
    let stopped = {
        use rustix::process::{Pid, Signal, kill_process_group};
        match kill_process_group(Pid::from_child(child), Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(std::io::Error::from(error)),
        }
    };
    #[cfg(not(unix))]
    let stopped = child.kill();
    // Always reap our child, including when signalling the group fails.
    if stopped.is_err() {
        let _ = child.kill();
    }
    let waited = child.wait();
    stopped.and(waited.map(|_| ())).map_err(|error| {
        DomainError::SystemCommandFailed(
            crate::i18n::tr("err_stop_command").replace("{err}", &error.to_string()),
        )
    })
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

/// 获取 SSH 全局端口；审计通过 ssh_config_verified 区分未知与已验证值。
pub fn detect_ssh_port() -> u16 {
    ssh::SshConfig::default()
        .effective()
        .ok()
        .and_then(|config| config.ports.first().copied())
        .unwrap_or(22)
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

/// 检测软件包是否已安装
///
/// 部分配套包没有可执行文件（如 Debian 的 `aide-common` 只提供配置与 `aideinit`），
/// 无法用 [`which`] 判断，必须查询包管理器。
pub fn package_installed(pm: PackageManager, package: &str) -> bool {
    let result = match pm {
        PackageManager::Apt => run_cmd("dpkg-query", &["-W", "-f=${Status}", package]),
        PackageManager::Dnf | PackageManager::Yum => run_cmd("rpm", &["-q", package]),
        PackageManager::Unknown => return false,
    };
    result
        .map(|out| installed_from_output(&out))
        .unwrap_or(false)
}

/// 判断包管理器输出是否表示"已安装"
///
/// 只认各包管理器的**确定性标志**，不用"含连字符/词数"之类启发式
/// （`deinstall ok config-files` 会被启发式误判为已安装）：
///
/// - `dpkg-query -W -f=${Status}`：已安装为 `<want> ok installed`，
///   已卸载为 `deinstall ok config-files`，未安装为 `unknown ok not-installed`
/// - `rpm -q`：已安装输出首行 `aide-0.18.6-1.el9.x86_64`；未安装为
///   `package aide is not installed`（rpm 自 4.11 起 stderr 也输出同样文本）
/// - 因此 rpm 分支判据为"不含 not installed 且含版本分隔连字符"
fn installed_from_output(output: &str) -> bool {
    let text = output.trim();
    if text.is_empty() {
        return false;
    }
    // dpkg：状态字段固定为 installed / config-files / not-installed
    if let Some(rest) = text.strip_prefix("install ok ") {
        return rest.trim() == "installed";
    }
    if text.starts_with("deinstall ok ") || text.starts_with("unknown ok ") {
        return false;
    }
    // rpm / pacman：`name-version-release` 形如 `aide-0.18.6-1.el9.x86_64`
    !text.contains("not installed") && text.contains('-')
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
    run_full_audit_with(ssh::SshConfig::default())
}

fn run_full_audit_with(config: ssh::SshConfig) -> AuditReport {
    let is_root = detect_is_root();
    let package_manager = detect_package_manager();
    let ssh_config = config.effective();
    let ssh_config_verified = ssh_config.as_ref().is_ok_and(|config| config.verified);
    let ssh_port = ssh_config
        .as_ref()
        .ok()
        .and_then(|config| config.ports.first().copied())
        .unwrap_or(22);
    let password_auth_disabled = ssh_config
        .as_ref()
        .is_ok_and(|config| config.password_auth_disabled);
    let root_login_disabled = ssh_config
        .as_ref()
        .is_ok_and(|config| config.root_login_disabled);
    let ssh_detail = match &ssh_config {
        Ok(config) => crate::i18n::tr("audit_ssh_global").replace(
            "{ports}",
            &config
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Err(error) => error.to_string(),
    };
    let sudo_users = detect_sudo_users();
    let fail2ban_installed = detect_fail2ban_installed();
    let ufw_enabled = detect_ufw_enabled();
    let auto_updates_enabled = detect_auto_updates_enabled();
    let system_up_to_date = detect_system_up_to_date();
    let lynis_installed = detect_lynis_installed();
    let logwatch_installed = detect_logwatch_installed();
    let aide_installed = detect_aide_installed();
    let ssh_restart_needed = detect_ssh_restart_needed();

    let mut report = AuditReport {
        items: vec![],
        is_root,
        package_manager,
        ssh_port,
        ssh_config_verified,
        password_auth_disabled,
        root_login_disabled,
        sudo_users: sudo_users.clone(),
        fail2ban_installed,
        ufw_enabled,
        auto_updates_enabled,
        system_up_to_date,
        lynis_installed,
        logwatch_installed,
        aide_installed,
        ssh_restart_needed,
    };

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

    for (kind, name, detail) in [
        (
            crate::domain::steps::StepKind::SshPortChange,
            "audit_ssh_port",
            ssh_detail,
        ),
        (
            crate::domain::steps::StepKind::SshPasswordAuth,
            "audit_password_auth",
            crate::i18n::tr(if password_auth_disabled {
                "audit_detail_pw_disabled"
            } else {
                "audit_detail_pw_missing"
            })
            .into(),
        ),
        (
            crate::domain::steps::StepKind::SshRootLogin,
            "audit_root_login",
            crate::i18n::tr(if root_login_disabled {
                "audit_detail_root_disabled"
            } else {
                "audit_detail_root_missing_cfg"
            })
            .into(),
        ),
    ] {
        let detail = if ssh_config_verified {
            detail
        } else {
            format!("{}: {detail}", crate::i18n::tr("audit_ssh_unverified"))
        };
        items.push(AuditItem::new(
            crate::i18n::tr(name),
            report.status_for(kind),
            detail,
        ));
    }

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

    report.items = items;
    report
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

    // useradd 已产生账户；后续初始化失败同样必须撤销。
    rollback::register_user_remove(username.to_string());

    // 加入管理员组：Debian/Ubuntu 为 sudo，RHEL 系为 wheel
    add_to_admin_group(username)?;

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
    generate_ssh_keypair_with_replace(username, false)
}

pub fn generate_ssh_keypair_with_replace(
    username: &str,
    replace: bool,
) -> Result<String, DomainError> {
    #[cfg(unix)]
    {
        super::ssh_keys::generate_ssh_keypair(username, replace)
    }
    #[cfg(not(unix))]
    {
        let _ = (username, replace);
        Err(DomainError::PreconditionFailed(
            "SSH key operations require Unix".into(),
        ))
    }
}

/// 将公钥追加到用户的 authorized_keys
pub fn add_authorized_key(username: &str, pub_key: &str) -> Result<(), DomainError> {
    #[cfg(unix)]
    {
        super::ssh_keys::add_authorized_key(username, pub_key)
    }
    #[cfg(not(unix))]
    {
        let _ = (username, pub_key);
        Err(DomainError::PreconditionFailed(
            "SSH key operations require Unix".into(),
        ))
    }
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

    key_fingerprint_at(Path::new(&auth_keys))
}

fn key_fingerprint_at(auth_keys: &Path) -> Option<String> {
    if !auth_keys.exists() {
        return None;
    }

    let content = std::fs::read_to_string(auth_keys).ok()?;
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

#[cfg(test)]
#[path = "system_tests.rs"]
mod coverage_tests;

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

#[cfg(test)]
mod tests {
    use super::installed_from_output;

    #[test]
    fn test_dpkg_query_installed_status() {
        // dpkg-query -W -f=${Status} 的真实输出
        assert!(installed_from_output("install ok installed"));
        assert!(installed_from_output("install ok installed\n"));
    }

    #[test]
    fn test_dpkg_query_removed_status_is_not_installed() {
        // 已卸载但残留配置：不得判定为已安装
        assert!(!installed_from_output("deinstall ok config-files"));
        assert!(!installed_from_output("unknown ok not-installed"));
        assert!(!installed_from_output(""));
        assert!(!installed_from_output("   "));
    }

    #[test]
    fn test_rpm_query_output() {
        assert!(installed_from_output("aide-0.18.6-1.el9.x86_64"));
        assert!(!installed_from_output("package aide is not installed"));
    }

    #[test]
    fn test_package_installed_unknown_manager_is_false() {
        // Unknown 直接返回 false，不应尝试执行任何包管理器命令
        assert!(!super::package_installed(
            crate::domain::audit::PackageManager::Unknown,
            "aide"
        ));
    }
}
