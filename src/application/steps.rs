use std::process::Command;
use std::time::Duration;

use crate::domain::audit::PackageManager;
use crate::domain::errors::DomainError;
use crate::domain::steps::{ExecuteParams, HardeningStep, SshKeyAction, StepKind, StepResult};
use crate::infrastructure::system::StreamStatus;
use crate::infrastructure::{aide, artifacts, lynis, package_mirror, rollback, system};

// 超时（长耗时步骤必须有上限，避免"假卡住"）

const TIMEOUT_UPDATE: Duration = Duration::from_secs(300);
const TIMEOUT_UPGRADE: Duration = Duration::from_secs(1800);
const TIMEOUT_INSTALL: Duration = Duration::from_secs(900);
const TIMEOUT_LYNIS: Duration = Duration::from_secs(900);
const TIMEOUT_LOGWATCH: Duration = Duration::from_secs(300);
const TIMEOUT_SERVICE: Duration = Duration::from_secs(120);

/// apt 非交互执行，避免卡在 conffile 提示
const APT_ENVS: &[(&str, &str)] = &[("DEBIAN_FRONTEND", "noninteractive")];

// 步骤工厂

/// 按类型构造步骤实例（步骤都是无状态单元结构体）
pub fn step_for(kind: StepKind) -> Box<dyn HardeningStep + Send> {
    match kind {
        StepKind::SystemUpdate => Box::new(SystemUpdateStep),
        StepKind::UserCreation => Box::new(UserCreationStep),
        StepKind::SshRootLogin => Box::new(SshRootLoginStep),
        StepKind::SshPortChange => Box::new(SshPortChangeStep),
        StepKind::SshPasswordAuth => Box::new(SshPasswordAuthStep),
        StepKind::SshKeySetup => Box::new(SshKeySetupStep),
        StepKind::Ufw => Box::new(UfwStep),
        StepKind::Fail2ban => Box::new(Fail2banStep),
        StepKind::AutoUpdates => Box::new(AutoUpdatesStep),
        StepKind::SecurityScan => Box::new(SecurityScanStep),
        StepKind::LogAudit => Box::new(LogAuditStep),
        StepKind::RestartSsh => Box::new(RestartSshStep),
    }
}

// 公共辅助

/// 当前步骤的实时输出文件（由 StepRunner 注入，缺省时落到报告目录）
fn live_log(params: &ExecuteParams, prefix: &str) -> String {
    params
        .live_log
        .clone()
        .unwrap_or_else(|| artifacts::path_for(prefix, "log"))
}

/// 报告目录
fn report_dir(params: &ExecuteParams) -> String {
    params
        .report_dir
        .clone()
        .unwrap_or_else(artifacts::dir_display)
}

/// 报告目录下的产物路径
fn artifact_path(params: &ExecuteParams, prefix: &str, ext: &str) -> String {
    format!(
        "{}/{}-{}.{ext}",
        report_dir(params),
        prefix,
        artifacts::stamp()
    )
}

/// 把包管理器命令转成可展示的字符串
fn argv_display(argv: &[String]) -> String {
    argv.join(" ")
}

/// 流式命令失败时统一构造失败结果
fn stream_failure(
    kind: StepKind,
    status: StreamStatus,
    action: &str,
    log_path: &str,
) -> StepResult {
    let reason = crate::i18n::tr("result_cmd_failed")
        .replace("{action}", action)
        .replace("{reason}", &status.describe());
    StepResult::failed(
        kind,
        crate::i18n::tr("result_see_log")
            .replace("{msg}", &reason)
            .replace("{log}", log_path),
    )
    .with_artifacts(vec![log_path.to_string()])
}

fn apt_envs(pm: PackageManager) -> &'static [(&'static str, &'static str)] {
    if pm == PackageManager::Apt {
        APT_ENVS
    } else {
        &[]
    }
}

// 步骤 1：系统更新

#[derive(Debug)]
pub struct SystemUpdateStep;

impl HardeningStep for SystemUpdateStep {
    fn kind(&self) -> StepKind {
        StepKind::SystemUpdate
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();
        if pm == PackageManager::Unknown {
            return Ok(StepResult::skipped(
                self.kind(),
                crate::i18n::tr("result_pkg_unknown"),
            ));
        }

        let log = live_log(params, "step01-system-update");
        let envs = apt_envs(pm);

        let update_cmd = pm.update_cmd();
        let update = package_mirror::build_pm_argv(pm, &params.mirror, &update_cmd[1..]);
        let status = system::run_streaming_argv(&update, envs, &log, TIMEOUT_UPDATE)?;
        if !status.is_success() {
            return Ok(stream_failure(
                self.kind(),
                status,
                &argv_display(&update),
                &log,
            ));
        }

        let upgrade_cmd = pm.upgrade_cmd();
        let upgrade = package_mirror::build_pm_argv(pm, &params.mirror, &upgrade_cmd[1..]);
        let status = system::run_streaming_argv(&upgrade, envs, &log, TIMEOUT_UPGRADE)?;
        if !status.is_success() {
            return Ok(stream_failure(
                self.kind(),
                status,
                &argv_display(&upgrade),
                &log,
            ));
        }

        Ok(
            StepResult::changed(self.kind(), crate::i18n::tr("result_sys_updated"))
                .with_artifacts(vec![log]),
        )
    }
}

// 步骤 2：非 root 用户创建

#[derive(Debug)]
pub struct UserCreationStep;

impl HardeningStep for UserCreationStep {
    fn kind(&self) -> StepKind {
        StepKind::UserCreation
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let username = params.new_username.as_deref().ok_or_else(|| {
            DomainError::PreconditionFailed(crate::i18n::tr("err_no_username").into())
        })?;

        if system::user_exists(username) {
            return Err(DomainError::PreconditionFailed(
                crate::i18n::tr("err_user_exists").replace("{user}", username),
            ));
        }

        system::create_system_user(username)?;

        // 注册撤销：创建用户 → 删除用户（在创建成功后注册，避免幽灵撤销）
        rollback::register_user_remove(username.to_string());

        if params.lock_password {
            system::lock_user_password(username)?;
        }

        // 为用户生成 SSH key pair
        let pub_key_path = system::generate_ssh_keypair(username)?;

        // 读取公钥并添加到 authorized_keys
        if let Ok(pub_key) = std::fs::read_to_string(&pub_key_path) {
            system::add_authorized_key(username, pub_key.trim())?;
        }

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_user_created").replace("{user}", username),
        ))
    }
}

// 步骤 3：禁止 root SSH 登录

#[derive(Debug)]
pub struct SshRootLoginStep;

impl HardeningStep for SshRootLoginStep {
    fn kind(&self) -> StepKind {
        StepKind::SshRootLogin
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 前置条件：必须存在 sudo 用户
        let sudo_users = system::detect_sudo_users();
        if sudo_users.is_empty() {
            return Err(DomainError::PreconditionFailed(
                crate::i18n::tr("err_no_sudo_before_root").into(),
            ));
        }

        let message = modify_sshd_config("PermitRootLogin", "prohibit-password")?;
        Ok(StepResult::changed(self.kind(), message))
    }
}

// 步骤 4：SSH 端口修改

#[derive(Debug)]
pub struct SshPortChangeStep;

impl HardeningStep for SshPortChangeStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPortChange
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let new_port = params.new_ssh_port.ok_or_else(|| {
            DomainError::PreconditionFailed(crate::i18n::tr("err_no_ssh_port").into())
        })?;

        if new_port == 0 {
            return Err(DomainError::PreconditionFailed(
                crate::i18n::tr("err_port_zero").into(),
            ));
        }

        let message = modify_sshd_config("Port", &new_port.to_string())?;

        // UFW 放行新端口（如果 ufw 已启用）
        if system::detect_ufw_enabled() {
            // 注册撤销：放行端口 → 删除规则
            let port_for_undo = new_port.to_string();
            rollback::register_command_undo(
                crate::i18n::tr("undo_ufw_delete").replace("{port}", &port_for_undo),
                vec!["ufw".into(), "delete".into(), "allow".into(), port_for_undo],
            );
            let _ = Command::new("ufw")
                .args(["allow", &new_port.to_string()])
                .output();
        }

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_ssh_port_set")
                .replace("{port}", &new_port.to_string())
                .replace("{msg}", &message),
        ))
    }
}

// 步骤 5：禁止密码登录

#[derive(Debug)]
pub struct SshPasswordAuthStep;

impl HardeningStep for SshPasswordAuthStep {
    fn kind(&self) -> StepKind {
        StepKind::SshPasswordAuth
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 前置条件
        let sudo_users = system::detect_sudo_users();
        if sudo_users.is_empty() {
            return Err(DomainError::PreconditionFailed(
                crate::i18n::tr("err_no_sudo_before_pw").into(),
            ));
        }

        modify_sshd_config("PasswordAuthentication", "no")?;
        modify_sshd_config("ChallengeResponseAuthentication", "no")?;

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_pw_auth_disabled"),
        ))
    }
}

// 步骤 6：ED25519 密钥设置

#[derive(Debug)]
pub struct SshKeySetupStep;

impl HardeningStep for SshKeySetupStep {
    fn kind(&self) -> StepKind {
        StepKind::SshKeySetup
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let username = params.ssh_key_username.as_deref().ok_or_else(|| {
            DomainError::PreconditionFailed(crate::i18n::tr("err_no_target_user").into())
        })?;

        let action = params.ssh_key_action.as_ref().ok_or_else(|| {
            DomainError::PreconditionFailed(crate::i18n::tr("err_no_key_action").into())
        })?;

        match action {
            SshKeyAction::GenerateNew => {
                let home = system::home_dir(username);
                // 注册撤销：删除生成的密钥文件
                rollback::register_command_undo(
                    crate::i18n::tr("undo_key_delete").replace("{user}", username),
                    vec![
                        "rm".into(),
                        "-f".into(),
                        format!("{home}/.ssh/id_ed25519"),
                        format!("{home}/.ssh/id_ed25519.pub"),
                    ],
                );
                let pub_key_path = system::generate_ssh_keypair(username)?;
                let priv_path = pub_key_path.trim_end_matches(".pub");
                let msg = crate::i18n::tr("result_key_generated")
                    .replace("{priv}", priv_path)
                    .replace("{pub}", &pub_key_path)
                    .replace("{key}", priv_path);
                Ok(StepResult::changed(self.kind(), msg))
            },
            SshKeyAction::PasteKey(pub_key) => {
                system::add_authorized_key(username, pub_key)?;
                Ok(StepResult::changed(
                    self.kind(),
                    crate::i18n::tr("result_key_pasted").replace("{user}", username),
                ))
            },
        }
    }
}

// 步骤 7：UFW 防火墙

#[derive(Debug)]
pub struct UfwStep;

impl HardeningStep for UfwStep {
    fn kind(&self) -> StepKind {
        StepKind::Ufw
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let port = system::detect_ssh_port();
        let was_ufw_enabled = system::detect_ufw_enabled();

        // 放行 SSH 端口
        let output = Command::new("ufw")
            .args(["allow", &port.to_string()])
            .output()
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!(
                    "{}: {e}",
                    crate::i18n::tr("err_ufw_allow_failed")
                ))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "{}: {stderr}",
                crate::i18n::tr("err_ufw_allow_failed")
            )));
        }

        // 操作成功后注册撤销（先删除端口规则；如果之前未启用则再关闭 UFW）
        let port_for_undo = port.to_string();
        rollback::register_command_undo(
            crate::i18n::tr("undo_ufw_delete").replace("{port}", &port_for_undo),
            vec!["ufw".into(), "delete".into(), "allow".into(), port_for_undo],
        );
        if !was_ufw_enabled {
            rollback::register_command_undo(
                crate::i18n::tr("undo_ufw_disable").into(),
                vec!["ufw".into(), "--force".into(), "disable".into()],
            );
        }

        if !was_ufw_enabled {
            let output = Command::new("ufw")
                .args(["--force", "enable"])
                .output()
                .map_err(|e| {
                    DomainError::SystemCommandFailed(format!(
                        "{}: {e}",
                        crate::i18n::tr("err_ufw_enable_failed")
                    ))
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(DomainError::SystemCommandFailed(format!(
                    "{}: {stderr}",
                    crate::i18n::tr("err_ufw_enable_failed")
                )));
            }
        }

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_ufw_enabled").replace("{port}", &port.to_string()),
        ))
    }
}

// 步骤 8：Fail2ban

#[derive(Debug)]
pub struct Fail2banStep;

impl HardeningStep for Fail2banStep {
    fn kind(&self) -> StepKind {
        StepKind::Fail2ban
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let log = live_log(params, "step08-fail2ban");
        let mut artifacts_list = vec![];

        if !system::which("fail2ban-server") {
            let pm = system::detect_package_manager();
            if pm == PackageManager::Unknown {
                return Ok(StepResult::skipped(
                    self.kind(),
                    crate::i18n::tr("err_unsupported_pkg"),
                ));
            }

            let argv = package_mirror::install_argv(pm, &params.mirror, "fail2ban");
            let status = system::run_streaming_argv(&argv, apt_envs(pm), &log, TIMEOUT_INSTALL)?;
            if !status.is_success() {
                return Ok(stream_failure(
                    self.kind(),
                    status,
                    &argv_display(&argv),
                    &log,
                ));
            }
            artifacts_list.push(log.clone());

            if !system::which("fail2ban-server") {
                return Ok(StepResult::failed(
                    self.kind(),
                    crate::i18n::tr("err_install_fail2ban"),
                )
                .with_artifacts(artifacts_list));
            }

            // 安装成功后注册撤销
            rollback::register_command_undo(
                crate::i18n::tr("undo_cmd").replace("{desc}", "stop fail2ban"),
                vec!["systemctl".into(), "stop".into(), "fail2ban".into()],
            );
            rollback::register_package_remove(
                crate::i18n::tr("undo_pkg_remove").replace("{pkg}", "fail2ban"),
                "fail2ban".into(),
            );
        }

        // 配置监狱规则（使用 SSH 端口），写入前备份并注册回滚
        let port = system::detect_ssh_port();
        let jail_local = format!("[sshd]\nenabled = true\nport = {port}\n");
        if let Some(backup) = backup_file("/etc/fail2ban/jail.local") {
            rollback::register_file_backup(
                crate::i18n::tr("undo_file_restore_generic")
                    .replace("{path}", "/etc/fail2ban/jail.local"),
                backup,
                "/etc/fail2ban/jail.local".into(),
            );
        }
        std::fs::write("/etc/fail2ban/jail.local", &jail_local)
            .map_err(|e| DomainError::SystemCommandFailed(format!("写入 jail.local 失败: {e}")))?;

        let argv = vec![
            "systemctl".to_string(),
            "enable".into(),
            "--now".into(),
            "fail2ban".into(),
        ];
        let status = system::run_streaming_argv(&argv, &[], &log, TIMEOUT_SERVICE)?;
        if !status.is_success() {
            return Ok(stream_failure(
                self.kind(),
                status,
                &argv_display(&argv),
                &log,
            ));
        }
        artifacts_list.push(log);

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_fail2ban_installed").replace("{port}", &port.to_string()),
        )
        .with_artifacts(artifacts_list))
    }
}

// 步骤 9：自动安全更新（可选步骤：默认不勾选；失败不触发全局回滚）

#[derive(Debug)]
pub struct AutoUpdatesStep;

impl HardeningStep for AutoUpdatesStep {
    fn kind(&self) -> StepKind {
        StepKind::AutoUpdates
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();
        if pm != PackageManager::Apt {
            // 非 Debian 系不再返回错误（避免拖垮整个流程的回滚）
            return Ok(StepResult::skipped(
                self.kind(),
                crate::i18n::tr("result_auto_update_only_debian"),
            ));
        }

        let log = live_log(params, "step09-auto-updates");
        let mut artifacts_list = vec![log.clone()];

        if !system::which("unattended-upgrade") {
            let argv = package_mirror::install_argv(pm, &params.mirror, "unattended-upgrades");
            let status = system::run_streaming_argv(&argv, apt_envs(pm), &log, TIMEOUT_INSTALL)?;
            if !status.is_success() {
                return Ok(stream_failure(
                    self.kind(),
                    status,
                    &argv_display(&argv),
                    &log,
                ));
            }
            if !system::which("unattended-upgrade") {
                return Ok(StepResult::failed(
                    self.kind(),
                    crate::i18n::tr("err_install_unattended"),
                )
                .with_artifacts(artifacts_list));
            }

            rollback::register_command_undo(
                crate::i18n::tr("undo_cmd").replace("{desc}", "stop unattended-upgrades"),
                vec![
                    "systemctl".into(),
                    "stop".into(),
                    "unattended-upgrades".into(),
                ],
            );
            rollback::register_package_remove(
                crate::i18n::tr("undo_pkg_remove").replace("{pkg}", "unattended-upgrades"),
                "unattended-upgrades".into(),
            );
        }

        // 写入配置：启用自动安全更新（写入前备份并注册回滚）
        let config_path = "/etc/apt/apt.conf.d/20auto-upgrades";
        if let Some(backup) = backup_file(config_path) {
            rollback::register_file_backup(
                crate::i18n::tr("undo_file_restore_generic").replace("{path}", config_path),
                backup,
                config_path.into(),
            );
        }
        let auto_config = "APT::Periodic::Update-Package-Lists \"1\";\n\
                           APT::Periodic::Unattended-Upgrade \"1\";\n\
                           APT::Periodic::Download-Upgradeable-Packages \"1\";\n\
                           APT::Periodic::AutocleanInterval \"7\";\n";
        std::fs::write(config_path, auto_config).map_err(|e| {
            DomainError::SystemCommandFailed(format!("写入 {config_path} 失败: {e}"))
        })?;

        let argv = vec![
            "systemctl".to_string(),
            "enable".into(),
            "--now".into(),
            "unattended-upgrades".into(),
        ];
        let status = system::run_streaming_argv(&argv, &[], &log, TIMEOUT_SERVICE)?;
        if !status.is_success() {
            return Ok(stream_failure(
                self.kind(),
                status,
                &argv_display(&argv),
                &log,
            ));
        }
        artifacts_list.push(config_path.to_string());

        Ok(
            StepResult::changed(self.kind(), crate::i18n::tr("result_auto_updates_enabled"))
                .with_artifacts(artifacts_list),
        )
    }
}

// 步骤 10：安全扫描（可选步骤）

#[derive(Debug)]
pub struct SecurityScanStep;

impl HardeningStep for SecurityScanStep {
    fn kind(&self) -> StepKind {
        StepKind::SecurityScan
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let log = live_log(params, "step10-lynis");
        let mut artifacts_list = vec![log.clone()];

        // ── 安装 lynis（优先使用发行版官方源，不再引入第三方源与 apt-key）──
        if !system::which("lynis") {
            let pm = system::detect_package_manager();
            if pm == PackageManager::Unknown {
                return Ok(StepResult::skipped(
                    self.kind(),
                    crate::i18n::tr("err_unknown_pkg_lynis"),
                ));
            }

            let argv = package_mirror::install_argv(pm, &params.mirror, "lynis");
            let status = system::run_streaming_argv(&argv, apt_envs(pm), &log, TIMEOUT_INSTALL)?;
            if !status.is_success() {
                return Ok(stream_failure(
                    self.kind(),
                    status,
                    &argv_display(&argv),
                    &log,
                ));
            }
            if !system::which("lynis") {
                return Ok(
                    StepResult::failed(self.kind(), crate::i18n::tr("result_lynis_fail"))
                        .with_artifacts(artifacts_list),
                );
            }

            rollback::register_package_remove(
                crate::i18n::tr("undo_pkg_remove").replace("{pkg}", "lynis"),
                "lynis".into(),
            );
        }

        // ── 执行扫描：日志与报告都持久化到报告目录 ──
        let lynis_log = artifact_path(params, "lynis", "log");
        let report_file = artifact_path(params, "lynis", "dat");
        let argv = vec![
            "lynis".to_string(),
            "audit".into(),
            "system".into(),
            "--quick".into(),
            "--cronjob".into(),
            "--no-colors".into(),
            "--logfile".into(),
            lynis_log.clone(),
            "--report-file".into(),
            report_file.clone(),
        ];
        let status = system::run_streaming_argv(&argv, &[], &log, TIMEOUT_LYNIS)?;
        artifacts_list.push(lynis_log.clone());
        artifacts_list.push(report_file.clone());

        // lynis 退出码 78 = 发现告警，属正常结果
        match status {
            StreamStatus::Success => {},
            StreamStatus::Failed(Some(78)) => {},
            other => {
                let mut result = stream_failure(self.kind(), other, &argv_display(&argv), &log);
                result.artifacts = artifacts_list;
                return Ok(result);
            },
        }
        artifacts::restrict_file(&lynis_log);
        artifacts::restrict_file(&report_file);

        let summary = std::fs::read_to_string(&report_file)
            .map(|content| lynis::parse_report(&content))
            .unwrap_or_default();

        let index = summary
            .hardening_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "?".into());
        let message = crate::i18n::tr("result_lynis_ok")
            .replace("{index}", &index)
            .replace("{warns}", &summary.warnings.to_string())
            .replace("{suggs}", &summary.suggestions.to_string())
            .replace("{report}", &report_file);

        Ok(StepResult::changed(self.kind(), message).with_artifacts(artifacts_list))
    }
}

// 步骤 11：日志与审计增强（可选步骤）

#[derive(Debug)]
pub struct LogAuditStep;

impl HardeningStep for LogAuditStep {
    fn kind(&self) -> StepKind {
        StepKind::LogAudit
    }

    fn execute(&self, params: &ExecuteParams) -> Result<StepResult, DomainError> {
        let pm = system::detect_package_manager();
        if pm == PackageManager::Unknown {
            return Ok(StepResult::skipped(
                self.kind(),
                crate::i18n::tr("err_unsupported_pkg"),
            ));
        }

        let log = live_log(params, "step11-log-audit");
        let mut artifacts_list = vec![log.clone()];
        let mut installed: Vec<&str> = vec![];
        let mut failures: Vec<String> = vec![];

        // ── 安装 logwatch / aide（安装后必须校验，不再"伪成功"）──
        // Debian/Ubuntu 的 aide 包**只装二进制**，配置文件与 aideinit 由 aide-common 提供，
        // 缺失时 `aide --init` 会以退出码 17（Configuration error）失败。
        let mut aide_packages: Vec<&str> = vec!["aide"];
        aide_packages.extend(aide::companion_packages(pm).iter().copied());
        for (binary, package) in std::iter::once(("logwatch", "logwatch"))
            .chain(aide_packages.iter().map(|p| ("aide", *p)))
        {
            let is_companion = package != "aide";
            if !is_companion && system::which(binary) {
                installed.push(package);
                continue;
            }
            if is_companion && system::package_installed(pm, package) {
                continue;
            }
            let argv = package_mirror::install_argv(pm, &params.mirror, package);
            let status = system::run_streaming_argv(&argv, apt_envs(pm), &log, TIMEOUT_INSTALL)?;
            if !status.is_success() {
                // 配套包失败也记录：后续配置探测会发现没有可用 aide.conf 并走兜底配置
                failures.push(
                    crate::i18n::tr("result_install_pkg_failed")
                        .replace("{pkg}", package)
                        .replace("{reason}", &status.describe()),
                );
                continue;
            }
            if is_companion
                || system::which(binary)
                || (package == "aide" && system::which("aide.wrapper"))
            {
                if !is_companion {
                    installed.push(package);
                }
                rollback::register_package_remove(
                    crate::i18n::tr("undo_pkg_remove").replace("{pkg}", package),
                    package.into(),
                );
            } else {
                failures.push(
                    crate::i18n::tr("result_install_pkg_unverified").replace("{pkg}", package),
                );
            }
        }

        // ── logwatch：立即生成一份可查看的报告（默认 yesterday，落在报告目录）──
        let mut logwatch_report = None;
        if system::which("logwatch") {
            let path = format!(
                "{}/logwatch-{}.txt",
                report_dir(params),
                artifacts::date_stamp()
            );
            let argv = vec![
                "logwatch".to_string(),
                "--output".into(),
                "stdout".into(),
                "--format".into(),
                "text".into(),
                "--range".into(),
                "yesterday".into(),
                "--detail".into(),
                "high".into(),
            ];
            match system::run_streaming_argv(&argv, &[], &path, TIMEOUT_LOGWATCH)? {
                StreamStatus::Success => {
                    artifacts::restrict_file(&path);
                    logwatch_report = Some(path.clone());
                    artifacts_list.push(path);
                },
                other => failures.push(
                    crate::i18n::tr("result_logwatch_report_failed")
                        .replace("{reason}", &other.describe()),
                ),
            }
        }

        // ── 每日报告定时任务：不覆盖发行版自带文件，仅在缺失时补装 ──
        let mut cron_path = None;
        if system::which("logwatch") && !std::path::Path::new("/etc/cron.daily/00logwatch").exists()
        {
            let path = "/etc/cron.daily/99u2secure-logwatch";
            let script = format!(
                "#!/bin/bash\n# 由 U2Secure 生成：每日日志审计报告\n/usr/sbin/logwatch --output stdout --format text --range yesterday --detail high > {}/logwatch-$(date +\\%F).txt 2>&1\n",
                report_dir(params)
            );
            if let Some(backup) = backup_file(path) {
                rollback::register_file_backup(
                    crate::i18n::tr("undo_file_restore_generic").replace("{path}", path),
                    backup,
                    path.into(),
                );
            }
            std::fs::write(path, script)
                .map_err(|e| DomainError::SystemCommandFailed(format!("写入 {path} 失败: {e}")))?;
            set_executable(path);
            cron_path = Some(path.to_string());
            artifacts_list.push(path.to_string());
        }

        // ── aide：先确保有可用配置，再初始化数据库（历史缺陷：裸 `aide --init` 报退出码 17）──
        let mut aide_config_display: Option<String> = None;
        let mut aide_init_log = None;
        let mut aide_db_display: Option<String> = None;
        let mut aide_plan = None;
        if system::which("aide") {
            match resolve_aide_plan(pm, params) {
                Ok(plan) => {
                    if !plan.database_ready() {
                        let path = artifact_path(params, "aide-init", "log");
                        let check_log = artifact_path(params, "aide-check", "log");
                        artifacts_list.push(path.clone());
                        artifacts_list.push(check_log.clone());
                        aide_init_log = Some(path.clone());
                        let init = aide::initialize_database(
                            &plan,
                            std::path::Path::new(&path),
                            std::path::Path::new(&check_log),
                        );
                        if let Err(err) = init {
                            // 原始错误 + 日志路径一并给出，不伪造成成功
                            let reason = format!("{err}；日志: {path}");
                            failures.push(
                                crate::i18n::tr("result_aide_init_failed")
                                    .replace("{reason}", &reason),
                            );
                        }
                    }
                    if let Some(conf) = &plan.config {
                        display_path(&mut aide_config_display, conf);
                    }
                    if plan.database_ready() {
                        aide_db_display = Some(plan.database_metadata());
                    } else {
                        // 数据库尚未就绪时也给出预期路径，便于人工排查
                        display_path(&mut aide_db_display, &plan.database_in);
                    }
                    aide_plan = Some(plan);
                },
                Err(reason) => failures.push(
                    crate::i18n::tr("result_aide_config_failed").replace("{reason}", &reason),
                ),
            }
        }

        // ── 每日完整性检查：用本次实际生效的配置，避免脚本重复踩"缺配置"的坑 ──
        let mut aide_cron = false;
        if let Some(plan) = aide_plan.as_ref().filter(|p| p.database_ready())
            && !aide_check_scheduled()
        {
            let path = "/etc/cron.daily/99u2secure-aide";
            let script = aide::render_daily_script(plan.config.as_deref(), &report_dir(params));
            if let Some(backup) = backup_file(path) {
                rollback::register_file_backup(
                    crate::i18n::tr("undo_file_restore_generic").replace("{path}", path),
                    backup,
                    path.into(),
                );
            }
            if std::fs::write(path, script).is_ok() {
                set_executable(path);
                aide_cron = true;
                artifacts_list.push(path.to_string());
            }
        }

        let mut message = crate::i18n::tr("result_logwatch_installed")
            .replace("{installed}", &installed.join(", "))
            .replace("{report_dir}", &report_dir(params));
        if let Some(report) = &logwatch_report {
            message.push_str(
                &crate::i18n::tr("result_logwatch_report_path").replace("{path}", report),
            );
        }
        if let Some(cron) = &cron_path {
            message.push_str(&crate::i18n::tr("result_logwatch_cron").replace("{path}", cron));
        }
        if let Some(log_path) = &aide_init_log {
            message.push_str(&crate::i18n::tr("result_aide_init").replace("{path}", log_path));
        }
        if let Some(conf) = &aide_config_display {
            message.push_str(&crate::i18n::tr("result_aide_config").replace("{path}", conf));
        }
        if let Some(db) = &aide_db_display {
            message.push_str(&crate::i18n::tr("result_aide_db").replace("{path}", db));
        }
        if aide_cron {
            message.push_str(crate::i18n::tr("result_aide_cron"));
        }

        if !failures.is_empty() {
            message.push_str(
                &crate::i18n::tr("result_partial_failures").replace("{list}", &failures.join("; ")),
            );
            return Ok(StepResult::failed(self.kind(), message).with_artifacts(artifacts_list));
        }

        Ok(StepResult::changed(self.kind(), message).with_artifacts(artifacts_list))
    }
}

/// 确定 aide 实际使用的配置与数据库路径
///
/// 顺序：探测发行版配置 → 只读校验语法 → 缺失或不可用时生成兜底配置到报告目录。
/// 历史缺陷：直接执行 `aide --init`，在只装了 `aide` 没装 `aide-common` 的系统上
/// 会以退出码 17（Configuration error）失败。
fn resolve_aide_plan(pm: PackageManager, params: &ExecuteParams) -> Result<aide::AidePlan, String> {
    let log = artifact_path(params, "aide-config-check", "log");
    let mut plan = aide::detect_plan(pm);
    let mut problem = None;
    if plan.config.is_some() {
        match aide::config_problem(&plan, std::path::Path::new(&log)) {
            Ok(None) => return Ok(plan),
            Ok(Some(reason)) => problem = Some(reason),
            // 无法执行 aide：不掩盖原始错误，交由调用方报告
            Err(err) => return Err(format!("{err}；日志: {log}")),
        }
    }

    plan = aide::fallback_plan(std::path::Path::new(&report_dir(params)));
    aide::ensure_fallback_config(&mut plan).map_err(|e| {
        format!(
            "{e}（原配置问题: {}）",
            problem.unwrap_or_else(|| "未找到配置".into())
        )
    })?;
    Ok(plan)
}

/// 把路径写入可选的展示字段
fn display_path(slot: &mut Option<String>, path: &std::path::Path) {
    if slot.is_none() {
        *slot = Some(path.to_string_lossy().into_owned());
    }
}

/// 是否已存在每日 aide 检查机制（发行版自带则不重复添加）
fn aide_check_scheduled() -> bool {
    // Debian/Ubuntu 为 dailyaidecheck（cron 脚本 + dailyaidecheck.timer）
    for path in [
        "/etc/cron.daily/aide",
        "/etc/cron.daily/dailyaidecheck",
        "/usr/share/aide/config/cron.daily/dailyaidecheck",
    ] {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    // Debian aide-common 提供 dailyaidecheck.timer
    system::run_cmd("systemctl", &["is-enabled", "dailyaidecheck.timer"])
        .map(|s| s.trim() == "enabled")
        .unwrap_or(false)
}

/// 给脚本加上可执行位
///
/// `PermissionsExt` 只存在于 unix；非 unix 平台（Windows 构建）为空实现，
/// 避免为了一个 chmod 让整个二进制无法在 Windows 上编译。
fn set_executable(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// 备份已存在的文件（返回备份路径）；文件不存在时返回 None
fn backup_file(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let backup = format!("{path}.bak.{}", artifacts::stamp());
    std::fs::copy(path, &backup).ok()?;
    Some(backup)
}

// 步骤 12：SSH 服务重启与验证

#[derive(Debug)]
pub struct RestartSshStep;

impl HardeningStep for RestartSshStep {
    fn kind(&self) -> StepKind {
        StepKind::RestartSsh
    }

    fn execute(&self, _params: &ExecuteParams) -> Result<StepResult, DomainError> {
        // 幂等：配置未变更（不比服务进程更新）则无需重启
        if !system::detect_ssh_restart_needed() {
            return Ok(StepResult::skipped(
                self.kind(),
                crate::i18n::tr("result_ssh_no_restart"),
            ));
        }

        // 先验证 sshd_config 语法
        let check = Command::new("sshd").args(["-t"]).output().map_err(|e| {
            DomainError::SystemCommandFailed(format!("{}: {e}", crate::i18n::tr("err_sshd_check")))
        })?;

        if !check.status.success() {
            let stderr = String::from_utf8_lossy(&check.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "{}: {stderr}",
                crate::i18n::tr("err_sshd_syntax")
            )));
        }

        // 重启 SSH 服务
        let output = Command::new("systemctl")
            .args(["restart", "sshd"])
            .output()
            .or_else(|_| Command::new("systemctl").args(["restart", "ssh"]).output())
            .map_err(|e| {
                DomainError::SystemCommandFailed(format!(
                    "{}: {e}",
                    crate::i18n::tr("err_ssh_restart")
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::SystemCommandFailed(format!(
                "{}: {stderr}",
                crate::i18n::tr("err_ssh_restart")
            )));
        }

        // 验证服务状态
        let status = Command::new("systemctl")
            .args(["is-active", "sshd"])
            .output()
            .or_else(|_| {
                Command::new("systemctl")
                    .args(["is-active", "ssh"])
                    .output()
            });

        let status_str = match &status {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".into(),
        };

        Ok(StepResult::changed(
            self.kind(),
            crate::i18n::tr("result_ssh_restarted").replace("{status}", &status_str),
        ))
    }
}

// 辅助函数：修改 sshd_config

/// 修改 sshd_config 中的键值，返回结果描述（备份路径已注册回滚）
fn modify_sshd_config(key: &str, value: &str) -> Result<String, DomainError> {
    let path = std::path::Path::new("/etc/ssh/sshd_config");
    if !path.exists() {
        return Err(DomainError::ParseError(
            crate::i18n::tr("err_sshd_not_found").into(),
        ));
    }

    // 备份
    let backup = format!(
        "/etc/ssh/sshd_config.bak.{}",
        chrono::Local::now().format("%Y%m%d%H%M%S")
    );
    std::fs::copy(path, &backup).map_err(|e| {
        DomainError::SystemCommandFailed(format!("{}: {e}", crate::i18n::tr("err_backup")))
    })?;

    // 注册撤销：从备份恢复原文件
    rollback::register_file_backup(
        crate::i18n::tr("undo_file_restore").replace("{key}", key),
        backup.clone(),
        path.to_string_lossy().to_string(),
    );

    let content = std::fs::read_to_string(path)
        .map_err(|e| DomainError::ParseError(format!("{}: {e}", crate::i18n::tr("err_read"))))?;

    let mut found = false;
    let new_content: Vec<String> = content
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                return line.to_string();
            }
            // 精确匹配第一个单词（避免 Port 误匹配 PortNumber）
            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            if first_word == key {
                found = true;
                format!("{key} {value}")
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut result = new_content.join("\n");
    if !found {
        result.push_str(&format!("\n{key} {value}\n"));
    }

    std::fs::write(path, result).map_err(|e| {
        DomainError::SystemCommandFailed(format!("{}: {e}", crate::i18n::tr("err_write")))
    })?;

    Ok(crate::i18n::tr("result_sshd_cfg_set")
        .replace("{key}", key)
        .replace("{value}", value)
        .replace("{bak}", &backup))
}
