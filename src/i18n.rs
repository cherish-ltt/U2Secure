//! 国际化支持（零外部依赖，纯 Rust 实现）
//!
//! 使用方法：
//! 1. 启动时调用 `i18n::init(lang)` 设置语言
//! 2. 任意位置 `t!("key")` 获取翻译

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 语言枚举
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    /// English
    En,
    /// 简体中文
    ZhCn,
    /// 繁體中文
    ZhTw,
}

impl Lang {
    pub fn all() -> &'static [Lang] {
        &[Self::ZhCn, Self::ZhTw, Self::En]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::ZhCn => "简体中文",
            Self::ZhTw => "繁體中文",
        }
    }
}

// ---------------------------------------------------------------------------
// 全局语言状态（启动时设置一次，运行中不变）
// ---------------------------------------------------------------------------

static LANG: OnceLock<Lang> = OnceLock::new();

/// 初始化语言（必须在任何 `t!` 调用前执行）
pub fn init(lang: Lang) {
    let _ = LANG.set(lang);
}

/// 获取当前语言
pub fn current() -> Lang {
    LANG.get().copied().unwrap_or(Lang::ZhCn)
}

// ---------------------------------------------------------------------------
// 翻译宏
// ---------------------------------------------------------------------------

/// 翻译查询入口
pub fn translate(key: &'static str) -> &'static str {
    match current() {
        Lang::En => en(key).unwrap_or(key),
        Lang::ZhCn => zh_cn(key).unwrap_or(key),
        Lang::ZhTw => zh_tw(key).unwrap_or(key),
    }
}

/// 翻译短别名
pub fn tr(key: &'static str) -> &'static str {
    translate(key)
}

// ===========================================================================
// 简体中文翻译表（原始语言）
// ===========================================================================

fn zh_cn(key: &str) -> Option<&'static str> {
    Some(match key {
        // ── 主入口 ──
        "lang_en" => "English",
        "lang_zh_cn" => "简体中文",
        "lang_zh_tw" => "繁體中文",
        "select_language" => "选择语言",
        "select_mode" => "请选择启动模式",
        "mode_cli" => "CLI 模式（传统交互式）",
        "mode_tui" => "TUI 模式（终端图形界面）",
        "unknown_arg" => "未知参数: {arg}，使用 -c (CLI) 或 -t (TUI)",

        // ── 标题 ──
        "app_title" => "U2Secure — Linux 服务器安全加固工具",

        // ── Step 标签（12项） ──
        "step_system_update" => "系统更新",
        "step_user_creation" => "非 root 用户创建",
        "step_ssh_root_login" => "禁止 root SSH 登录",
        "step_ssh_port_change" => "SSH 端口修改",
        "step_ssh_password_auth" => "禁止密码登录",
        "step_ssh_key_setup" => "ED25519 密钥设置",
        "step_ufw" => "UFW 防火墙配置",
        "step_fail2ban" => "Fail2ban 安装配置",
        "step_auto_updates" => "自动安全更新",
        "step_security_scan" => "安全扫描",
        "step_log_audit" => "日志与审计增强",
        "step_restart_ssh" => "SSH 服务重启与验证",

        // ── 审计项名称 ──
        "audit_root" => "当前用户权限",
        "audit_pkg_mgr" => "包管理器",
        "audit_ssh_port" => "SSH 端口",
        "audit_password_auth" => "密码登录",
        "audit_root_login" => "root 登录",
        "audit_sudo_users" => "sudo 用户",
        "audit_fail2ban" => "Fail2ban",
        "audit_ufw" => "UFW 防火墙",
        "audit_auto_updates" => "自动安全更新",
        "audit_sys_update" => "系统更新状态",
        "audit_detail_root_ok" => "已以 root 运行",
        "audit_detail_root_missing" => "非 root 用户，需要 root 权限",
        "audit_detail_pkg" => "检测到 {pkg}",
        "audit_detail_port_safe" => "已自定义为 {port}",
        "audit_detail_port_missing" => "默认端口 22",
        "audit_detail_pw_disabled" => "已禁用",
        "audit_detail_pw_missing" => "密码登录未禁用",
        "audit_detail_root_disabled" => "已禁止",
        "audit_detail_root_missing_cfg" => "root 登录未禁止",
        "audit_detail_sudo_missing" => "未检测到非 root 管理用户",
        "audit_detail_sudo_ok" => "已存在: {users}",
        "audit_detail_fb_installed" => "已安装",
        "audit_detail_fb_missing" => "未安装",
        "audit_detail_ufw_enabled" => "已启用",
        "audit_detail_ufw_missing" => "未启用",
        "audit_detail_au_enabled" => "已启用",
        "audit_detail_au_missing" => "未启用",
        "audit_detail_sys_uptodate" => "缓存未过期",
        "audit_detail_sys_needs_update" => "缓存已过期，建议更新",

        // ── 审计状态 ──
        "status_safe" => "✅",
        "status_partial" => "⚠️",
        "status_missing" => "❌",
        "status_needs_update" => "🔄",

        // ── 包管理器 ──
        "pkg_apt" => "apt",
        "pkg_yum" => "yum",
        "pkg_dnf" => "dnf",
        "pkg_unknown" => "unknown",

        // ── 领域错误 ──
        "err_permission_denied" => "需要 root 权限运行",
        "err_cmd_failed" => "系统命令执行失败: {msg}",
        "err_parse_error" => "配置解析错误: {msg}",
        "err_precondition_failed" => "前置条件不满足: {msg}",
        "err_user_aborted" => "用户取消操作",

        // ── 错误详情（我们的包装说明，非原始系统错误） ──
        "err_unknown_pkg_mgr" => "无法识别的包管理器",
        "err_unsupported_pkg" => "不支持的包管理器",
        "err_auto_update_only_debian" => "自动安全更新仅支持 Debian/Ubuntu",
        "err_unknown_pkg_lynis" => "无法确定包管理器，请手动安装 lynis",
        "err_sshd_not_found" => "sshd_config 不存在",
        "err_no_username" => "未提供用户名",
        "err_user_exists" => "用户 '{user}' 已存在",
        "err_no_sudo_before_root" => "禁止 root 登录前请先创建 sudo 用户",
        "err_no_ssh_port" => "未提供新 SSH 端口",
        "err_port_zero" => "端口 0 无效",
        "err_no_sudo_before_pw" => "禁止密码登录前请先创建 sudo 用户",
        "err_no_target_user" => "未提供目标用户名",
        "err_no_key_action" => "未选择密钥操作",
        "err_update_failed" => "update 失败",
        "err_upgrade_failed" => "upgrade 失败",
        "err_ufw_allow_failed" => "ufw allow 失败",
        "err_ufw_enable_failed" => "ufw enable 失败",
        "err_install_fail2ban" => "安装 fail2ban 失败",
        "err_install_unattended" => "安装 unattended-upgrades 失败",
        "err_lynis_exec" => "lynis 执行失败",
        "err_sshd_check" => "sshd 语法检查失败",
        "err_sshd_syntax" => "sshd_config 语法错误，请检查配置",
        "err_ssh_restart" => "重启 SSH 服务失败",
        "err_backup" => "备份失败",
        "err_read" => "读取失败",
        "err_write" => "写入失败",
        "err_setup_signal" => "无法注册 Ctrl+C 信号处理器",

        // ── 应用层（步骤执行结果） ──
        "result_sys_updated" => "系统更新完成",
        "result_user_created" => {
            "用户 '{user}' 已创建并加入 sudo 组，密钥已设置（私钥: ~/.ssh/id_ed25519）"
        },
        "result_root_login_set" => "PermitRootLogin 已设置为 prohibit-password（备份: {bak}）",
        "result_ssh_port_set" => "SSH 端口已修改为 {port}（{msg}）",
        "result_pw_auth_disabled" => "密码登录已禁用（仅允许密钥登录）",
        "result_key_generated" => {
            "ED25519 密钥对已生成\n  私钥: {priv}\n  公钥: {pub}\n  ⚠️  私钥无密码短语保护，建议手动加密：ssh-keygen -p -f {key}\n  请立即复制私钥并安全保存！"
        },
        "result_key_pasted" => "公钥已添加到 {user} 的 authorized_keys",
        "result_ufw_enabled" => "UFW 已启用，SSH 端口 {port} 已放行",
        "result_fail2ban_installed" => "Fail2ban 已安装并运行，SSH 端口 {port} 已加入监控",
        "result_auto_updates_enabled" => "自动安全更新已启用（每日检查，自动安装安全补丁）",
        "result_lynis_ok" => {
            "lynis 安全扫描完成（{warns} 个警告, {suggs} 个建议）\n  详细报告: /var/log/lynis.log"
        },
        "result_lynis_fail" => "lynis 无法自动安装，请手动安装后重新运行",
        "result_logwatch_installed" => {
            "日志与审计增强完成\n  已安装/配置: {installed}\n  logwatch: 每日邮件报告\n  aide: 文件完整性检查已初始化"
        },
        "result_ssh_restarted" => {
            "SSH 服务已重启（状态: {status}）\n  ⚠️  请在另一终端验证连接后再关闭当前会话！\n  🔄 如需回滚：systemctl restart sshd 或恢复备份 /etc/ssh/sshd_config.bak.*"
        },
        "result_sshd_cfg_set" => "{key} 已设置为 {value}（备份: {bak}）",
        "result_sshd_syntax_ok" => "sshd_config 语法检查通过",
        "result_sshd_syntax_err" => "sshd_config 语法错误，请检查配置: {err}",

        // ── 日志前缀 ──
        "log_audit" => "[审计]",
        "log_operation" => "[操作]",
        "log_rollback" => "[回退]",
        "log_audit_start" => "开始环境审计...",
        "log_audit_done" => "完成，共 {n} 项检测",
        "log_step_start" => "开始执行",
        "log_step_complete" => "完成",
        "log_step_failed" => "失败",
        "log_rollback_auto" => "步骤失败，自动回退所有已注册的修改",

        // ── 回退描述 ──
        "undo_user_remove" => "删除用户 '{user}'",
        "undo_pkg_remove" => "删除 {pkg}",
        "undo_cmd" => "{desc}",
        "undo_file_restore" => "恢复 sshd_config（{key}）",
        "undo_ufw_disable" => "关闭 UFW 防火墙",
        "undo_ufw_delete" => "删除 UFW 端口 {port} 放行规则",
        "undo_key_delete" => "删除 {user} 的密钥文件",

        // ── CLI 界面 ──
        "cli_welcome" => "U2Secure - Linux 服务器安全加固工具 v{ver}",
        "cli_auditing" => "正在执行环境审计...",
        "cli_audit_done" => "环境审计完成：",
        "cli_select_steps" => "请选择要执行的加固步骤（已安全配置的默认不勾选）：",
        "cli_hint_nav" => "提示：方向键上下移动，空格选择，回车确认",
        "cli_collecting" => "开始收集配置参数...",
        "cli_will_execute" => "以下步骤将被执行：",
        "cli_confirm" => "是否继续？",
        "cli_cancelled" => "用户取消。",
        "cli_no_selection" => "未选择任何步骤，退出。",
        "cli_executing" => "开始执行加固步骤...",
        "cli_summary_title" => "本次加固总结报告",
        "cli_summary_total" => "总计: {ok} 成功, {fail} 失败/跳过",
        "cli_log_saved" => "日志已保存至 /var/log/secure-init.log",
        "cli_create_user" => "是否创建新的管理用户？",
        "cli_username_prompt" => "请输入新用户名",
        "cli_username_empty" => "用户名不能为空",
        "cli_username_exists" => "用户已存在",
        "cli_username_invalid" => "用户名只能包含字母、数字、- 和 _",
        "cli_lock_pw" => "锁定密码（强制密钥登录）？",
        "cli_current_port" => "当前 SSH 端口: {port}",
        "cli_default_port" => "22（默认）",
        "cli_suggest_port" => "建议端口: {port}",
        "cli_port_prompt" => "请输入新 SSH 端口（输入 0 跳过）",
        "cli_port_invalid" => "请输入有效数字",
        "cli_port_zero" => "端口 0 无效",
        "cli_existing_sudo" => "已有 sudo 用户: {users}",
        "cli_no_sudo" => "没有可用的 sudo 用户，跳过密钥设置",
        "cli_manual_user" => "未检测到 sudo 用户，请输入要设置密钥的目标用户名",
        "cli_user_prompt" => "目标用户名",
        "cli_no_input" => "未输入用户名，跳过密钥设置",
        "cli_select_user" => "选择要设置密钥的用户",
        "cli_key_found" => "用户 {user} 已有公钥: {fp}",
        "cli_key_action" => "为 {user} 设置 SSH 密钥",
        "cli_key_generate" => "生成新密钥对",
        "cli_key_paste" => "粘贴已有公钥",
        "cli_key_skip" => "跳过",
        "cli_key_prompt" => "请粘贴公钥内容（ssh-ed25519 AAA...）",
        "cli_ssh_port_info" => "当前 SSH 端口: {port_str}",
        "cli_ssh_suggest_info" => "建议端口: {port}",

        // ── TUI 界面 ──
        "tui_title" => "U2Secure — Linux 服务器安全加固工具",
        "tui_audit_report" => "审计报告",
        "tui_steps_title" => "加固步骤 ({n})",
        "tui_help_title" => "操作提示",
        "tui_help_move" => "移动光标",
        "tui_help_toggle" => "切换选择 / 取消",
        "tui_help_batch" => "批量执行选中的步骤",
        "tui_help_single" => "立即执行当前步骤",
        "tui_help_reauth" => "重新审计",
        "tui_help_quit" => "退出",
        "tui_selected_count" => "已勾选 {n} 项",
        "tui_single_hint" => "按 e 可强制执行任意单项",
        "tui_exec_title" => "执行状态",
        "tui_exec_running" => "正在执行: {step}",
        "tui_exec_done" => "已完成: {step}",
        "tui_exec_skip" => "跳过: {msg}",
        "tui_exec_failed" => "失败: {err}",
        "tui_exec_interrupted" => "用户中断",
        "tui_result_title" => "执行结果",
        "tui_result_summary" => "总计: {ok} 成功, {fail} 失败/跳过",
        "tui_result_return" => "按任意键返回步骤列表",
        "tui_footer_select" => {
            "↑↓/jk 移动 | Space 选择 | Enter 批量执行 | e 单项执行 | r 重新审计 | q 退出"
        },
        "tui_footer_exec" => "执行中... 按 Ctrl+C 中断",
        "tui_footer_summary" => "执行完毕 | 按任意键返回步骤列表",
        "tui_popup_username" => "目标用户名",
        "tui_popup_enter_user" => "输入用户名...",
        "tui_popup_select_user" => "选择用户",
        "tui_popup_select_action" => "选择操作",
        "tui_popup_gen_key" => "生成新密钥对",
        "tui_popup_paste_key" => "粘贴已有公钥",
        "tui_popup_skip" => "跳过",
        "tui_popup_paste_title" => "粘贴公钥",
        "tui_popup_paste_hint" => "粘贴 ssh-ed25519 / ssh-rsa 公钥内容...",
        "tui_popup_overwrite_title" => "密钥已存在",
        "tui_popup_overwrite_yes" => "重新创建 (覆盖现有密钥)",
        "tui_popup_overwrite_no" => "取消",
        "tui_popup_new_user" => "新用户名",
        "tui_popup_lock_title" => "锁定密码",
        "tui_popup_lock_yes" => "是 (锁定密码, 强制密钥登录)",
        "tui_popup_lock_no" => "否 (不锁定密码)",
        "tui_popup_port_title" => "新 SSH 端口",
        "tui_popup_port_suggest" => "建议端口: {port}",
        "tui_popup_port_current" => "当前: {port}",
        "tui_popup_port_placeholder" => "输入 0-65535...",
        "tui_popup_enter" => "Enter 确认",
        "tui_popup_esc" => "Esc 取消",
        "tui_popup_esc_back" => "Esc 返回",
        "tui_popup_updown" => "↑↓ 选择",
        "tui_popup_enter_confirm" => "Enter 确认",
        "tui_hint_enter_esc" => "Enter 确认  Esc 取消",
        "tui_hint_updown_enter_esc" => "↑↓ 选择  Enter 确认  Esc 取消",
        "tui_hint_enter_esc_back" => "Enter 确认  Esc 返回",
        "tui_hint_updown_enter_esc_back" => "↑↓ 选择  Enter 确认  Esc 返回",
        "tui_step_status_running" => "▶",
        "tui_step_status_done" => "✓",
        "tui_step_status_failed" => "✗",

        // ── 步骤执行中的日志 ──
        "log_running" => "正在执行: {step}",
        "log_completed" => "已完成: {step}",
        "log_skip" => "跳过: {msg}",
        "log_failed" => "失败: {err}",
        "log_interrupted" => "用户中断",

        _ => return None,
    })
}

// ===========================================================================
// English Translation Table
// ===========================================================================

fn en(key: &str) -> Option<&'static str> {
    Some(match key {
        "lang_en" => "English",
        "lang_zh_cn" => "简体中文",
        "lang_zh_tw" => "繁體中文",
        "select_language" => "Select Language",
        "select_mode" => "Select Launch Mode",
        "mode_cli" => "CLI Mode (Traditional Interactive)",
        "mode_tui" => "TUI Mode (Terminal GUI)",
        "unknown_arg" => "Unknown argument: {arg}, use -c (CLI) or -t (TUI)",
        "app_title" => "U2Secure — Linux Server Security Hardening Tool",

        "step_system_update" => "System Update",
        "step_user_creation" => "Non-root User Creation",
        "step_ssh_root_login" => "Disable Root SSH Login",
        "step_ssh_port_change" => "SSH Port Change",
        "step_ssh_password_auth" => "Disable Password Auth",
        "step_ssh_key_setup" => "ED25519 Key Setup",
        "step_ufw" => "UFW Firewall Config",
        "step_fail2ban" => "Fail2ban Install & Config",
        "step_auto_updates" => "Auto Security Updates",
        "step_security_scan" => "Security Scan",
        "step_log_audit" => "Log & Audit Enhancement",
        "step_restart_ssh" => "SSH Restart & Verify",

        "audit_root" => "Current User Privilege",
        "audit_pkg_mgr" => "Package Manager",
        "audit_ssh_port" => "SSH Port",
        "audit_password_auth" => "Password Auth",
        "audit_root_login" => "Root Login",
        "audit_sudo_users" => "Sudo Users",
        "audit_fail2ban" => "Fail2ban",
        "audit_ufw" => "UFW Firewall",
        "audit_auto_updates" => "Auto Security Updates",
        "audit_sys_update" => "System Update Status",
        "audit_detail_root_ok" => "Running as root",
        "audit_detail_root_missing" => "Not running as root, root required",
        "audit_detail_pkg" => "Detected {pkg}",
        "audit_detail_port_safe" => "Customized to {port}",
        "audit_detail_port_missing" => "Default port 22",
        "audit_detail_pw_disabled" => "Disabled",
        "audit_detail_pw_missing" => "Password auth not disabled",
        "audit_detail_root_disabled" => "Disabled",
        "audit_detail_root_missing_cfg" => "Root login not disabled",
        "audit_detail_sudo_missing" => "No non-root admin users",
        "audit_detail_sudo_ok" => "Existing: {users}",
        "audit_detail_fb_installed" => "Installed",
        "audit_detail_fb_missing" => "Not installed",
        "audit_detail_ufw_enabled" => "Enabled",
        "audit_detail_ufw_missing" => "Not enabled",
        "audit_detail_au_enabled" => "Enabled",
        "audit_detail_au_missing" => "Not enabled",
        "audit_detail_sys_uptodate" => "Cache not expired",
        "audit_detail_sys_needs_update" => "Cache expired, update recommended",

        "status_safe" => "✅",
        "status_partial" => "⚠️",
        "status_missing" => "❌",
        "status_needs_update" => "🔄",

        "pkg_apt" => "apt",
        "pkg_yum" => "yum",
        "pkg_dnf" => "dnf",
        "pkg_unknown" => "unknown",

        "err_permission_denied" => "Root permission required",
        "err_cmd_failed" => "System command failed: {msg}",
        "err_parse_error" => "Config parse error: {msg}",
        "err_precondition_failed" => "Precondition not met: {msg}",
        "err_user_aborted" => "User cancelled operation",

        // ── 错误详情 ──
        "err_unknown_pkg_mgr" => "Unrecognized package manager",
        "err_unsupported_pkg" => "Unsupported package manager",
        "err_auto_update_only_debian" => "Auto security updates only support Debian/Ubuntu",
        "err_unknown_pkg_lynis" => {
            "Cannot determine package manager, please install lynis manually"
        },
        "err_sshd_not_found" => "sshd_config not found",
        "err_no_username" => "No username provided",
        "err_user_exists" => "User '{user}' already exists",
        "err_no_sudo_before_root" => "Please create a sudo user before disabling root login",
        "err_no_ssh_port" => "No SSH port provided",
        "err_port_zero" => "Port 0 is invalid",
        "err_no_sudo_before_pw" => "Please create a sudo user before disabling password auth",
        "err_no_target_user" => "No target username provided",
        "err_no_key_action" => "No key action selected",
        "err_update_failed" => "update failed",
        "err_upgrade_failed" => "upgrade failed",
        "err_ufw_allow_failed" => "ufw allow failed",
        "err_ufw_enable_failed" => "ufw enable failed",
        "err_install_fail2ban" => "Installing fail2ban failed",
        "err_install_unattended" => "Installing unattended-upgrades failed",
        "err_lynis_exec" => "Lynis execution failed",
        "err_sshd_check" => "sshd syntax check failed",
        "err_sshd_syntax" => "sshd_config syntax error, please check configuration",
        "err_ssh_restart" => "SSH service restart failed",
        "err_backup" => "Backup failed",
        "err_read" => "Read failed",
        "err_write" => "Write failed",

        "result_sys_updated" => "System update completed",
        "result_user_created" => {
            "User '{user}' created with sudo, SSH key set (private key: ~/.ssh/id_ed25519)"
        },
        "result_root_login_set" => "PermitRootLogin set to prohibit-password (backup: {bak})",
        "result_ssh_port_set" => "SSH port changed to {port} ({msg})",
        "result_pw_auth_disabled" => "Password auth disabled (key-only login)",
        "result_key_generated" => {
            "ED25519 key pair generated\n  Private: {priv}\n  Public: {pub}\n  ⚠️  No passphrase set, encrypt manually: ssh-keygen -p -f {key}\n  Copy and save the private key now!"
        },
        "result_key_pasted" => "Public key added to {user}'s authorized_keys",
        "result_ufw_enabled" => "UFW enabled, SSH port {port} allowed",
        "result_fail2ban_installed" => "Fail2ban installed and running, SSH port {port} monitored",
        "result_auto_updates_enabled" => {
            "Auto security updates enabled (daily check, auto-install patches)"
        },
        "result_lynis_ok" => {
            "Lynis security scan completed ({warns} warnings, {suggs} suggestions)\n  Full report: /var/log/lynis.log"
        },
        "result_lynis_fail" => "Lynis could not be auto-installed, please install manually",
        "result_logwatch_installed" => {
            "Log & audit enhancement complete\n  Installed/configured: {installed}\n  logwatch: daily email report\n  aide: file integrity check initialized"
        },
        "result_ssh_restarted" => {
            "SSH service restarted (status: {status})\n  ⚠️  Verify connection in another terminal before closing this session!\n  🔄 Rollback: systemctl restart sshd or restore /etc/ssh/sshd_config.bak.*"
        },
        "result_sshd_cfg_set" => "{key} set to {value} (backup: {bak})",
        "result_sshd_syntax_ok" => "sshd_config syntax check passed",
        "result_sshd_syntax_err" => "sshd_config syntax error: {err}",

        "log_audit" => "[Audit]",
        "log_operation" => "[Operation]",
        "log_rollback" => "[Rollback]",
        "log_audit_start" => "Starting environment audit...",
        "log_audit_done" => "Completed, {n} items checked",
        "log_step_start" => "Starting",
        "log_step_complete" => "Completed",
        "log_step_failed" => "Failed",
        "log_rollback_auto" => "Step failed, auto-rolling back all registered changes",

        "undo_user_remove" => "Remove user '{user}'",
        "undo_pkg_remove" => "Remove {pkg}",
        "undo_cmd" => "{desc}",
        "undo_file_restore" => "Restore sshd_config ({key})",
        "undo_ufw_disable" => "Disable UFW firewall",
        "undo_ufw_delete" => "Delete UFW port {port} allow rule",
        "undo_key_delete" => "Delete SSH keys for {user}",

        "cli_welcome" => "U2Secure - Linux Server Security Hardening Tool v{ver}",
        "cli_auditing" => "Running environment audit...",
        "cli_audit_done" => "Environment audit completed:",
        "cli_select_steps" => {
            "Select hardening steps to execute (secure items are unchecked by default):"
        },
        "cli_hint_nav" => "Hint: arrow keys to move, space to select, enter to confirm",
        "cli_collecting" => "Collecting configuration parameters...",
        "cli_will_execute" => "The following steps will be executed:",
        "cli_confirm" => "Continue?",
        "cli_cancelled" => "Cancelled.",
        "cli_no_selection" => "No steps selected, exiting.",
        "cli_executing" => "Starting hardening steps...",
        "cli_summary_title" => "Hardening Summary Report",
        "cli_summary_total" => "Total: {ok} success, {fail} failed/skipped",
        "cli_log_saved" => "Log saved to /var/log/secure-init.log",
        "cli_create_user" => "Create a new admin user?",
        "cli_username_prompt" => "Enter new username",
        "cli_username_empty" => "Username cannot be empty",
        "cli_username_exists" => "User already exists",
        "cli_username_invalid" => "Username can only contain letters, numbers, - and _",
        "cli_lock_pw" => "Lock password (force key login)?",
        "cli_current_port" => "Current SSH port: {port}",
        "cli_default_port" => "22 (default)",
        "cli_suggest_port" => "Suggested port: {port}",
        "cli_port_prompt" => "Enter new SSH port (enter 0 to skip)",
        "cli_port_invalid" => "Enter a valid number",
        "cli_port_zero" => "Port 0 is invalid",
        "cli_existing_sudo" => "Existing sudo users: {users}",
        "cli_no_sudo" => "No sudo users available, skipping key setup",
        "cli_manual_user" => "No sudo users detected, enter target username for key setup",
        "cli_user_prompt" => "Target username",
        "cli_no_input" => "No username entered, skipping key setup",
        "cli_select_user" => "Select user for key setup",
        "cli_key_found" => "User {user} already has a public key: {fp}",
        "cli_key_action" => "Set up SSH key for {user}",
        "cli_key_generate" => "Generate new key pair",
        "cli_key_paste" => "Paste existing public key",
        "cli_key_skip" => "Skip",
        "cli_key_prompt" => "Paste public key content (ssh-ed25519 AAA...)",
        "cli_ssh_port_info" => "Current SSH port: {port_str}",
        "cli_ssh_suggest_info" => "Suggested port: {port}",

        "tui_title" => "U2Secure — Linux Server Security Hardening Tool",
        "tui_audit_report" => "Audit Report",
        "tui_steps_title" => "Steps ({n})",
        "tui_help_title" => "Help",
        "tui_help_move" => "Move cursor",
        "tui_help_toggle" => "Toggle select / unselect",
        "tui_help_batch" => "Batch execute selected steps",
        "tui_help_single" => "Execute current step immediately",
        "tui_help_reauth" => "Re-run audit",
        "tui_help_quit" => "Quit",
        "tui_selected_count" => "{n} selected",
        "tui_single_hint" => "Press e to execute any single step",
        "tui_exec_title" => "Execution Status",
        "tui_exec_running" => "Running: {step}",
        "tui_exec_done" => "Completed: {step}",
        "tui_exec_skip" => "Skipped: {msg}",
        "tui_exec_failed" => "Failed: {err}",
        "tui_exec_interrupted" => "Interrupted",
        "tui_result_title" => "Execution Result",
        "tui_result_summary" => "Total: {ok} success, {fail} failed/skipped",
        "tui_result_return" => "Press any key to return to step list",
        "tui_footer_select" => {
            "↑↓/jk Move | Space Toggle | Enter Batch | e Single | r Re-audit | q Quit"
        },
        "tui_footer_exec" => "Running... Press Ctrl+C to interrupt",
        "tui_footer_summary" => "Done | Press any key to return",
        "tui_popup_username" => "Target Username",
        "tui_popup_enter_user" => "Enter username...",
        "tui_popup_select_user" => "Select User",
        "tui_popup_select_action" => "Select Action",
        "tui_popup_gen_key" => "Generate new key pair",
        "tui_popup_paste_key" => "Paste existing public key",
        "tui_popup_skip" => "Skip",
        "tui_popup_paste_title" => "Paste Public Key",
        "tui_popup_paste_hint" => "Paste ssh-ed25519 / ssh-rsa public key...",
        "tui_popup_overwrite_title" => "Key Exists",
        "tui_popup_overwrite_yes" => "Recreate (overwrite existing key)",
        "tui_popup_overwrite_no" => "Cancel",
        "tui_popup_new_user" => "New Username",
        "tui_popup_lock_title" => "Lock Password",
        "tui_popup_lock_yes" => "Yes (lock password, force key login)",
        "tui_popup_lock_no" => "No (do not lock password)",
        "tui_popup_port_title" => "New SSH Port",
        "tui_popup_port_suggest" => "Suggested: {port}",
        "tui_popup_port_current" => "Current: {port}",
        "tui_popup_port_placeholder" => "Enter 0-65535...",
        "tui_popup_enter" => "Enter confirm",
        "tui_popup_esc" => "Esc cancel",
        "tui_popup_esc_back" => "Esc back",
        "tui_popup_updown" => "↑↓ select",
        "tui_popup_enter_confirm" => "Enter confirm",
        "tui_hint_enter_esc" => "Enter confirm  Esc cancel",
        "tui_hint_updown_enter_esc" => "↑↓ select  Enter confirm  Esc cancel",
        "tui_hint_enter_esc_back" => "Enter confirm  Esc back",
        "tui_hint_updown_enter_esc_back" => "↑↓ select  Enter confirm  Esc back",
        "tui_step_status_running" => "▶",
        "tui_step_status_done" => "✓",
        "tui_step_status_failed" => "✗",

        "log_running" => "Running: {step}",
        "log_completed" => "Completed: {step}",
        "log_skip" => "Skipped: {msg}",
        "log_failed" => "Failed: {err}",
        "log_interrupted" => "Interrupted",

        _ => return None,
    })
}

// ===========================================================================
// 繁體中文翻譯表
// ===========================================================================

fn zh_tw(key: &str) -> Option<&'static str> {
    Some(match key {
        "lang_en" => "English",
        "lang_zh_cn" => "简体中文",
        "lang_zh_tw" => "繁體中文",
        "select_language" => "選擇語言",
        "select_mode" => "請選擇啟動模式",
        "mode_cli" => "CLI 模式（傳統互動式）",
        "mode_tui" => "TUI 模式（終端圖形界面）",
        "unknown_arg" => "未知參數: {arg}，使用 -c (CLI) 或 -t (TUI)",
        "app_title" => "U2Secure — Linux 伺服器安全強化工具",

        "step_system_update" => "系統更新",
        "step_user_creation" => "非 root 用戶創建",
        "step_ssh_root_login" => "禁止 root SSH 登入",
        "step_ssh_port_change" => "SSH 連接埠修改",
        "step_ssh_password_auth" => "禁止密碼登入",
        "step_ssh_key_setup" => "ED25519 金鑰設定",
        "step_ufw" => "UFW 防火牆配置",
        "step_fail2ban" => "Fail2ban 安裝配置",
        "step_auto_updates" => "自動安全更新",
        "step_security_scan" => "安全掃描",
        "step_log_audit" => "日誌與稽核增強",
        "step_restart_ssh" => "SSH 服務重啟與驗證",

        "audit_root" => "當前用戶權限",
        "audit_pkg_mgr" => "套件管理器",
        "audit_ssh_port" => "SSH 連接埠",
        "audit_password_auth" => "密碼登入",
        "audit_root_login" => "root 登入",
        "audit_sudo_users" => "sudo 用戶",
        "audit_fail2ban" => "Fail2ban",
        "audit_ufw" => "UFW 防火牆",
        "audit_auto_updates" => "自動安全更新",
        "audit_sys_update" => "系統更新狀態",
        "audit_detail_root_ok" => "已以 root 執行",
        "audit_detail_root_missing" => "非 root 用戶，需要 root 權限",
        "audit_detail_pkg" => "檢測到 {pkg}",
        "audit_detail_port_safe" => "已自訂為 {port}",
        "audit_detail_port_missing" => "預設連接埠 22",
        "audit_detail_pw_disabled" => "已停用",
        "audit_detail_pw_missing" => "密碼登入未停用",
        "audit_detail_root_disabled" => "已禁止",
        "audit_detail_root_missing_cfg" => "root 登入未禁止",
        "audit_detail_sudo_missing" => "未檢測到非 root 管理用戶",
        "audit_detail_sudo_ok" => "已存在: {users}",
        "audit_detail_fb_installed" => "已安裝",
        "audit_detail_fb_missing" => "未安裝",
        "audit_detail_ufw_enabled" => "已啟用",
        "audit_detail_ufw_missing" => "未啟用",
        "audit_detail_au_enabled" => "已啟用",
        "audit_detail_au_missing" => "未啟用",
        "audit_detail_sys_uptodate" => "快取未過期",
        "audit_detail_sys_needs_update" => "快取已過期，建議更新",

        "status_safe" => "✅",
        "status_partial" => "⚠️",
        "status_missing" => "❌",
        "status_needs_update" => "🔄",

        "pkg_apt" => "apt",
        "pkg_yum" => "yum",
        "pkg_dnf" => "dnf",
        "pkg_unknown" => "unknown",

        "err_permission_denied" => "需要 root 權限執行",
        "err_cmd_failed" => "系統命令執行失敗: {msg}",
        "err_parse_error" => "配置解析錯誤: {msg}",
        "err_precondition_failed" => "前置條件不滿足: {msg}",
        "err_user_aborted" => "用戶取消操作",

        // ── 錯誤詳情 ──
        "err_unknown_pkg_mgr" => "無法識別的套件管理器",
        "err_unsupported_pkg" => "不支援的套件管理器",
        "err_auto_update_only_debian" => "自動安全更新僅支援 Debian/Ubuntu",
        "err_unknown_pkg_lynis" => "無法確定套件管理器，請手動安裝 lynis",
        "err_sshd_not_found" => "sshd_config 不存在",
        "err_no_username" => "未提供用戶名",
        "err_user_exists" => "用戶 '{user}' 已存在",
        "err_no_sudo_before_root" => "禁止 root 登入前請先創建 sudo 用戶",
        "err_no_ssh_port" => "未提供新 SSH 連接埠",
        "err_port_zero" => "連接埠 0 無效",
        "err_no_sudo_before_pw" => "禁止密碼登入前請先創建 sudo 用戶",
        "err_no_target_user" => "未提供目標用戶名",
        "err_no_key_action" => "未選擇金鑰操作",
        "err_update_failed" => "update 失敗",
        "err_upgrade_failed" => "upgrade 失敗",
        "err_ufw_allow_failed" => "ufw allow 失敗",
        "err_ufw_enable_failed" => "ufw enable 失敗",
        "err_install_fail2ban" => "安裝 fail2ban 失敗",
        "err_install_unattended" => "安裝 unattended-upgrades 失敗",
        "err_lynis_exec" => "lynis 執行失敗",
        "err_sshd_check" => "sshd 語法檢查失敗",
        "err_sshd_syntax" => "sshd_config 語法錯誤，請檢查配置",
        "err_ssh_restart" => "重啟 SSH 服務失敗",
        "err_backup" => "備份失敗",
        "err_read" => "讀取失敗",
        "err_write" => "寫入失敗",

        "result_sys_updated" => "系統更新完成",
        "result_user_created" => {
            "用戶 '{user}' 已創建並加入 sudo 群組，金鑰已設定（私鑰: ~/.ssh/id_ed25519）"
        },
        "result_root_login_set" => "PermitRootLogin 已設定為 prohibit-password（備份: {bak}）",
        "result_ssh_port_set" => "SSH 連接埠已修改為 {port}（{msg}）",
        "result_pw_auth_disabled" => "密碼登入已停用（僅允許金鑰登入）",
        "result_key_generated" => {
            "ED25519 金鑰對已生成\n  私鑰: {priv}\n  公鑰: {pub}\n  ⚠️  私鑰無密碼短語保護，建議手動加密：ssh-keygen -p -f {key}\n  請立即複製私鑰並安全儲存！"
        },
        "result_key_pasted" => "公鑰已添加到 {user} 的 authorized_keys",
        "result_ufw_enabled" => "UFW 已啟用，SSH 連接埠 {port} 已放行",
        "result_fail2ban_installed" => "Fail2ban 已安裝並執行，SSH 連接埠 {port} 已加入監控",
        "result_auto_updates_enabled" => "自動安全更新已啟用（每日檢查，自動安裝安全修補程式）",
        "result_lynis_ok" => {
            "lynis 安全掃描完成（{warns} 個警告, {suggs} 個建議）\n  詳細報告: /var/log/lynis.log"
        },
        "result_lynis_fail" => "lynis 無法自動安裝，請手動安裝後重新執行",
        "result_logwatch_installed" => {
            "日誌與稽核增強完成\n  已安裝/配置: {installed}\n  logwatch: 每日郵件報告\n  aide: 檔案完整性檢查已初始化"
        },
        "result_ssh_restarted" => {
            "SSH 服務已重新啟動（狀態: {status}）\n  ⚠️  請在另一個終端驗證連線後再關閉當前會話！\n  🔄 如需回退：systemctl restart sshd 或恢復備份 /etc/ssh/sshd_config.bak.*"
        },
        "result_sshd_cfg_set" => "{key} 已設定為 {value}（備份: {bak}）",
        "result_sshd_syntax_ok" => "sshd_config 語法檢查通過",
        "result_sshd_syntax_err" => "sshd_config 語法錯誤，請檢查配置: {err}",

        "log_audit" => "[稽核]",
        "log_operation" => "[操作]",
        "log_rollback" => "[回退]",
        "log_audit_start" => "開始環境稽核...",
        "log_audit_done" => "完成，共 {n} 項檢測",
        "log_step_start" => "開始執行",
        "log_step_complete" => "完成",
        "log_step_failed" => "失敗",
        "log_rollback_auto" => "步驟失敗，自動回退所有已註冊的修改",

        "undo_user_remove" => "刪除用戶 '{user}'",
        "undo_pkg_remove" => "刪除 {pkg}",
        "undo_cmd" => "{desc}",
        "undo_file_restore" => "恢復 sshd_config（{key}）",
        "undo_ufw_disable" => "關閉 UFW 防火牆",
        "undo_ufw_delete" => "刪除 UFW 連接埠 {port} 放行規則",
        "undo_key_delete" => "刪除 {user} 的金鑰檔案",

        "cli_welcome" => "U2Secure - Linux 伺服器安全強化工具 v{ver}",
        "cli_auditing" => "正在執行環境稽核...",
        "cli_audit_done" => "環境稽核完成：",
        "cli_select_steps" => "請選擇要執行的強化步驟（已安全配置的預設不勾選）：",
        "cli_hint_nav" => "提示：方向鍵上下移動，空格選擇，回車確認",
        "cli_collecting" => "開始收集配置參數...",
        "cli_will_execute" => "以下步驟將被執行：",
        "cli_confirm" => "是否繼續？",
        "cli_cancelled" => "用戶取消。",
        "cli_no_selection" => "未選擇任何步驟，退出。",
        "cli_executing" => "開始執行強化步驟...",
        "cli_summary_title" => "本次強化總結報告",
        "cli_summary_total" => "總計: {ok} 成功, {fail} 失敗/跳過",
        "cli_log_saved" => "日誌已儲存至 /var/log/secure-init.log",
        "cli_create_user" => "是否創建新的管理用戶？",
        "cli_username_prompt" => "請輸入新用戶名",
        "cli_username_empty" => "用戶名不能為空",
        "cli_username_exists" => "用戶已存在",
        "cli_username_invalid" => "用戶名只能包含字母、數字、- 和 _",
        "cli_lock_pw" => "鎖定密碼（強制金鑰登入）？",
        "cli_current_port" => "當前 SSH 連接埠: {port}",
        "cli_default_port" => "22（預設）",
        "cli_suggest_port" => "建議連接埠: {port}",
        "cli_port_prompt" => "請輸入新 SSH 連接埠（輸入 0 跳過）",
        "cli_port_invalid" => "請輸入有效數字",
        "cli_port_zero" => "連接埠 0 無效",
        "cli_existing_sudo" => "已有 sudo 用戶: {users}",
        "cli_no_sudo" => "沒有可用的 sudo 用戶，跳過金鑰設定",
        "cli_manual_user" => "未檢測到 sudo 用戶，請輸入要設定金鑰的目標用戶名",
        "cli_user_prompt" => "目標用戶名",
        "cli_no_input" => "未輸入用戶名，跳過金鑰設定",
        "cli_select_user" => "選擇要設定金鑰的用戶",
        "cli_key_found" => "用戶 {user} 已有公鑰: {fp}",
        "cli_key_action" => "為 {user} 設定 SSH 金鑰",
        "cli_key_generate" => "生成新金鑰對",
        "cli_key_paste" => "貼上已有公鑰",
        "cli_key_skip" => "跳過",
        "cli_key_prompt" => "請貼上公鑰內容（ssh-ed25519 AAA...）",
        "cli_ssh_port_info" => "當前 SSH 連接埠: {port_str}",
        "cli_ssh_suggest_info" => "建議連接埠: {port}",

        "tui_title" => "U2Secure — Linux 伺服器安全強化工具",
        "tui_audit_report" => "稽核報告",
        "tui_steps_title" => "強化步驟 ({n})",
        "tui_help_title" => "操作提示",
        "tui_help_move" => "移動游標",
        "tui_help_toggle" => "切換選擇 / 取消",
        "tui_help_batch" => "批次執行選中的步驟",
        "tui_help_single" => "立即執行當前步驟",
        "tui_help_reauth" => "重新稽核",
        "tui_help_quit" => "退出",
        "tui_selected_count" => "已勾選 {n} 項",
        "tui_single_hint" => "按 e 可強制執行任意單項",
        "tui_exec_title" => "執行狀態",
        "tui_exec_running" => "正在執行: {step}",
        "tui_exec_done" => "已完成: {step}",
        "tui_exec_skip" => "跳過: {msg}",
        "tui_exec_failed" => "失敗: {err}",
        "tui_exec_interrupted" => "用戶中斷",
        "tui_result_title" => "執行結果",
        "tui_result_summary" => "總計: {ok} 成功, {fail} 失敗/跳過",
        "tui_result_return" => "按任意鍵返回步驟列表",
        "tui_footer_select" => {
            "↑↓/jk 移動 | Space 選擇 | Enter 批次執行 | e 單項執行 | r 重新稽核 | q 退出"
        },
        "tui_footer_exec" => "執行中... 按 Ctrl+C 中斷",
        "tui_footer_summary" => "執行完畢 | 按任意鍵返回步驟列表",
        "tui_popup_username" => "目標用戶名",
        "tui_popup_enter_user" => "輸入用戶名...",
        "tui_popup_select_user" => "選擇用戶",
        "tui_popup_select_action" => "選擇操作",
        "tui_popup_gen_key" => "生成新金鑰對",
        "tui_popup_paste_key" => "貼上已有公鑰",
        "tui_popup_skip" => "跳過",
        "tui_popup_paste_title" => "貼上公鑰",
        "tui_popup_paste_hint" => "貼上 ssh-ed25519 / ssh-rsa 公鑰內容...",
        "tui_popup_overwrite_title" => "金鑰已存在",
        "tui_popup_overwrite_yes" => "重新建立 (覆蓋現有金鑰)",
        "tui_popup_overwrite_no" => "取消",
        "tui_popup_new_user" => "新用戶名",
        "tui_popup_lock_title" => "鎖定密碼",
        "tui_popup_lock_yes" => "是 (鎖定密碼, 強制金鑰登入)",
        "tui_popup_lock_no" => "否 (不鎖定密碼)",
        "tui_popup_port_title" => "新 SSH 連接埠",
        "tui_popup_port_suggest" => "建議連接埠: {port}",
        "tui_popup_port_current" => "當前: {port}",
        "tui_popup_port_placeholder" => "輸入 0-65535...",
        "tui_popup_enter" => "Enter 確認",
        "tui_popup_esc" => "Esc 取消",
        "tui_popup_esc_back" => "Esc 返回",
        "tui_popup_updown" => "↑↓ 選擇",
        "tui_popup_enter_confirm" => "Enter 確認",
        "tui_hint_enter_esc" => "Enter 確認  Esc 取消",
        "tui_hint_updown_enter_esc" => "↑↓ 選擇  Enter 確認  Esc 取消",
        "tui_hint_enter_esc_back" => "Enter 確認  Esc 返回",
        "tui_hint_updown_enter_esc_back" => "↑↓ 選擇  Enter 確認  Esc 返回",
        "tui_step_status_running" => "▶",
        "tui_step_status_done" => "✓",
        "tui_step_status_failed" => "✗",

        "log_running" => "正在執行: {step}",
        "log_completed" => "已完成: {step}",
        "log_skip" => "跳過: {msg}",
        "log_failed" => "失敗: {err}",
        "log_interrupted" => "用戶中斷",

        _ => return None,
    })
}
