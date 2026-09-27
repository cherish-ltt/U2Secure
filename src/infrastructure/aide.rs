//! AIDE 文件完整性检查的配置发现与初始化编排
//!
//! 关键背景：部分发行版的 `aide` 包**只安装二进制**，配置文件由独立包提供
//! （Debian/Ubuntu 为 `aide-common`，配置文件 `/etc/aide/aide.conf`）。
//! 只装 `aide` 时执行 `aide --init` 会以退出码 17（Configuration error）
//! 失败并报 `missing configuration`。本模块负责：
//!
//! 1. 定位可用配置：`aide.wrapper` → 标准路径 → 生成最小可用配置兜底
//! 2. 从配置中解析数据库路径（不写死 `/var/lib/aide`，兼容 RH 系与自定义布局）
//! 3. 构造 `--init` / `--check` 命令，并在初始化后提升数据库、验证可用性

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::domain::audit::PackageManager;
use crate::domain::errors::DomainError;
use crate::infrastructure::system::{self, StreamStatus};

/// 初始化与完整性检查的超时（全盘哈希较慢，两者一致）
pub const TIMEOUT_AIDE: Duration = Duration::from_secs(1800);

/// 配置错误的 AIDE 退出码（Configuration error，见 aide(1) 的 EXIT STATUS）
const EXIT_CONFIG_ERROR: i32 = 17;

/// 兜底配置文件名（写入报告目录，不覆盖发行版配置）
pub const FALLBACK_CONF_NAME: &str = "aide-u2secure.conf";

/// 兜底数据库文件名：刻意区别于发行版默认的 `aide.db`，避免覆盖既有基线
pub const FALLBACK_DB_NAME: &str = "aide-u2secure.db";

/// 兜底配置的 `database_out` 文件名（aide 约定的 `.new` 中间产物）
pub const FALLBACK_DB_OUT_NAME: &str = "aide-u2secure.db.new";

/// 兜底配置首行标记：用于识别"本工具生成的配置"，避免覆盖用户自己的配置
const FALLBACK_MARKER: &str = "# 由 U2Secure 生成：发行版未提供可用 aide.conf";

/// 兜底数据库路径：优先配合发行版目录，目录不存在时落在报告目录
const DB_CANDIDATES: &[&str] = &["/var/lib/aide", "/var/lib"];

/// 解析出的 AIDE 配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AidePlan {
    /// 配置来源："system"（发行版提供）或 "generated"（本次生成）
    pub source: &'static str,
    /// 实际使用的 aide.conf 路径；`None` 表示依赖 aide 自身默认值
    pub config: Option<PathBuf>,
    /// `aide --init` 写出的新数据库路径
    pub database_out: PathBuf,
    /// `aide --check` 读取的基线数据库路径
    pub database_in: PathBuf,
}

impl AidePlan {
    pub fn use_system_config(path: PathBuf) -> Self {
        Self {
            source: "system",
            config: Some(path),
            database_out: PathBuf::from("/var/lib/aide/aide.db.new"),
            database_in: PathBuf::from("/var/lib/aide/aide.db"),
        }
    }
}

/// 发行版可能提供 aide.conf 的标准位置
pub fn standard_config_paths(pm: PackageManager) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if pm == PackageManager::Apt {
        paths.push(PathBuf::from("/etc/aide/aide.conf"));
    }
    paths.push(PathBuf::from("/etc/aide.conf"));
    paths
}

/// Debian/Ubuntu 的 `aide` 包只装二进制，配置与 `aideinit` 由 `aide-common` 提供
pub fn companion_packages(pm: PackageManager) -> &'static [&'static str] {
    match pm {
        PackageManager::Apt => &["aide-common"],
        _ => &[],
    }
}

/// 从 `aideinit` 中读取其默认配置路径（Debian 提供 `-c`，故不会歧义）
fn wrapper_config_path(wrapper: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(wrapper).ok()?;
    for line in text.lines() {
        let line = line.trim().trim_start_matches("export ").trim();
        let Some(rest) = line.strip_prefix("CONFIG=") else {
            continue;
        };
        // CONFIG="${CONFIG:-/etc/aide/aide.conf}" 与 CONFIG=/etc/aide.conf 两种写法
        let value = rest.trim().trim_matches('"').trim_matches('\'');
        let candidate = value
            .rsplit_once(":-")
            .map(|(_, default)| default)
            .unwrap_or(value)
            .trim_end_matches('}');
        if candidate.starts_with('/') && Path::new(candidate).is_file() {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

/// 探测配置与数据库路径（`aideinit`/`aide.wrapper` → 系统标准路径 → 兜底数据库路径）
pub fn detect_plan(pm: PackageManager) -> AidePlan {
    for wrapper in ["/usr/sbin/aideinit", "/usr/bin/aide.wrapper"] {
        if let Some(path) = wrapper_config_path(Path::new(wrapper)) {
            let mut plan = AidePlan::use_system_config(path);
            plan.reload_database_paths();
            return plan;
        }
    }
    for path in standard_config_paths(pm) {
        if path.is_file() {
            let mut plan = AidePlan::use_system_config(path);
            plan.reload_database_paths();
            return plan;
        }
    }
    let mut plan = fallback_plan(Path::new("/tmp"));
    plan.source = "missing";
    plan
}

/// 生成兜底配置的路径规划
///
/// 数据库使用**独立文件名**（`aide-u2secure.db`），避免与系统既有基线
/// `/var/lib/aide/aide.db` 同名而覆盖它；配置本身写入报告目录，不触碰 `/etc`。
pub fn fallback_plan(report_dir: &Path) -> AidePlan {
    let db_dir = DB_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir() && is_writable_dir(p))
        .or_else(|| DB_CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_dir()))
        .unwrap_or_else(|| report_dir.to_path_buf());
    AidePlan {
        source: "generated",
        config: Some(report_dir.join(FALLBACK_CONF_NAME)),
        database_out: db_dir.join(FALLBACK_DB_OUT_NAME),
        database_in: db_dir.join(FALLBACK_DB_NAME),
    }
}

/// 目录是否可写（不可写时换用报告目录，避免初始化必然失败）
fn is_writable_dir(path: &Path) -> bool {
    let probe = path.join(format!(".u2secure-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        },
        Err(_) => false,
    }
}

impl AidePlan {
    /// 用配置里的 `database_in` / `database_out` 覆盖默认数据库路径
    fn reload_database_paths(&mut self) {
        let Some(conf) = self
            .config
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
        else {
            return;
        };
        if let Some(out) = parse_database_path(&conf, "database_out") {
            self.database_out = out;
        }
        if let Some(input) = parse_database_path(&conf, "database_in") {
            self.database_in = input;
        }
    }

    /// `database_out` / `database_in` 的实际落盘路径（含 gzip 变体）
    pub fn existing_database(&self, path: &Path) -> Option<PathBuf> {
        gzip_variants(path).into_iter().find(|p| p.is_file())
    }

    /// 数据库是否已初始化（存在 `database_in` 对应文件）
    pub fn database_ready(&self) -> bool {
        self.existing_database(&self.database_in).is_some()
    }

    /// 构造 `--init` 命令：优先发行版包装器（含权限与日志处理），否则直接调用 aide
    pub fn init_command(&self) -> AideCommand {
        let wrapper = ["/usr/sbin/aideinit", "/usr/bin/aideinit"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file());
        match (wrapper, self.config.as_ref()) {
            // aideinit 会读取配置里的 database_* 并把 aide 输出重定向到 /var/log/aide
            (Some(wrapper), Some(conf)) => AideCommand {
                argv: vec![
                    wrapper.to_string_lossy().into_owned(),
                    "-y".into(),
                    "-f".into(),
                    "-c".into(),
                    conf.to_string_lossy().into_owned(),
                ],
            },
            (Some(wrapper), None) => AideCommand {
                argv: vec![
                    wrapper.to_string_lossy().into_owned(),
                    "-y".into(),
                    "-f".into(),
                ],
            },
            (None, conf) => {
                let mut argv = vec!["aide".to_string()];
                push_config(&mut argv, conf);
                argv.push("--init".into());
                AideCommand { argv }
            },
        }
    }

    /// 构造 `--config-check` 命令：只读校验配置语法
    pub fn config_check_command(&self) -> AideCommand {
        let mut argv = vec!["aide".to_string()];
        push_config(&mut argv, self.config.as_ref());
        argv.push("--config-check".into());
        AideCommand { argv }
    }

    /// 构造 `--check` 命令
    pub fn check_command(&self) -> AideCommand {
        let mut argv = vec!["aide".to_string()];
        push_config(&mut argv, self.config.as_ref());
        argv.push("--check".into());
        AideCommand { argv }
    }

    /// 数据库当前归属的路径与权限摘要（报告用）
    pub fn database_metadata(&self) -> String {
        let Some(path) = self.existing_database(&self.database_in) else {
            return String::new();
        };
        match read_mode(&path) {
            Some(mode) => format!("{} (mode={mode:o})", path.display()),
            None => path.display().to_string(),
        }
    }
}

/// 待执行命令
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AideCommand {
    pub argv: Vec<String>,
}

fn push_config(argv: &mut Vec<String>, config: Option<&PathBuf>) {
    if let Some(conf) = config {
        argv.push(format!("--config={}", conf.display()));
    }
}

/// 解析配置中的 `database_in` / `database_out`（兼容 `key = file:/x` 与 `key=file:/x`）
pub fn parse_database_path(config: &str, key: &str) -> Option<PathBuf> {
    for raw in config.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value.trim();
        let value = value.strip_prefix("file:").unwrap_or(value);
        if value.is_empty() {
            return None;
        }
        return Some(PathBuf::from(value));
    }
    None
}

/// 数据库文件的 gzip 变体（`gzip_dbout=yes` 时输出 `.gz`）
pub fn gzip_variants(path: &Path) -> Vec<PathBuf> {
    let plain = path.to_path_buf();
    if path.extension().is_some_and(|e| e == "gz") {
        return vec![plain];
    }
    vec![plain, PathBuf::from(format!("{}.gz", path.display()))]
}

/// 生成最小可用 AIDE 配置：只使用各版本通用的配置项，不依赖发行版 conf.d
pub fn render_fallback_config(plan: &AidePlan) -> String {
    format!(
        "\
{FALLBACK_MARKER}
# 生成原因：系统缺少可用的 aide 配置（aide 已安装但未提供 aide.conf）
# 数据库使用独立文件名，不会覆盖系统既有的 aide.db 基线
# 请勿手工修改：重新执行步骤 11 会按需重建本文件
# 如需自定义规则，请改用发行版配置 /etc/aide/aide.conf

database_in=file:{db_in}
database_out=file:{db_out}
database_new=file:{db_out}

# 兜底配置固定输出未压缩数据库，便于识别与校验
gzip_dbout=no
report_ignore_e2fsattrs=VNIE

Checksums = H
OwnerMode = p+u+g+ftype
Size = s+b
InodeData = OwnerMode+n+i+Size+l+X
StaticFile = m+c+Checksums
Full = InodeData+StaticFile
VarTime = InodeData+Checksums
VarFile = OwnerMode+n+l+X
VarDir = OwnerMode+n+i+X
Log = OwnerMode+n+S
GrowingLog = OwnerMode+n+S+Checksums
Reptile = OwnerMode+n+X
StaticDir = OwnerMode+n+i+X

# 配置与日志
/etc Full
!/etc/mtab
!/etc/.*~
!/etc/aide/aide.conf
!/etc/aide/aide.conf.d
!/etc/ssl/certs
/bin Full
/sbin Full
/usr/bin Full
/usr/sbin Full
/lib Full
/lib64 Full
/opt Full
!/var/log/.*
/var/log VarDir
/var/log/aide Log
/var/log/u2secure GrowingLog
/root Full
!/root/.*history
!/root/.*cache
",
        db_in = plan.database_in.display(),
        db_out = plan.database_out.display(),
    )
}

/// 写入兜底配置并返回可用的 plan
///
/// 复用上次生成的配置以保持数据库路径稳定；若目标路径存在**且不是**本工具生成的
/// 文件，则换用带时间戳的文件名，绝不覆盖用户自己的配置。
pub fn ensure_fallback_config(plan: &mut AidePlan) -> Result<(), DomainError> {
    let Some(path) = plan.config.clone() else {
        return Err(DomainError::SystemCommandFailed(
            "兜底配置缺少目标路径".into(),
        ));
    };
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing.starts_with(FALLBACK_MARKER) => {
            restrict(&path, 0o644);
            Ok(())
        },
        Ok(_) => {
            let unique = path.with_file_name(format!(
                "aide-u2secure-{}.conf",
                crate::infrastructure::artifacts::stamp()
            ));
            plan.config = Some(unique.clone());
            write_config(&unique, plan)
        },
        Err(_) => write_config(&path, plan),
    }
}

/// 生成配置内容并落盘
fn write_config(path: &Path, plan: &AidePlan) -> Result<(), DomainError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            DomainError::SystemCommandFailed(format!("创建 {} 失败: {e}", parent.display()))
        })?;
    }
    std::fs::write(path, render_fallback_config(plan)).map_err(|e| {
        DomainError::SystemCommandFailed(format!("写入 {} 失败: {e}", path.display()))
    })?;
    restrict(path, 0o644);
    Ok(())
}

/// 写入每日检查脚本内容（发行版已有机制时不会调用）
pub fn render_daily_script(config: Option<&Path>, log_dir: &str) -> String {
    let mut check = String::from("aide");
    if let Some(conf) = config {
        check.push_str(&format!(" --config={}", conf.display()));
    }
    check.push_str(" --check");
    format!(
        "#!/bin/bash\n\
# 由 U2Secure 生成：每日文件完整性检查\n\
AIDE_LOG=\"{log_dir}/aide-check-$(date +%F).log\"\n\
mkdir -p \"$(dirname \"$AIDE_LOG\")\"\n\
{check} > \"$AIDE_LOG\" 2>&1\n\
rc=$?\n\
# 退出码 1-7 表示检测到文件差异（正常结果），>=14 才是执行错误\n\
if [ \"$rc\" -ge 14 ]; then\n\
    echo \"AIDE 检查失败，退出码 $rc，详见 $AIDE_LOG\" >&2\n\
    exit \"$rc\"\n\
fi\n\
exit 0\n"
    )
}

/// 初始化 AIDE 数据库：执行 `--init`，提升数据库，并以 `--check` 验证可用
pub fn initialize_database(
    plan: &AidePlan,
    log: &Path,
    check_log: &Path,
) -> Result<(), DomainError> {
    let command = plan.init_command();
    let status = run_command(&command, log)?;
    if !status.is_success() {
        return Err(DomainError::SystemCommandFailed(format!(
            "{}: {}",
            init_failure_hint(&status, plan),
            status.describe()
        )));
    }

    promote_database(plan)?;

    // 初始化成功不等于可用：立即以 --check 验证基线可读
    let check = plan.check_command();
    let status = run_command(&check, check_log)?;
    if !status.is_success() && !is_difference_exit(&status) {
        return Err(DomainError::SystemCommandFailed(format!(
            "aide --check 验证失败：{}",
            status.describe()
        )));
    }
    Ok(())
}

/// 只读校验配置语法；返回错误说明（配置有问题时不应继续初始化）
pub fn config_problem(plan: &AidePlan, log: &Path) -> Result<Option<String>, DomainError> {
    let command = plan.config_check_command();
    let status = run_command(&command, log)?;
    if status.is_success() {
        return Ok(None);
    }
    Ok(Some(status.describe()))
}

/// 执行 AIDE 命令（子进程 stdin 恒为 null，不会抢终端输入）
fn run_command(command: &AideCommand, log: &Path) -> Result<StreamStatus, DomainError> {
    system::run_streaming_argv(&command.argv, &[], &log.to_string_lossy(), TIMEOUT_AIDE)
}

/// 重命名/复制新数据库为正式基线（Debian 的 aideinit 会自行 `cp`，此处做兜底）
fn promote_database(plan: &AidePlan) -> Result<(), DomainError> {
    if plan.database_ready() {
        return Ok(());
    }
    let Some(new_db) = plan.existing_database(&plan.database_out) else {
        return Err(DomainError::SystemCommandFailed(format!(
            "初始化后未生成新数据库：{}",
            plan.database_out.display()
        )));
    };
    std::fs::copy(&new_db, &plan.database_in).map_err(|e| {
        DomainError::SystemCommandFailed(format!(
            "提升数据库 {} -> {} 失败: {e}",
            new_db.display(),
            plan.database_in.display()
        ))
    })?;
    restrict(&plan.database_in, 0o600);
    Ok(())
}

/// `aide --check` 的退出码 1-7 表示报告了文件差异，属于正常结果
pub fn is_difference_exit(status: &StreamStatus) -> bool {
    matches!(status, StreamStatus::Failed(Some(code)) if (1..=7).contains(code))
}

/// 初始化失败时给出可操作的原因提示（不掩盖原始错误）
fn init_failure_hint(status: &StreamStatus, plan: &AidePlan) -> String {
    match status {
        StreamStatus::Failed(Some(EXIT_CONFIG_ERROR)) => format!(
            "AIDE 配置错误（退出码 {EXIT_CONFIG_ERROR}），配置文件: {}",
            plan.config
                .as_ref()
                .map(|c| c.display().to_string())
                .unwrap_or_else(|| "未找到".into())
        ),
        _ => "AIDE 数据库初始化失败".to_string(),
    }
}

fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// 读取文件权限位（非 unix 平台返回 None）
fn read_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o7777)
            .ok()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_CONF: &str = "\
# AIDE conf
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
@@x_include /etc/aide/aide.conf.d ^[a-zA-Z0-9_-]+$
";

    #[test]
    fn parse_database_path_reads_both_spellings() {
        assert_eq!(
            parse_database_path(DEBIAN_CONF, "database_in"),
            Some(PathBuf::from("/var/lib/aide/aide.db"))
        );
        assert_eq!(
            parse_database_path("database_out = file:/custom/db.new", "database_out"),
            Some(PathBuf::from("/custom/db.new"))
        );
        assert_eq!(
            parse_database_path("database_in=/plain/aide.db", "database_in"),
            Some(PathBuf::from("/plain/aide.db"))
        );
        assert_eq!(parse_database_path(DEBIAN_CONF, "database_new"), None);
    }

    #[test]
    fn parse_database_path_ignores_comments_and_prefix_collisions() {
        let conf = "# database_in=file:/commented\ndatabase_inx=file:/wrong\n";
        assert_eq!(parse_database_path(conf, "database_in"), None);
    }

    #[test]
    fn reload_database_paths_overrides_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conf = dir.path().join("aide.conf");
        std::fs::write(
            &conf,
            "database_in=file:/srv/aide.db\ndatabase_out=file:/srv/aide.db.new\n",
        )
        .expect("write");
        let mut plan = AidePlan::use_system_config(conf);
        plan.reload_database_paths();
        assert_eq!(plan.database_in, PathBuf::from("/srv/aide.db"));
        assert_eq!(plan.database_out, PathBuf::from("/srv/aide.db.new"));
    }

    #[test]
    fn fallback_config_is_self_contained() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = AidePlan {
            source: "generated",
            config: Some(dir.path().join(FALLBACK_CONF_NAME)),
            database_out: dir.path().join("aide.db.new"),
            database_in: dir.path().join("aide.db"),
        };
        let conf = render_fallback_config(&plan);
        assert_eq!(
            parse_database_path(&conf, "database_in"),
            Some(plan.database_in.clone())
        );
        assert_eq!(
            parse_database_path(&conf, "database_out"),
            Some(plan.database_out.clone())
        );
        // 兜底配置必须固定为未压缩输出，否则数据库提升逻辑会找不到文件
        assert!(conf.contains("gzip_dbout=no"));
        // 不得包含依赖发行版 conf.d 的包含指令
        assert!(!conf.contains("@@x_include"));
        dir.close().ok();
    }

    #[test]
    fn init_command_prefers_config_explicitly() {
        let plan = AidePlan {
            source: "generated",
            config: Some(PathBuf::from("/tmp/aide-u2secure.conf")),
            database_out: PathBuf::from("/var/lib/aide/aide.db.new"),
            database_in: PathBuf::from("/var/lib/aide/aide.db"),
        };
        let argv = plan.init_command().argv;
        // 无论走 aideinit 还是 aide，都必须显式带 -c/--config
        assert!(
            argv.iter().any(|a| a == "-c" || a.starts_with("--config")),
            "init 命令必须显式指定配置: {argv:?}"
        );
    }

    #[test]
    fn check_command_passes_config_and_requests_check() {
        let plan = AidePlan::use_system_config(PathBuf::from("/etc/aide/aide.conf"));
        let command = plan.check_command();
        assert!(
            command
                .argv
                .iter()
                .any(|a| a == "--config=/etc/aide/aide.conf")
        );
        assert_eq!(command.argv.last().map(String::as_str), Some("--check"));
    }

    #[test]
    fn config_check_command_uses_config_check_flag() {
        let plan = AidePlan::use_system_config(PathBuf::from("/etc/aide/aide.conf"));
        assert_eq!(
            plan.config_check_command().argv.last().map(String::as_str),
            Some("--config-check")
        );
    }

    #[test]
    fn config_problem_reports_configuration_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("aide.log");
        let broken = AidePlan::use_system_config(dir.path().join("missing.conf"));
        let problem = config_problem(&broken, &log);
        // 测试机（macOS）没有 aide：命令无法启动属于环境问题，不是本测试的断言目标
        let Ok(Some(reason)) = problem else {
            return;
        };
        assert!(reason.contains("17"), "原因应包含原始退出码: {reason}");
    }

    #[test]
    fn fallback_config_reuses_own_file_but_never_overwrites_foreign_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join(FALLBACK_CONF_NAME);
        std::fs::write(&target, format!("{FALLBACK_MARKER}\n# 上次生成\n")).expect("write");

        let mut plan = AidePlan {
            source: "generated",
            config: Some(target.clone()),
            database_out: dir.path().join("aide.db.new"),
            database_in: dir.path().join("aide.db"),
        };
        ensure_fallback_config(&mut plan).expect("复用自身配置");
        assert_eq!(plan.config.as_ref(), Some(&target), "应复用自己生成的配置");

        // 用户自己放了同名文件：必须换名，绝不覆盖
        let mut foreign = AidePlan {
            source: "generated",
            config: Some(target.clone()),
            database_out: dir.path().join("aide.db.new"),
            database_in: dir.path().join("aide.db"),
        };
        std::fs::write(&target, "# 这是用户自己的规则\n/important Full\n").expect("write");
        ensure_fallback_config(&mut foreign).expect("写入新配置");
        assert_ne!(foreign.config.as_ref(), Some(&target), "不得覆盖用户配置");
        assert_eq!(
            std::fs::read_to_string(&target).expect("用户文件仍在"),
            "# 这是用户自己的规则\n/important Full\n"
        );
        let generated = foreign.config.clone().expect("新配置路径");
        let content = std::fs::read_to_string(&generated).expect("新配置已写入");
        assert!(content.starts_with(FALLBACK_MARKER));
        assert!(
            parse_database_path(&content, "database_in").is_some(),
            "新配置必须写入真实数据库路径"
        );
        dir.close().ok();
    }

    #[test]
    fn companion_packages_only_debian() {
        assert_eq!(companion_packages(PackageManager::Apt), ["aide-common"]);
        assert!(companion_packages(PackageManager::Dnf).is_empty());
        assert!(companion_packages(PackageManager::Yum).is_empty());
    }

    #[test]
    fn fallback_plan_never_reuses_distro_database_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = fallback_plan(dir.path());
        // 兜底路径必须与发行版默认基线区分，否则可能覆盖系统已有数据库
        assert_ne!(plan.database_in.file_name().unwrap(), "aide.db");
        assert_ne!(plan.database_out.file_name().unwrap(), "aide.db.new");
        assert_eq!(plan.database_in.file_name().unwrap(), FALLBACK_DB_NAME);
        assert!(
            plan.database_out.to_string_lossy().ends_with(".db.new"),
            "database_out 应为 aide 约定的 .new 中间产物: {:?}",
            plan.database_out
        );
        // 配置落在报告目录，不写 /etc
        assert_eq!(
            plan.config.as_ref().unwrap().parent(),
            Some(dir.path()),
            "兜底配置必须写入报告目录"
        );
    }

    #[test]
    fn difference_exit_codes_are_not_errors() {
        assert!(is_difference_exit(&StreamStatus::Failed(Some(1))));
        assert!(is_difference_exit(&StreamStatus::Failed(Some(7))));
        assert!(!is_difference_exit(&StreamStatus::Failed(Some(17))));
        assert!(!is_difference_exit(&StreamStatus::Success));
    }

    #[test]
    fn gzip_variants_cover_compressed_output() {
        let plain = PathBuf::from("/var/lib/aide/aide.db");
        let variants = gzip_variants(&plain);
        assert_eq!(variants[0], plain);
        assert_eq!(variants[1], PathBuf::from("/var/lib/aide/aide.db.gz"));
        assert_eq!(gzip_variants(&PathBuf::from("/x/aide.db.gz")).len(), 1);
    }

    #[test]
    fn daily_script_tolerates_difference_exit_codes() {
        let script =
            render_daily_script(Some(Path::new("/etc/aide/aide.conf")), "/var/log/u2secure");
        assert!(script.contains("--config=/etc/aide/aide.conf --check"));
        assert!(script.contains("-ge 14"));
        assert!(script.contains("/var/log/u2secure/aide-check-"));
    }
}
