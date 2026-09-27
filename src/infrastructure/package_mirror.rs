//! 临时软件源（镜像仓库）—— 加速软件包下载
//!
//! 设计取舍：**不修改系统任何文件**。
//! - apt：把改写后的源写入临时目录，通过
//!   `apt -o Dir::Etc::sourcelist=... -o Dir::Etc::sourceparts=... -o APT::Get::List-Cleanup=0`
//!   覆盖本次调用的源列表；原始 `/etc/apt/sources.list` 完全不动。
//! - dnf/yum：复制并改写 repo 文件到临时目录，通过 `--setopt=reposdir=...` 覆盖。
//!
//! 临时目录由 `TempDir` 持有，进程退出（含 panic）时自动删除，无需回滚。

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::domain::audit::PackageManager;
use crate::domain::errors::DomainError;
use crate::domain::mirror::PackageMirror;
use crate::domain::steps::MirrorOverride;
use crate::infrastructure::system;

/// 延迟探测超时
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// 预热尝试次数（含首次）
pub const WARM_UP_ATTEMPTS: usize = 3;
/// 单次预热尝试的最长等待
const WARM_UP_TIMEOUT: Duration = Duration::from_secs(300);
/// 连续无输出即判定"源无响应"
pub const WARM_UP_STALL: Duration = Duration::from_secs(30);

/// 已知的上游主机（只替换这些主机，避免误改内网/自建源）
const UPSTREAM_HOSTS: &[&str] = &[
    // Ubuntu
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "cn.archive.ubuntu.com",
    "old-releases.ubuntu.com",
    // Debian
    "deb.debian.org",
    "ftp.debian.org",
    "security.debian.org",
    "debian.map.fastlydns.net",
    // CentOS / Rocky / Fedora（yum/dnf baseurl）
    "mirror.centos.org",
    "mirrorlist.centos.org",
    "dl.rockylinux.org",
    "dl.fedoraproject.org",
    "download.fedoraproject.org",
];

/// 探测镜像延迟（TCP 443 建连耗时）；不可达或 DNS 失败返回 None
pub fn probe_latency(mirror: &PackageMirror) -> Option<Duration> {
    let host = mirror.probe_host()?;
    let addr = (host.as_str(), 443).to_socket_addrs().ok()?.next()?;
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        Ok(_) => Some(started.elapsed()),
        Err(_) => None,
    }
}

/// 把内容中的已知上游主机替换为镜像主机（路径与查询串保持不变）
///
/// 纯函数，便于单元测试。
pub fn rewrite_hosts(content: &str, mirror: &PackageMirror) -> (String, usize) {
    let Some(target) = mirror.probe_host() else {
        return (content.to_string(), 0);
    };
    let mut result = content.to_string();
    let mut hits = 0;
    for host in UPSTREAM_HOSTS {
        let (new_result, n) = replace_host(&result, host, &target);
        result = new_result;
        hits += n;
    }
    (result, hits)
}

/// 替换 `//<host>` 出现处，仅当其后面是路径分隔符/空白/引号/行尾（避免误伤 `host.evil.com`）
fn replace_host(content: &str, host: &str, target: &str) -> (String, usize) {
    let needle = format!("//{host}");
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    let mut hits = 0;
    while let Some(idx) = rest.find(&needle) {
        let after = idx + needle.len();
        let next = rest[after..].chars().next();
        let boundary = matches!(next, None | Some('/') | Some('"') | Some('\'') | Some('#'))
            || next.is_some_and(char::is_whitespace);
        out.push_str(&rest[..idx]);
        if boundary {
            out.push_str("//");
            out.push_str(target);
            hits += 1;
        } else {
            out.push_str(&needle);
        }
        rest = &rest[after..];
    }
    out.push_str(rest);
    (out, hits)
}

/// 改写 yum/dnf repo 内容：只处理 `baseurl=` 行，`mirrorlist=` 保持原样
fn rewrite_repo_file(content: &str, mirror: &PackageMirror) -> (String, usize, bool) {
    let mut hits = 0;
    let mut has_baseurl = false;
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("baseurl=") || trimmed.starts_with("baseurl =") {
            has_baseurl = true;
            let (new_line, n) = rewrite_hosts(line, mirror);
            hits += n;
            out.push_str(&new_line);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    (out, hits, has_baseurl)
}

/// 一次运行的临时软件源会话
pub struct MirrorSession {
    /// 临时目录（Drop 时自动清理）
    dir: Option<TempDir>,
    mirror: PackageMirror,
    package_manager: PackageManager,
    override_: MirrorOverride,
    rewritten_files: usize,
    rewritten_entries: usize,
    /// 存在 mirrorlist 但无 baseurl 的 repo 文件数（这部分无法加速）
    skipped_repos: usize,
}

impl MirrorSession {
    /// 创建临时源；Original / 未知包管理器返回空会话
    pub fn apply(mirror: PackageMirror, pm: PackageManager) -> Result<Self, DomainError> {
        let empty = |mirror: PackageMirror| Self {
            dir: None,
            mirror,
            package_manager: pm,
            override_: MirrorOverride::default(),
            rewritten_files: 0,
            rewritten_entries: 0,
            skipped_repos: 0,
        };

        if mirror.is_original() || pm == PackageManager::Unknown {
            return Ok(empty(mirror));
        }

        let dir = tempfile::Builder::new()
            .prefix("u2secure-mirror-")
            .tempdir()
            .map_err(|e| DomainError::SystemCommandFailed(format!("创建临时源目录失败: {e}")))?;

        let mut session = empty(mirror);
        match pm {
            PackageManager::Apt => session.build_apt(&dir)?,
            PackageManager::Yum | PackageManager::Dnf => session.build_yum(&dir)?,
            PackageManager::Unknown => {},
        }
        session.dir = Some(dir);
        Ok(session)
    }

    fn build_apt(&mut self, dir: &TempDir) -> Result<(), DomainError> {
        let mirror = self.mirror.clone();
        // 一列式源：/etc/apt/sources.list + sources.list.d/*.list
        let mut merged = String::new();
        let mut files = vec![std::path::PathBuf::from("/etc/apt/sources.list")];
        if let Ok(entries) = std::fs::read_dir("/etc/apt/sources.list.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("list") {
                    files.push(path);
                }
            }
        }
        // deb822 源：sources.list.d/*.sources（格式不同，必须单独存放）
        let parts_dir = dir.path().join("parts");
        std::fs::create_dir_all(&parts_dir)
            .map_err(|e| DomainError::SystemCommandFailed(format!("创建临时源目录失败: {e}")))?;

        for path in files {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (rewritten, hits) = rewrite_hosts(&content, &mirror);
            if hits > 0 {
                self.rewritten_files += 1;
                self.rewritten_entries += hits;
            }
            merged.push_str(&format!("# from {}\n", path.display()));
            merged.push_str(&rewritten);
            merged.push('\n');
        }

        if let Ok(entries) = std::fs::read_dir("/etc/apt/sources.list.d") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("sources") {
                    continue;
                }
                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let (rewritten, hits) = rewrite_hosts(&content, &mirror);
                if hits > 0 {
                    self.rewritten_files += 1;
                    self.rewritten_entries += hits;
                }
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "temp.sources".into());
                let _ = std::fs::write(parts_dir.join(name), rewritten);
            }
        }

        if self.rewritten_entries == 0 {
            return Ok(());
        }

        let sourcelist = dir.path().join("sources.list");
        std::fs::write(&sourcelist, merged)
            .map_err(|e| DomainError::SystemCommandFailed(format!("写入临时源失败: {e}")))?;
        crate::infrastructure::artifacts::restrict_file(&sourcelist.to_string_lossy());

        self.override_ = MirrorOverride {
            apt_sourcelist: Some(sourcelist.to_string_lossy().to_string()),
            apt_sourceparts: Some(parts_dir.to_string_lossy().to_string()),
            yum_reposdir: None,
        };
        Ok(())
    }

    fn build_yum(&mut self, dir: &TempDir) -> Result<(), DomainError> {
        let mirror = self.mirror.clone();
        let repos_dir = dir.path().join("yum.repos.d");
        std::fs::create_dir_all(&repos_dir)
            .map_err(|e| DomainError::SystemCommandFailed(format!("创建临时源目录失败: {e}")))?;

        let Ok(entries) = std::fs::read_dir("/etc/yum.repos.d") else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("repo") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (rewritten, hits, has_baseurl) = rewrite_repo_file(&content, &mirror);
            if !has_baseurl {
                self.skipped_repos += 1;
            }
            if hits > 0 {
                self.rewritten_files += 1;
                self.rewritten_entries += hits;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "temp.repo".into());
            let _ = std::fs::write(repos_dir.join(name), rewritten);
        }

        if self.rewritten_entries > 0 {
            self.override_ = MirrorOverride {
                apt_sourcelist: None,
                apt_sourceparts: None,
                yum_reposdir: Some(repos_dir.to_string_lossy().to_string()),
            };
        }
        Ok(())
    }

    /// 本次会话是否真的生效（有可用的临时源）
    pub fn is_active(&self) -> bool {
        !self.override_.is_empty()
    }

    pub fn override_value(&self) -> MirrorOverride {
        self.override_.clone()
    }

    pub fn mirror(&self) -> &PackageMirror {
        &self.mirror
    }

    /// 人类可读的生效说明（写入执行结果）
    pub fn summary(&self) -> String {
        if !self.is_active() {
            return crate::i18n::tr("mirror_not_applied").to_string();
        }
        let mut text = crate::i18n::tr("mirror_applied")
            .replace("{mirror}", &self.mirror.label())
            .replace("{files}", &self.rewritten_files.to_string())
            .replace("{entries}", &self.rewritten_entries.to_string());
        if self.skipped_repos > 0 {
            text.push_str(
                &crate::i18n::tr("mirror_repo_skipped")
                    .replace("{n}", &self.skipped_repos.to_string()),
            );
        }
        text
    }

    /// 生成包管理器命令（含临时源参数），argv[0] 为可执行文件
    pub fn pm_argv(&self, pm: PackageManager, args: &[&str]) -> Vec<String> {
        build_pm_argv(pm, &self.override_, args)
    }
}

/// 构造包管理器命令；无临时源时等价于原命令
pub fn build_pm_argv(pm: PackageManager, over: &MirrorOverride, args: &[&str]) -> Vec<String> {
    let mut argv = vec![pm.name().to_string()];
    match pm {
        PackageManager::Apt => {
            if let Some(list) = &over.apt_sourcelist {
                argv.push("-o".into());
                argv.push(format!("Dir::Etc::sourcelist={list}"));
                if let Some(parts) = &over.apt_sourceparts {
                    argv.push("-o".into());
                    argv.push(format!("Dir::Etc::sourceparts={parts}"));
                }
                // 不清空原有 lists，避免临时源把系统包列表删掉
                argv.push("-o".into());
                argv.push("APT::Get::List-Cleanup=0".into());
            }
        },
        PackageManager::Yum | PackageManager::Dnf => {
            if let Some(dir) = &over.yum_reposdir {
                argv.push(format!("--setopt=reposdir={dir}"));
            }
        },
        PackageManager::Unknown => {},
    }
    argv.extend(args.iter().map(|a| a.to_string()));
    argv
}

/// 包管理器安装软件包（带临时源）
pub fn install_argv(pm: PackageManager, over: &MirrorOverride, package: &str) -> Vec<String> {
    build_pm_argv(pm, over, &["install", "-y", package])
}

/// 切换源后预热：让 apt 先按镜像拉取索引，后续 install 才能真正走镜像。
///
/// 失败或 30 秒无任何响应时自动重试，最多 [`WARM_UP_ATTEMPTS`] 次；
/// 每次失败通过 `on_attempt(尝试序号, 原因)` 回调，便于界面提示过程。
/// 全部失败返回最后一次的原因（**不自动回退**，交由用户决定重试或更换源）。
pub fn warm_up(
    session: &MirrorSession,
    log_path: &str,
    on_attempt: &mut dyn FnMut(usize, String),
) -> Result<(), String> {
    // 临时源未生效，或非 apt（yum/dnf 的 install 会自行刷新元数据）：无需预热
    if !session.is_active() || session.package_manager != PackageManager::Apt {
        return Ok(());
    }

    let argv = session.pm_argv(PackageManager::Apt, &["update"]);
    let mut last_reason = String::new();
    for attempt in 1..=WARM_UP_ATTEMPTS {
        let status = system::run_streaming_watchdog(
            &argv,
            &[],
            log_path,
            WARM_UP_TIMEOUT,
            Some(WARM_UP_STALL),
        )
        .map_err(|e| e.to_string())?;

        if status.is_success() {
            return Ok(());
        }
        last_reason = status.describe();
        on_attempt(attempt, last_reason.clone());
    }
    Err(last_reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_debian_host() {
        let src = "deb http://deb.debian.org/debian bookworm main\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Tsinghua);
        assert_eq!(hits, 1);
        assert_eq!(
            out,
            "deb http://mirrors.tuna.tsinghua.edu.cn/debian bookworm main\n"
        );
    }

    #[test]
    fn test_rewrite_host_boundary_is_respected() {
        // deb.debian.org.evil.com 不应被替换
        let src = "deb http://deb.debian.org.evil.com/debian bookworm main\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Tsinghua);
        assert_eq!(hits, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn test_rewrite_ubuntu_host_keeps_path() {
        let src = "deb https://archive.ubuntu.com/ubuntu noble main\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Ustc);
        assert_eq!(hits, 1);
        assert!(out.contains("mirrors.ustc.edu.cn/ubuntu"));
    }

    #[test]
    fn test_rewrite_skips_unknown_host_and_original() {
        let src = "deb http://mirror.internal.corp/ubuntu noble main\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Tsinghua);
        assert_eq!(hits, 0);
        assert_eq!(out, src);

        let src = "deb http://archive.ubuntu.com/ubuntu noble main\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Original);
        assert_eq!(hits, 0);
        assert_eq!(out, src);
    }

    #[test]
    fn test_rewrite_deb822_format() {
        let src =
            "Types: deb\nURIs: http://deb.debian.org/debian-security\nSuites: bookworm-security\n";
        let (out, hits) = rewrite_hosts(src, &PackageMirror::Tsinghua);
        assert_eq!(hits, 1);
        assert!(out.contains("mirrors.tuna.tsinghua.edu.cn/debian-security"));
    }

    #[test]
    fn test_rewrite_repo_only_touches_baseurl() {
        let src = "[base]\nmirrorlist=https://mirrorlist.centos.org/?release=9\nbaseurl=https://mirror.centos.org/centos/9/os/\n";
        let (out, hits, has_baseurl) = rewrite_repo_file(src, &PackageMirror::Tsinghua);
        assert!(has_baseurl);
        assert_eq!(hits, 1);
        assert!(out.contains("mirrorlist=https://mirrorlist.centos.org/?release=9"));
        assert!(out.contains("mirrors.tuna.tsinghua.edu.cn/centos/9/os/"));
    }

    #[test]
    fn test_build_pm_argv_without_override() {
        let argv = build_pm_argv(
            PackageManager::Apt,
            &MirrorOverride::default(),
            &["install", "-y", "lynis"],
        );
        assert_eq!(argv, vec!["apt", "install", "-y", "lynis"]);
    }

    #[test]
    fn test_build_pm_argv_with_override() {
        let over = MirrorOverride {
            apt_sourcelist: Some("/tmp/u2s/sources.list".into()),
            apt_sourceparts: Some("/tmp/u2s/parts".into()),
            yum_reposdir: None,
        };
        let argv = build_pm_argv(PackageManager::Apt, &over, &["update"]);
        assert_eq!(argv[0], "apt");
        assert!(argv.iter().any(|a| a == "APT::Get::List-Cleanup=0"));
        assert!(argv.iter().any(|a| a.contains("Dir::Etc::sourcelist=")));
        assert_eq!(argv.last().unwrap(), "update");
    }

    #[test]
    fn test_warm_up_is_noop_without_active_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("mirror.log");
        let session =
            MirrorSession::apply(PackageMirror::Original, PackageManager::Apt).expect("session");

        let mut attempts = 0;
        let result = warm_up(&session, &log.to_string_lossy(), &mut |_, _| attempts += 1);

        assert!(result.is_ok(), "未生效的临时源不应预热");
        assert_eq!(attempts, 0, "不应产生重试回调");
        assert!(!log.exists(), "不应创建日志文件");
    }

    #[test]
    fn test_no_response_status_is_described() {
        let text = crate::infrastructure::system::StreamStatus::NoResponse.describe();
        assert!(text.contains("30"), "应提示 30 秒无响应: {text}");
    }

    #[test]
    fn test_original_mirror_session_is_inactive() {
        let session =
            MirrorSession::apply(PackageMirror::Original, PackageManager::Apt).expect("session");
        assert!(!session.is_active());
        assert_eq!(
            session.pm_argv(PackageManager::Apt, &["update"]),
            vec!["apt", "update"]
        );
    }
}
