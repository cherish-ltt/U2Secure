//! lynis 报告解析（`lynis-report.dat` 为 `key=value` 与 `key[]=value` 形式）
//!
//! 比按 stdout 文本包含 "Warning"/"Suggestion" 计数可靠：不会把汇总行重复计入。

/// lynis 扫描摘要
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LynisSummary {
    pub warnings: usize,
    pub suggestions: usize,
    /// 加固指数（0-100），报告缺失该字段时为 None
    pub hardening_index: Option<u32>,
}

/// 解析 `lynis-report.dat` 内容
pub fn parse_report(content: &str) -> LynisSummary {
    let mut summary = LynisSummary::default();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("warning[]=") {
            summary.warnings += 1;
        } else if line.starts_with("suggestion[]=") {
            summary.suggestions += 1;
        } else if let Some(value) = line.strip_prefix("hardening_index=") {
            summary.hardening_index = value.trim().parse().ok();
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Lynis report file
lynis_version=3.0.8
hardening_index=67
warning[]=SSH-7408|Consider hardening SSH configuration|Details: AllowTcpForwarding (set YES to NO)|Solution: Set AllowTcpForwarding to NO
warning[]=PKGS-7392|Check for vulnerable packages
suggestion[]=DEBIAN-5000|Enable automatic security updates
suggestion[]=KRNL-6000|Check kernel hardening options
";

    #[test]
    fn test_parse_report_counts_entries() {
        let summary = parse_report(SAMPLE);
        assert_eq!(summary.warnings, 2);
        assert_eq!(summary.suggestions, 2);
        assert_eq!(summary.hardening_index, Some(67));
    }

    #[test]
    fn test_parse_report_without_index() {
        let summary = parse_report("warning[]=A\n");
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.suggestions, 0);
        assert_eq!(summary.hardening_index, None);
    }

    #[test]
    fn test_parse_empty_report() {
        assert_eq!(parse_report(""), LynisSummary::default());
    }
}
