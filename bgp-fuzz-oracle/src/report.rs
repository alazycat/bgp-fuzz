use std::fs;
use std::io;
use std::path::Path;

use crate::BugReport;

/// Write a single bug report to a JSON file in the output directory.
///
/// Filename format: `bgp-fuzz-YYYYMMDD-HHMMSS-XXXX.json`
/// Returns the path of the written file.
pub fn write_report(report: &BugReport, output_dir: &Path) -> io::Result<String> {
    fs::create_dir_all(output_dir)?;
    let filename = format!("{}.json", report.id);
    let path = output_dir.join(&filename);
    let json = serde_json::to_string_pretty(report)
        .map_err(io::Error::other)?;
    fs::write(&path, json)?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, ReproStep};
    use std::path::PathBuf;

    #[test]
    fn write_and_read_report() {
        let report = BugReport {
            id: "BGP-FUZZ-20260616-120000-0042".into(),
            title: "Test".into(),
            severity: crate::BugSeverity::High,
            target: "127.0.0.1:179".into(),
            rfc_reference: None,
            fsm_trace: vec![],
            repro: vec![ReproStep {
                direction: Direction::Send,
                hex: "deadbeef".into(),
                expected: "something".into(),
                actual: "something else".into(),
            }],
            discovered_at: "2026-06-16T12:00:00Z".into(),
            description: "test report write".into(),
        };

        let dir = PathBuf::from("test_reports");
        let path = write_report(&report, &dir).unwrap();
        assert!(path.contains("BGP-FUZZ-20260616-120000-0042.json"));

        // Verify file content
        let json = fs::read_to_string(&path).unwrap();
        assert!(json.contains("BGP-FUZZ-20260616-120000-0042"));
        assert!(json.contains("127.0.0.1:179"));

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_report_creates_output_dir() {
        let report = BugReport {
            id: "BGP-FUZZ-20260616-120000-0001".into(),
            title: "T".into(),
            severity: crate::BugSeverity::Medium,
            target: "t".into(),
            rfc_reference: None,
            fsm_trace: vec![],
            repro: vec![],
            discovered_at: "t".into(),
            description: "t".into(),
        };

        let dir = PathBuf::from("test_reports_nested/sub");
        let path = write_report(&report, &dir).unwrap();
        assert!(path.contains("BGP-FUZZ-20260616-120000-0001.json"));
        let _ = fs::remove_dir_all("test_reports_nested");
    }
}
