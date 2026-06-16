use crate::{BugReport, BugSeverity, LogEntry, Oracle, RecvKind, RecvOutcome, SessionStats, ReproStep, Direction};
use chrono::Utc;

/// Detects peer crashes: TCP RST and unexpected connection close.
#[derive(Debug, Default)]
pub struct CrashOracle;

impl Oracle for CrashOracle {
    fn name(&self) -> &str {
        "CrashOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[LogEntry],
        _stats: &SessionStats,
    ) -> Vec<BugReport> {
        let now = Utc::now().to_rfc3339();
        let sent_hex = hex::encode(sent);

        match outcome.kind {
            RecvKind::ConnectionReset => {
                vec![BugReport {
                    id: format!("BGP-FUZZ-{}", now.replace(['-', ':'], "").split_at(15).0),
                    title: format!("Peer sent RST after {} byte message", sent.len()),
                    severity: BugSeverity::Critical,
                    target: String::new(),
                    rfc_reference: None,
                    fsm_trace: vec![],
                    repro: vec![ReproStep {
                        direction: Direction::Send,
                        hex: sent_hex,
                        expected: "peer should accept message".into(),
                        actual: "peer sent TCP RST (likely crash)".into(),
                    }],
                    discovered_at: now,
                    description: format!(
                        "Target sent TCP RST after receiving a {} byte message. \
                         This likely indicates a crash or assertion failure.",
                        sent.len()
                    ),
                }]
            }
            RecvKind::PeerClosed => {
                vec![BugReport {
                    id: format!("BGP-FUZZ-{}", now.replace(['-', ':'], "").split_at(15).0),
                    title: format!("Peer closed connection unexpectedly after {} byte message", sent.len()),
                    severity: BugSeverity::High,
                    target: String::new(),
                    rfc_reference: None,
                    fsm_trace: vec![],
                    repro: vec![ReproStep {
                        direction: Direction::Send,
                        hex: sent_hex,
                        expected: "peer should keep connection open".into(),
                        actual: "peer sent FIN (clean close)".into(),
                    }],
                    discovered_at: now,
                    description: "Peer cleanly closed the connection at an unexpected time.".into(),
                }]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rst_reports_critical() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome {
            bytes: vec![],
            kind: RecvKind::ConnectionReset,
        };
        let bugs = oracle.check(&[0xFF; 29], &outcome, &[], &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Critical);
        assert!(bugs[0].title.contains("RST"));
    }

    #[test]
    fn eof_reports_high() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome {
            bytes: vec![],
            kind: RecvKind::PeerClosed,
        };
        let bugs = oracle.check(&[0xFF; 19], &outcome, &[], &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
    }

    #[test]
    fn normal_data_no_bug() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome {
            bytes: vec![0xFF; 19],
            kind: RecvKind::Data,
        };
        let bugs = oracle.check(&[], &outcome, &[], &SessionStats::default());
        assert!(bugs.is_empty());
    }
}
