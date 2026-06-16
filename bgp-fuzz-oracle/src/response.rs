use std::time::Instant;

use crate::{BugReport, BugSeverity, Direction, LogEntry, Oracle, RecvKind, RecvOutcome, ReproStep, SessionStats};
use chrono::Utc;

/// Detects unresponsive peers: single timeouts and consecutive hangs.
#[derive(Debug)]
pub struct ResponseOracle {
    last_send: Option<Instant>,
    consecutive_timeouts: u32,
    timeout_secs: u64,
}

impl Default for ResponseOracle {
    fn default() -> Self {
        ResponseOracle {
            last_send: None,
            consecutive_timeouts: 0,
            timeout_secs: 30,
        }
    }
}

impl ResponseOracle {
    pub fn new(timeout_secs: u64) -> Self {
        ResponseOracle {
            timeout_secs,
            ..Default::default()
        }
    }
}

impl Oracle for ResponseOracle {
    fn name(&self) -> &str {
        "ResponseOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[LogEntry],
        _stats: &SessionStats,
    ) -> Vec<BugReport> {
        self.last_send = Some(Instant::now());

        match outcome.kind {
            RecvKind::Timeout => {
                self.consecutive_timeouts += 1;
                let severity = if self.consecutive_timeouts >= 3 {
                    BugSeverity::High
                } else {
                    BugSeverity::Medium
                };
                let now = Utc::now().to_rfc3339();
                vec![BugReport {
                    id: format!("BGP-FUZZ-{}", now.replace(['-', ':'], "").split_at(15).0),
                    title: format!(
                        "No response from peer — timeout #{} consecutive ({}s)",
                        self.consecutive_timeouts,
                        self.timeout_secs,
                    ),
                    severity,
                    target: String::new(),
                    rfc_reference: Some("RFC 4271 §8 — Hold Timer must be respected".into()),
                    fsm_trace: vec![],
                    repro: vec![ReproStep {
                        direction: Direction::Send,
                        hex: hex::encode(sent),
                        expected: "peer should respond within hold time".into(),
                        actual: format!("no response for {}s", self.timeout_secs),
                    }],
                    discovered_at: now,
                    description: format!(
                        "Peer did not respond within {}s timeout (consecutive timeout #{})",
                        self.timeout_secs,
                        self.consecutive_timeouts,
                    ),
                }]
            }
            _ => {
                self.consecutive_timeouts = 0;
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_timeout_reports_medium() {
        let mut oracle = ResponseOracle::new(1);
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        let bugs = oracle.check(&[], &outcome, &[], &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
        assert_eq!(oracle.consecutive_timeouts, 1);
    }

    #[test]
    fn three_timeouts_reports_high() {
        let mut oracle = ResponseOracle::new(1);
        let timeout = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        oracle.check(&[], &timeout, &[], &SessionStats::default());
        oracle.check(&[], &timeout, &[], &SessionStats::default());
        let bugs = oracle.check(&[], &timeout, &[], &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert_eq!(oracle.consecutive_timeouts, 3);
    }

    #[test]
    fn response_resets_counter() {
        let mut oracle = ResponseOracle::new(1);
        let timeout = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        let data = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        oracle.check(&[], &timeout, &[], &SessionStats::default());
        oracle.check(&[], &timeout, &[], &SessionStats::default());
        assert_eq!(oracle.consecutive_timeouts, 2);
        oracle.check(&[], &data, &[], &SessionStats::default());
        assert_eq!(oracle.consecutive_timeouts, 0);
    }
}
