use std::time::Instant;

use crate::{Finding, Oracle, RecvKind, RecvOutcome};

#[derive(Debug)]
pub struct ResponseOracle {
    last_send: Option<Instant>,
    consecutive_timeouts: u32,
    timeout_secs: u64,
}

impl Default for ResponseOracle {
    fn default() -> Self {
        ResponseOracle { last_send: None, consecutive_timeouts: 0, timeout_secs: 30 }
    }
}

impl ResponseOracle {
    pub fn new(timeout_secs: u64) -> Self {
        ResponseOracle { timeout_secs, ..Default::default() }
    }
}

impl Oracle for ResponseOracle {
    fn name(&self) -> &str {
        "ResponseOracle"
    }

    fn check(
        &mut self,
        _sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[bgp_fsm::LogEntry],
    ) -> Vec<Finding> {
        self.last_send = Some(Instant::now());

        match outcome.kind {
            RecvKind::Timeout => {
                self.consecutive_timeouts += 1;
                vec![Finding::Timeout {
                    consecutive: self.consecutive_timeouts,
                    timeout_secs: self.timeout_secs,
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
    fn single_timeout_detected() {
        let mut oracle = ResponseOracle::new(1);
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        let findings = oracle.check(&[], &outcome, &[]);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::Timeout { consecutive: 1, timeout_secs: 1 }));
        assert_eq!(oracle.consecutive_timeouts, 1);
    }

    #[test]
    fn three_timeouts_detected() {
        let mut oracle = ResponseOracle::new(1);
        let timeout = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        oracle.check(&[], &timeout, &[]);
        oracle.check(&[], &timeout, &[]);
        let findings = oracle.check(&[], &timeout, &[]);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::Timeout { consecutive: 3, .. }));
    }

    #[test]
    fn response_resets_counter() {
        let mut oracle = ResponseOracle::new(1);
        let timeout = RecvOutcome { bytes: vec![], kind: RecvKind::Timeout };
        let data = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        oracle.check(&[], &timeout, &[]);
        oracle.check(&[], &timeout, &[]);
        assert_eq!(oracle.consecutive_timeouts, 2);
        oracle.check(&[], &data, &[]);
        assert_eq!(oracle.consecutive_timeouts, 0);
    }
}
