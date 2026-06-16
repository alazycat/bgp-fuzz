use std::time::Instant;

use crate::{Finding, Oracle, RecvKind, RecvOutcome};

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
        _fsm_log: &[bgp_fsm::LogEntry],
        _send_time: Instant,
    ) -> Vec<Finding> {
        match outcome.kind {
            RecvKind::ConnectionReset => vec![Finding::PeerReset { sent_len: sent.len() }],
            RecvKind::PeerClosed => vec![Finding::PeerClosed { sent_len: sent.len() }],
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rst_detected() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::ConnectionReset };
        let findings = oracle.check(&[0xFF; 29], &outcome, &[], Instant::now());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::PeerReset { sent_len: 29 }));
    }

    #[test]
    fn fin_detected() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::PeerClosed };
        let findings = oracle.check(&[0xFF; 19], &outcome, &[], Instant::now());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::PeerClosed { sent_len: 19 }));
    }

    #[test]
    fn normal_data_no_bug() {
        let mut oracle = CrashOracle;
        let outcome = RecvOutcome { bytes: vec![0xFF; 19], kind: RecvKind::Data };
        let findings = oracle.check(&[], &outcome, &[], Instant::now());
        assert!(findings.is_empty());
    }
}
