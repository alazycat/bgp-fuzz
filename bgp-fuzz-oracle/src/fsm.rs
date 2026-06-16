use std::time::Instant;

use crate::{Finding, Oracle, RecvKind, RecvOutcome};

/// Detects RFC 4271 FSM compliance deviations.
#[derive(Debug, Default)]
pub struct FsmConsistencyOracle;

impl Oracle for FsmConsistencyOracle {
    fn name(&self) -> &str {
        "FsmConsistencyOracle"
    }

    fn check(
        &mut self,
        _sent: &[u8],
        outcome: &RecvOutcome,
        fsm_log: &[bgp_fsm::LogEntry],
        _send_time: Instant,
    ) -> Vec<Finding> {
        let last_sent = match fsm_log.last() {
            Some(entry) => entry,
            None => return vec![],
        };

        let peer_accepted = match outcome.kind {
            RecvKind::Data | RecvKind::Timeout => true,
            RecvKind::PeerClosed | RecvKind::ConnectionReset | RecvKind::Error => false,
        };

        let state = last_sent.state_after.clone();
        let event = last_sent.event_description.clone();

        match (last_sent.legality.as_str(), peer_accepted) {
            ("Illegal", true) => {
                vec![Finding::IllegalAccepted { state, event_description: event }]
            }
            ("Legal", false) => {
                vec![Finding::LegalRejected { state, event_description: event }]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_fsm::LogEntry;

    fn log_entry(legality: &str) -> LogEntry {
        LogEntry {
            state_after: "Established".into(),
            legality: legality.into(),
            event_description: "BgpUpdate".into(),
        }
    }

    #[test]
    fn illegal_accepted_detected() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Illegal")];
        let outcome = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        let findings = oracle.check(&[], &outcome, &log, Instant::now());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::IllegalAccepted { .. }));
    }

    #[test]
    fn legal_rejected_detected() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Legal")];
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::ConnectionReset };
        let findings = oracle.check(&[], &outcome, &log, Instant::now());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::LegalRejected { .. }));
    }

    #[test]
    fn legal_accepted_no_finding() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Legal")];
        let outcome = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        let findings = oracle.check(&[], &outcome, &log, Instant::now());
        assert!(findings.is_empty());
    }
}
