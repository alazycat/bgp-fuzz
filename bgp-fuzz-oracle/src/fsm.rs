use crate::{BugReport, BugSeverity, Direction, LogEntry, Oracle, RecvKind, RecvOutcome, ReproStep, SessionStats};
use chrono::Utc;

/// Detects RFC 4271 FSM compliance deviations.
///
/// Compares shadow FSM legality against peer's actual behavior:
/// - Illegal message accepted → High (peer too permissive)
/// - Legal message rejected → Medium (peer too strict)
#[derive(Debug, Default)]
pub struct FsmConsistencyOracle;

impl Oracle for FsmConsistencyOracle {
    fn name(&self) -> &str {
        "FsmConsistencyOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        fsm_log: &[LogEntry],
        _stats: &SessionStats,
    ) -> Vec<BugReport> {
        let last_sent = match fsm_log.last() {
            Some(entry) => entry,
            None => return vec![],
        };

        let peer_accepted = match outcome.kind {
            RecvKind::Data | RecvKind::Timeout => true,
            RecvKind::PeerClosed | RecvKind::ConnectionReset | RecvKind::Error => false,
        };

        let now = Utc::now().to_rfc3339();
        let sent_hex = hex::encode(sent);
        let state = &last_sent.state_after;
        let legality = &last_sent.legality;

        match (legality.as_str(), peer_accepted) {
            ("Illegal", true) => {
                vec![BugReport {
                    id: format!("BGP-FUZZ-{}", now.replace(['-', ':'], "").split_at(15).0),
                    title: format!(
                        "Peer accepted illegal message in state {} — FSM deviation",
                        state
                    ),
                    severity: BugSeverity::High,
                    target: String::new(),
                    rfc_reference: Some(format!("RFC 4271 §8.2 — transition {} in state {} is illegal", last_sent.event_description, state)),
                    fsm_trace: fsm_log.to_vec(),
                    repro: vec![ReproStep {
                        direction: Direction::Send,
                        hex: sent_hex,
                        expected: "peer should reject (NOTIFICATION or RST)".into(),
                        actual: "peer accepted the message".into(),
                    }],
                    discovered_at: now,
                    description: format!(
                        "FSM consistency violation: peer in state {} accepted a message \
                         that RFC 4271 marks as illegal for that state.",
                        state
                    ),
                }]
            }
            ("Legal", false) => {
                vec![BugReport {
                    id: format!("BGP-FUZZ-{}", now.replace(['-', ':'], "").split_at(15).0),
                    title: format!(
                        "Peer rejected legal message in state {} — unexpected behavior",
                        state
                    ),
                    severity: BugSeverity::Medium,
                    target: String::new(),
                    rfc_reference: Some(format!("RFC 4271 §8.2 — transition {} in state {} is legal", last_sent.event_description, state)),
                    fsm_trace: fsm_log.to_vec(),
                    repro: vec![ReproStep {
                        direction: Direction::Send,
                        hex: sent_hex,
                        expected: "peer should accept".into(),
                        actual: "peer rejected/closed connection".into(),
                    }],
                    discovered_at: now,
                    description: "Peer rejected a message that RFC 4271 says should be legal in this state.".into(),
                }]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_entry(legality: &str) -> LogEntry {
        LogEntry {
            state_after: "Established".into(),
            legality: legality.into(),
            event_description: "BgpUpdate".into(),
        }
    }

    #[test]
    fn illegal_accepted_reports_high() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Illegal")];
        let outcome = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        let bugs = oracle.check(&[], &outcome, &log, &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("illegal"));
    }

    #[test]
    fn legal_rejected_reports_medium() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Legal")];
        let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::ConnectionReset };
        let bugs = oracle.check(&[], &outcome, &log, &SessionStats::default());
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
    }

    #[test]
    fn legal_accepted_no_bug() {
        let mut oracle = FsmConsistencyOracle;
        let log = vec![log_entry("Legal")];
        let outcome = RecvOutcome { bytes: vec![0; 19], kind: RecvKind::Data };
        let bugs = oracle.check(&[], &outcome, &log, &SessionStats::default());
        assert!(bugs.is_empty());
    }
}
