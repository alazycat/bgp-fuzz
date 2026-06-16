pub mod report;
pub mod crash;
pub mod fsm;
pub mod response;

pub use crash::CrashOracle;
pub use fsm::FsmConsistencyOracle;
pub use response::ResponseOracle;

use std::fmt::Debug;

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Bug severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BugSeverity {
    /// Crash, hang — must fix
    Critical,
    /// FSM violation, consecutive timeouts — should fix
    High,
    /// Single timeout, minor deviation — nice to fix
    Medium,
}

/// Direction of a repro step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Direction {
    Send,
    Receive,
}

impl Direction {
    pub fn direction_label(&self) -> &str {
        match self {
            Direction::Send => "SEND",
            Direction::Receive => "RECV",
        }
    }
}

/// A single step in a bug reproduction sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproStep {
    pub direction: Direction,
    pub hex: String,
    pub expected: String,
    pub actual: String,
}

/// Structured bug report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReport {
    /// Unique ID: BGP-FUZZ-YYYYMMDD-HHMMSS-XXXX
    pub id: String,
    /// One-line description
    pub title: String,
    /// Severity level
    pub severity: BugSeverity,
    /// Target address
    pub target: String,
    /// RFC reference if applicable
    pub rfc_reference: Option<String>,
    /// Full FSM event log at time of discovery
    pub fsm_trace: Vec<bgp_fsm::LogEntry>,
    /// Minimal reproduction sequence
    pub repro: Vec<ReproStep>,
    /// ISO 8601 timestamp
    pub discovered_at: String,
    /// Detailed description
    pub description: String,
}

/// Outcome of a single receive operation.
#[derive(Debug, Clone)]
pub struct RecvOutcome {
    pub bytes: Vec<u8>,
    pub kind: RecvKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvKind {
    /// Received data
    Data,
    /// Peer sent FIN (clean close)
    PeerClosed,
    /// Peer sent RST (likely crash)
    ConnectionReset,
    /// No response within timeout
    Timeout,
    /// Other I/O error
    Error,
}

/// Statistics collected during a fuzz session.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub msgs_sent: u64,
    pub msgs_recv: u64,
    pub bugs_critical: u64,
    pub bugs_high: u64,
    pub bugs_medium: u64,
    pub connections: u64,
    pub elapsed_secs: u64,
}

/// A lightweight bug finding — detection without formatting.
#[derive(Debug, Clone)]
pub enum Finding {
    /// Peer sent TCP RST (crash detected).
    PeerReset { sent_len: usize },
    /// Peer sent FIN (unexpected close).
    PeerClosed { sent_len: usize },
    /// Peer accepted a message that RFC says MUST NOT be accepted.
    IllegalAccepted { state: String, event_description: String },
    /// Peer rejected a message that RFC says MUST be accepted.
    LegalRejected { state: String, event_description: String },
    /// Peer did not respond within the hold time.
    Timeout { consecutive: u32, timeout_secs: u64 },
}

impl Finding {
    /// Convert a Finding into a fully-formatted BugReport.
    /// The `bug_id()`, timestamps, and human-readable strings
    /// are assembled here — not inside oracle detection logic.
    pub fn into_report(
        self,
        target: String,
        sent: &[u8],
        fsm_log: &[bgp_fsm::LogEntry],
    ) -> BugReport {
        let id = bug_id();
        let sent_hex = hex::encode(sent);
        let now = Utc::now().to_rfc3339();

        let make_report = |title, severity, rfc, repro_step, desc| BugReport {
            id: id.clone(),
            title,
            severity,
            target: target.clone(),
            rfc_reference: rfc,
            fsm_trace: fsm_log.to_vec(),
            repro: vec![repro_step],
            discovered_at: now.clone(),
            description: desc,
        };

        match self {
            Finding::PeerReset { sent_len } => make_report(
                format!("Peer sent RST after {} byte message", sent_len),
                BugSeverity::Critical,
                None,
                ReproStep {
                    direction: Direction::Send,
                    hex: sent_hex,
                    expected: "peer should accept message".into(),
                    actual: "peer sent TCP RST (likely crash)".into(),
                },
                format!(
                    "Target sent TCP RST after receiving a {} byte message. \
                     This likely indicates a crash or assertion failure.",
                    sent_len
                ),
            ),
            Finding::PeerClosed { sent_len } => make_report(
                format!("Peer closed connection unexpectedly after {} byte message", sent_len),
                BugSeverity::High,
                None,
                ReproStep {
                    direction: Direction::Send,
                    hex: sent_hex,
                    expected: "peer should keep connection open".into(),
                    actual: "peer sent FIN (clean close)".into(),
                },
                "Peer cleanly closed the connection at an unexpected time.".into(),
            ),
            Finding::IllegalAccepted { state, event_description } => make_report(
                format!("Peer accepted illegal message in state {} — FSM deviation", state),
                BugSeverity::High,
                Some(format!(
                    "RFC 4271 §8.2 — transition {} in state {} is illegal",
                    event_description, state
                )),
                ReproStep {
                    direction: Direction::Send,
                    hex: sent_hex,
                    expected: "peer should reject (NOTIFICATION or RST)".into(),
                    actual: "peer accepted the message".into(),
                },
                format!(
                    "FSM consistency violation: peer in state {} accepted a message \
                     that RFC 4271 marks as illegal for that state.",
                    state
                ),
            ),
            Finding::LegalRejected { state, event_description } => make_report(
                format!("Peer rejected legal message in state {} — unexpected behavior", state),
                BugSeverity::Medium,
                Some(format!(
                    "RFC 4271 §8.2 — transition {} in state {} is legal",
                    event_description, state
                )),
                ReproStep {
                    direction: Direction::Send,
                    hex: sent_hex,
                    expected: "peer should accept".into(),
                    actual: "peer rejected/closed connection".into(),
                },
                "Peer rejected a message that RFC 4271 says should be legal in this state.".into(),
            ),
            Finding::Timeout { consecutive, timeout_secs } => {
                let severity = if consecutive >= 3 {
                    BugSeverity::High
                } else {
                    BugSeverity::Medium
                };
                make_report(
                    format!(
                        "No response from peer — timeout #{} consecutive ({}s)",
                        consecutive, timeout_secs,
                    ),
                    severity,
                    Some("RFC 4271 §8 — Hold Timer must be respected".into()),
                    ReproStep {
                        direction: Direction::Send,
                        hex: sent_hex,
                        expected: "peer should respond within hold time".into(),
                        actual: format!("no response for {}s", timeout_secs),
                    },
                    format!(
                        "Peer did not respond within {}s timeout (consecutive timeout #{})",
                        timeout_secs, consecutive,
                    ),
                )
            }
        }
    }
}

fn bug_id() -> String {
    let now = Utc::now().to_rfc3339();
    format!(
        "BGP-FUZZ-{}",
        now.replace(['-', ':'], "").split_at(15).0
    )
}

/// The Oracle trait — each oracle checks one class of invariant.
/// Returns lightweight `Finding` values; call `Finding::into_report(...)`
/// to produce a formatted `BugReport`.
pub trait Oracle: Debug + Send + Sync {
    fn name(&self) -> &str;

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        fsm_log: &[bgp_fsm::LogEntry],
    ) -> Vec<Finding>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bug_report_json_roundtrip() {
        let report = BugReport {
            id: "BGP-FUZZ-20260616-120000-0001".into(),
            title: "Test crash".into(),
            severity: BugSeverity::Critical,
            target: "127.0.0.1:179".into(),
            rfc_reference: Some("RFC 4271 §4.3".into()),
            fsm_trace: vec![],
            repro: vec![ReproStep {
                direction: Direction::Send,
                hex: "ffff".into(),
                expected: "peer should accept".into(),
                actual: "peer sent RST".into(),
            }],
            discovered_at: "2026-06-16T12:00:00Z".into(),
            description: "Test report".into(),
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let decoded: BugReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, report.id);
        assert_eq!(decoded.severity, BugSeverity::Critical);
    }

    #[test]
    fn bug_id_has_expected_format() {
        let id = bug_id();
        assert!(id.starts_with("BGP-FUZZ-"), "id: {id}");
        assert!(id.len() >= 20, "id too short: {id}");
    }
}
