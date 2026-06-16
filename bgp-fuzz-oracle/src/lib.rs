pub mod report;
pub mod crash;
pub mod fsm;
pub mod response;

pub use crash::CrashOracle;
pub use fsm::FsmConsistencyOracle;
pub use response::ResponseOracle;

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

/// A single entry in the FSM event log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// FSM state after the event (e.g. "Idle", "Established")
    pub state_after: String,
    /// RFC legality of the transition (e.g. "Legal", "Illegal", "Unspecified")
    pub legality: String,
    /// Human-readable event description (e.g. "Sent 64 bytes: BgpOpen")
    pub event_description: String,
}

/// Bug severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BugSeverity {
    /// Crash, hang — must fix
    Critical,
    /// FSM violation, consecutive timeouts — should fix
    High,
    /// Single timeout, minor deviation — nice to fix
    Medium,
}

/// Direction of a repro step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Direction {
    Send,
    Receive,
}

/// A single step in a bug reproduction sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproStep {
    pub direction: Direction,
    pub hex: String,
    pub expected: String,
    pub actual: String,
}

/// Structured bug report
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
    pub fsm_trace: Vec<LogEntry>,
    /// Minimal reproduction sequence
    pub repro: Vec<ReproStep>,
    /// ISO 8601 timestamp
    pub discovered_at: String,
    /// Detailed description
    pub description: String,
}

/// Outcome of a single receive operation
#[derive(Debug, Clone)]
pub struct RecvOutcome {
    pub bytes: Vec<u8>,
    pub kind: RecvKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Statistics collected during a fuzz session
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

/// The Oracle trait — each oracle checks one class of invariant.
pub trait Oracle: Debug + Send + Sync {
    /// Human-readable name for logging/reporting
    fn name(&self) -> &str;

    /// Called after each send+receive cycle. Returns any bugs found.
    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        fsm_log: &[LogEntry],
        session_stats: &SessionStats,
    ) -> Vec<BugReport>;
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
}
