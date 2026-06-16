use std::time::Instant;

use bgp_wire::{BgpMessage, WireDecode};
use crate::{Finding, Oracle, RecvKind, RecvOutcome};

/// Detects BGP UPDATE round-trip inconsistencies.
///
/// **Loose:** sent NLRI must appear in peer's response UPDATE.
/// **Strict:** sent UPDATE bytes must match response UPDATE bytes byte-for-byte.
#[derive(Debug, Default)]
pub struct AttributeEchoOracle {
    pending_nlri: Option<Vec<bgp_wire::NlriPrefix>>,
    last_update_bytes: Option<Vec<u8>>,
}

impl Oracle for AttributeEchoOracle {
    fn name(&self) -> &str {
        "AttributeEchoOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        fsm_log: &[bgp_fsm::LogEntry],
        _send_time: Instant,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check when we're in Established state
        let in_established = fsm_log.last().map_or(false, |e| e.state_after == "Established");
        if !in_established {
            return findings;
        }

        // When we send an UPDATE, store NLRI + bytes for later comparison
        if let Ok((msg, _)) = BgpMessage::decode(sent) {
            if let BgpMessage::Update(ref update) = msg {
                self.pending_nlri = Some(update.nlri.clone());
                self.last_update_bytes = Some(sent.to_vec());
            }
        }

        // When we receive data, check against stored expectations
        if outcome.kind == RecvKind::Data {
            if let Ok((msg, _)) = BgpMessage::decode(&outcome.bytes) {
                if let BgpMessage::Update(ref recv_update) = msg {
                    // Loose round-trip: check NLRI
                    if let Some(ref sent_nlri) = self.pending_nlri {
                        let missing: Vec<String> = sent_nlri
                            .iter()
                            .filter(|n| !recv_update.nlri.contains(n))
                            .map(|n| format!("{:?}", n))
                            .collect();
                        let extra: Vec<String> = recv_update.nlri
                            .iter()
                            .filter(|n| !sent_nlri.contains(n))
                            .map(|n| format!("{:?}", n))
                            .collect();
                        if !missing.is_empty() || !extra.is_empty() {
                            findings.push(Finding::AttributeEcho { missing, extra });
                        }
                    }

                    // Strict mirror: check bytes
                    if let Some(ref sent_bytes) = self.last_update_bytes {
                        if sent_bytes != &outcome.bytes {
                            let diff = describe_diff(sent_bytes, &outcome.bytes);
                            findings.push(Finding::AttributeMirror { diff });
                        }
                    }
                }
            }
        }

        findings
    }
}

/// Describe the first few byte-level differences between two byte slices.
fn describe_diff(expected: &[u8], actual: &[u8]) -> String {
    let min_len = expected.len().min(actual.len());
    let mut diffs = Vec::new();
    for i in 0..min_len {
        if expected[i] != actual[i] {
            diffs.push(format!("byte[{}]: expected {:02x}, got {:02x}", i, expected[i], actual[i]));
            if diffs.len() >= 3 {
                break;
            }
        }
    }
    if expected.len() != actual.len() {
        diffs.push(format!(
            "length: expected {}, got {}",
            expected.len(),
            actual.len()
        ));
    }
    if diffs.is_empty() {
        "no differences found".into()
    } else {
        diffs.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_fsm::LogEntry;
    use bgp_wire::WireEncode;
    use bgp_wire::attributes::origin::Origin;
    use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};
    use bgp_wire::attributes::next_hop::NextHop;

    fn est_log() -> Vec<LogEntry> {
        vec![LogEntry {
            state_after: "Established".into(),
            legality: "Legal".into(),
            event_description: "BgpUpdate".into(),
        }]
    }

    fn make_update(nlri: Vec<bgp_wire::NlriPrefix>) -> Vec<u8> {
        let msg = BgpMessage::Update(bgp_wire::update::UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: vec![
                Box::new(Origin(0)),
                Box::new(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] }),
                Box::new(NextHop([10, 0, 0, 1])),
            ],
            nlri,
        });
        let mut buf = vec![];
        msg.encode(&mut buf);
        buf
    }

    #[test]
    fn nlri_match_no_finding() {
        let mut oracle = AttributeEchoOracle::default();
        let nlri = vec![bgp_wire::NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] }];
        let sent = make_update(nlri.clone());
        let recv = make_update(nlri);

        oracle.check(&sent, &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &est_log(), Instant::now());
        let _findings = oracle.check(&sent, &RecvOutcome { bytes: recv, kind: RecvKind::Data }, &est_log(), Instant::now());
    }

    #[test]
    fn nlri_missing_detected() {
        let mut oracle = AttributeEchoOracle::default();
        let sent_nlri = vec![
            bgp_wire::NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] },
            bgp_wire::NlriPrefix { prefix_len: 32, prefix: vec![10, 0, 0, 1] },
        ];
        let recv_nlri = vec![
            bgp_wire::NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] },
        ];
        let sent = make_update(sent_nlri);
        let recv = make_update(recv_nlri);

        oracle.check(&sent, &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &est_log(), Instant::now());
        let findings = oracle.check(&sent, &RecvOutcome { bytes: recv, kind: RecvKind::Data }, &est_log(), Instant::now());
        assert!(!findings.is_empty(), "should detect missing NLRI");
    }

    #[test]
    fn strict_mirror_diff_detected() {
        let mut oracle = AttributeEchoOracle::default();
        let nlri = vec![bgp_wire::NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] }];
        let sent = make_update(nlri);
        let mut modified = sent.clone();
        modified[30] ^= 0x01; // flip a bit

        oracle.check(&sent, &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &est_log(), Instant::now());
        let findings = oracle.check(&sent, &RecvOutcome { bytes: modified, kind: RecvKind::Data }, &est_log(), Instant::now());
        assert!(findings.iter().any(|f| matches!(f, Finding::AttributeMirror { .. })), "should detect byte-level diff");
    }

    #[test]
    fn not_established_skips() {
        let mut oracle = AttributeEchoOracle::default();
        let non_est = vec![LogEntry {
            state_after: "Idle".into(),
            legality: "Legal".into(),
            event_description: "test".into(),
        }];
        let findings = oracle.check(&[], &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &non_est, Instant::now());
        assert!(findings.is_empty(), "should skip when not Established");
    }
}
