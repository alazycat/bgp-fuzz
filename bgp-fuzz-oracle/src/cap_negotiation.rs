use std::time::Instant;

use bgp_wire::{BgpMessage, WireDecode};
use crate::{Finding, Oracle, RecvKind, RecvOutcome};

/// Detects capability negotiation anomalies in BGP OPEN messages.
#[derive(Debug, Default)]
pub struct CapNegotiationOracle;

impl Oracle for CapNegotiationOracle {
    fn name(&self) -> &str {
        "CapNegotiationOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[bgp_fsm::LogEntry],
        _send_time: Instant,
    ) -> Vec<Finding> {
        let sent_open = match BgpMessage::decode(sent) {
            Ok((BgpMessage::Open(o), _)) => o,
            _ => return vec![],
        };

        let mut findings = Vec::new();

        // Check for duplicate capability types in our sent OPEN
        let cap_types: Vec<u8> = sent_open.optional_parameters
            .iter()
            .filter(|p| p.param_type == 2 && p.param_value.len() >= 1)
            .map(|p| p.param_value[0])
            .collect();

        let has_duplicates = (0..cap_types.len()).any(|i|
            cap_types[i+1..].contains(&cap_types[i])
        );

        // Check if peer correctly handled anomalies
        match outcome.kind {
            RecvKind::Data => {
                // Parse peer's response
                if let Ok((peer_msg, _)) = BgpMessage::decode(&outcome.bytes) {
                    match peer_msg {
                        BgpMessage::Open(_) => {
                            // If we sent duplicates and peer accepted → anomaly
                            if has_duplicates {
                                findings.push(Finding::CapNegotiation {
                                    description: "Peer accepted OPEN with duplicate Capability codes".into(),
                                });
                            }
                        }
                        BgpMessage::Notification(_) => {
                            // Peer rejected — check if it was for valid caps
                            if !has_duplicates && cap_types.iter().all(|&c| c <= 128) {
                                findings.push(Finding::CapNegotiation {
                                    description: "Peer rejected OPEN with valid capabilities".into(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            RecvKind::PeerClosed | RecvKind::ConnectionReset => {
                if !has_duplicates {
                    findings.push(Finding::CapNegotiation {
                        description: format!("Peer closed connection during capability negotiation (kind: {:?})", outcome.kind),
                    });
                }
            }
            _ => {}
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_wire::WireEncode;

    fn make_open(caps: Vec<(u8, Vec<u8>)>) -> Vec<u8> {
        let params: Vec<_> = caps.into_iter().map(|(code, val)| {
            bgp_wire::open::OptionalParameter {
                param_type: 2,
                param_length: val.len() as u8 + 1,
                param_value: {
                    let mut v = vec![code];
                    v.extend(val);
                    v
                },
            }
        }).collect();
        let msg = BgpMessage::Open(bgp_wire::open::OpenMessage {
            version: 4, my_as: 65001, hold_time: 180,
            bgp_id: [10, 0, 0, 1], optional_parameters: params,
        });
        let mut buf = vec![];
        msg.encode(&mut buf);
        buf
    }

    #[test]
    fn duplicate_cap_accepted_detected() {
        let mut oracle = CapNegotiationOracle;
        let sent = make_open(vec![(1, vec![]), (1, vec![])]);  // duplicate cap code 1
        let peer_open = make_open(vec![(1, vec![])]);
        let outcome = RecvOutcome { bytes: peer_open, kind: RecvKind::Data };
        let findings = oracle.check(&sent, &outcome, &[], Instant::now());
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::CapNegotiation { .. }));
    }

    #[test]
    fn valid_cap_accepted_no_finding() {
        let mut oracle = CapNegotiationOracle;
        let sent = make_open(vec![(1, vec![])]);  // single valid cap
        let peer_open = make_open(vec![(1, vec![])]);
        let outcome = RecvOutcome { bytes: peer_open, kind: RecvKind::Data };
        let findings = oracle.check(&sent, &outcome, &[], Instant::now());
        assert!(findings.is_empty());
    }

    #[test]
    fn non_open_skipped() {
        let mut oracle = CapNegotiationOracle;
        let findings = oracle.check(&[0xFF; 29], &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &[], Instant::now());
        assert!(findings.is_empty());
    }
}
