use std::collections::VecDeque;
use std::time::Instant;

use bgp_wire::{BgpMessage, WireDecode, WireEncode};
use crate::{Finding, Oracle, RecvKind, RecvOutcome};

/// A pending check: we sent `trigger_bytes` and expect NOTIFICATION with
/// `expected_code` and `expected_subcode`.
#[derive(Debug, Clone)]
struct TriggeredCheck {
    trigger_bytes: Vec<u8>,
    expected_code: u8,
    expected_subcode: u8,
    scenario_name: String,
}

/// Detects incorrect NOTIFICATION error codes per RFC 7606.
///
/// Uses `take_trigger()` to inject malformed BGP messages, then verifies
/// the peer's NOTIFICATION response has the correct error code/subcode.
#[derive(Debug)]
pub struct NotificationCodeOracle {
    triggers: VecDeque<TriggeredCheck>,
    pending: Option<TriggeredCheck>,
}

impl Default for NotificationCodeOracle {
    fn default() -> Self {
        NotificationCodeOracle {
            triggers: VecDeque::new(),
            pending: None,
        }
    }
}

impl NotificationCodeOracle {
    fn enqueue_scenarios(&mut self) {
        // RFC 7606 scenarios — construct malformed messages expecting specific error codes
        let scenarios: Vec<TriggeredCheck> = vec![
            // Message Header Error (1)
            TriggeredCheck {
                trigger_bytes: {
                    let mut buf = vec![0xFFu8; 16]; // marker
                    buf.extend_from_slice(&[0x00, 0x12]); // length = 18 (too short)
                    buf.push(0x01); // type = OPEN
                    buf
                },
                expected_code: 1,
                expected_subcode: 2,
                scenario_name: "Bad Message Length".into(),
            },
            TriggeredCheck {
                trigger_bytes: {
                    let mut buf = vec![0xFFu8; 16]; // marker
                    buf.extend_from_slice(&[0x00, 0x13]); // length = 19
                    buf.push(0x00); // type = 0 (bad message type)
                    buf
                },
                expected_code: 1,
                expected_subcode: 3,
                scenario_name: "Bad Message Type".into(),
            },
            // OPEN Message Error (2)
            TriggeredCheck {
                trigger_bytes: encode_open(5, 65001, 180, [10, 0, 0, 1], &[]),
                expected_code: 2,
                expected_subcode: 1,
                scenario_name: "Unsupported Version".into(),
            },
            TriggeredCheck {
                trigger_bytes: encode_open(4, 0, 180, [10, 0, 0, 1], &[]),
                expected_code: 2,
                expected_subcode: 2,
                scenario_name: "Bad Peer AS".into(),
            },
            TriggeredCheck {
                trigger_bytes: encode_open(4, 65001, 180, [0, 0, 0, 0], &[]),
                expected_code: 2,
                expected_subcode: 3,
                scenario_name: "Bad BGP Identifier".into(),
            },
            TriggeredCheck {
                trigger_bytes: encode_open(4, 65001, 1, [10, 0, 0, 1], &[]),
                expected_code: 2,
                expected_subcode: 5,
                scenario_name: "Unacceptable Hold Time".into(),
            },
            // UPDATE Message Error (3)
            TriggeredCheck {
                trigger_bytes: encode_update_missing_origin(),
                expected_code: 3,
                expected_subcode: 3,
                scenario_name: "Missing Well-known Attribute".into(),
            },
            TriggeredCheck {
                trigger_bytes: encode_update_bad_next_hop(),
                expected_code: 3,
                expected_subcode: 8,
                scenario_name: "Invalid NEXT_HOP".into(),
            },
        ];
        for s in scenarios {
            self.triggers.push_back(s);
        }
    }
}

fn encode_open(version: u8, my_as: u16, hold_time: u16, bgp_id: [u8; 4], caps: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let params: Vec<_> = caps.iter().map(|(code, val)| {
        let mut v = vec![*code];
        v.extend(val);
        bgp_wire::open::OptionalParameter { param_type: 2, param_length: v.len() as u8, param_value: v }
    }).collect();
    let msg = bgp_wire::BgpMessage::Open(bgp_wire::open::OpenMessage {
        version, my_as, hold_time, bgp_id, optional_parameters: params,
    });
    let mut buf = vec![];
    msg.encode(&mut buf);
    buf
}

fn encode_update_missing_origin() -> Vec<u8> {
    // UPDATE with only NEXT_HOP (no ORIGIN, no AS_PATH — RFC minimum is 3 attrs)
    use bgp_wire::attributes::next_hop::NextHop;
    let update = bgp_wire::update::UpdateMessage {
        withdrawn_routes: vec![],
        path_attributes: vec![Box::new(NextHop([10, 0, 0, 1]))],
        nlri: vec![],
    };
    let msg = BgpMessage::Update(update);
    let mut buf = vec![];
    msg.encode(&mut buf);
    buf
}

fn encode_update_bad_next_hop() -> Vec<u8> {
    use bgp_wire::attributes::origin::Origin;
    use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};
    use bgp_wire::attributes::next_hop::NextHop;
    let update = bgp_wire::update::UpdateMessage {
        withdrawn_routes: vec![],
        path_attributes: vec![
            Box::new(Origin(0)),
            Box::new(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] }),
            Box::new(NextHop([0, 0, 0, 0])), // all-zero NEXT_HOP
        ],
        nlri: vec![bgp_wire::NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] }],
    };
    let msg = BgpMessage::Update(update);
    let mut buf = vec![];
    msg.encode(&mut buf);
    buf
}

impl Oracle for NotificationCodeOracle {
    fn name(&self) -> &str {
        "NotificationCodeOracle"
    }

    fn take_trigger(&mut self) -> Option<Vec<u8>> {
        if self.triggers.is_empty() {
            self.enqueue_scenarios();
        }
        let next = self.triggers.pop_front()?;
        let bytes = next.trigger_bytes.clone();
        self.pending = Some(next);
        Some(bytes)
    }

    fn check(
        &mut self,
        _sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[bgp_fsm::LogEntry],
        _send_time: Instant,
    ) -> Vec<Finding> {
        let pending = match self.pending.take() {
            Some(p) => p,
            None => return vec![],
        };

        match outcome.kind {
            RecvKind::Data => {
                match BgpMessage::decode(&outcome.bytes) {
                    Ok((BgpMessage::Notification(n), _)) => {
                        if n.error_code == pending.expected_code
                            && n.error_subcode == pending.expected_subcode
                        {
                            vec![] // Correct error code
                        } else {
                            vec![Finding::NotificationCode {
                                expected: format!(
                                    "NOTIFICATION code {} subcode {} ({})",
                                    pending.expected_code, pending.expected_subcode, pending.scenario_name
                                ),
                                actual: format!(
                                    "NOTIFICATION code {} subcode {}",
                                    n.error_code, n.error_subcode
                                ),
                            }]
                        }
                    }
                    Ok((other, _)) => vec![Finding::NotificationCode {
                        expected: format!(
                            "NOTIFICATION code {} subcode {} ({})",
                            pending.expected_code, pending.expected_subcode, pending.scenario_name
                        ),
                        actual: format!("received {:?} instead of NOTIFICATION", std::mem::discriminant(&other)),
                    }],
                    Err(_) => vec![Finding::NotificationCode {
                        expected: format!(
                            "NOTIFICATION code {} subcode {} ({})",
                            pending.expected_code, pending.expected_subcode, pending.scenario_name
                        ),
                        actual: "unparseable response".into(),
                    }],
                }
            }
            RecvKind::PeerClosed | RecvKind::ConnectionReset => vec![Finding::NotificationCode {
                expected: format!(
                    "NOTIFICATION code {} subcode {} ({})",
                    pending.expected_code, pending.expected_subcode, pending.scenario_name
                ),
                actual: format!("peer closed/reset connection ({:?})", outcome.kind),
            }],
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecvKind;

    fn notif_outcome(code: u8, subcode: u8) -> RecvOutcome {
        let msg = BgpMessage::Notification(bgp_wire::notification::NotificationMessage {
            error_code: code, error_subcode: subcode, data: vec![],
        });
        let mut buf = vec![];
        msg.encode(&mut buf);
        RecvOutcome { bytes: buf, kind: RecvKind::Data }
    }

    #[test]
    fn correct_code_no_finding() {
        let mut oracle = NotificationCodeOracle::default();
        let trigger = oracle.take_trigger().unwrap();
        // Simulate correct NOTIFICATION response
        let pending = oracle.pending.as_ref().unwrap();
        let outcome = notif_outcome(pending.expected_code, pending.expected_subcode);
        let findings = oracle.check(&trigger, &outcome, &[], Instant::now());
        assert!(findings.is_empty(), "correct code should produce no finding");
    }

    #[test]
    fn wrong_code_reported() {
        let mut oracle = NotificationCodeOracle::default();
        let trigger = oracle.take_trigger().unwrap();
        let outcome = notif_outcome(0, 0); // wrong code
        let findings = oracle.check(&trigger, &outcome, &[], Instant::now());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn trigger_produces_valid_bytes() {
        let mut oracle = NotificationCodeOracle::default();
        let trigger = oracle.take_trigger().unwrap();
        // Trigger should be at least min BGP message length
        assert!(trigger.len() >= 19, "trigger too short: {}", trigger.len());
    }

    #[test]
    fn no_pending_check_returns_empty() {
        let mut oracle = NotificationCodeOracle::default();
        // No pending check set — check() should return empty
        let findings = oracle.check(&[], &RecvOutcome { bytes: vec![], kind: RecvKind::Data }, &[], Instant::now());
        assert!(findings.is_empty());
    }
}
