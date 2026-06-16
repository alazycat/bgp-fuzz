use std::collections::VecDeque;
use std::time::Instant;

use bgp_wire::{BgpMessage, WireDecode};
use crate::{Finding, Oracle, RecvOutcome};

/// Detects KEEPALIVE RTT spikes using a sliding window.
///
/// Maintains the last N KEEPALIVE round-trip times. Reports a finding
/// when the current RTT exceeds mean + spike_factor * stddev.
#[derive(Debug)]
pub struct LatencyOracle {
    window: VecDeque<u64>,
    window_size: usize,
    spike_factor: f64,
}

impl Default for LatencyOracle {
    fn default() -> Self {
        LatencyOracle {
            window: VecDeque::with_capacity(20),
            window_size: 20,
            spike_factor: 3.0,
        }
    }
}

impl LatencyOracle {
    pub fn new(window_size: usize, spike_factor: f64) -> Self {
        LatencyOracle {
            window: VecDeque::with_capacity(window_size),
            window_size,
            spike_factor,
        }
    }
}

impl Oracle for LatencyOracle {
    fn name(&self) -> &str {
        "LatencyOracle"
    }

    fn check(
        &mut self,
        sent: &[u8],
        outcome: &RecvOutcome,
        _fsm_log: &[bgp_fsm::LogEntry],
        send_time: Instant,
    ) -> Vec<Finding> {
        // Only track KEEPALIVE messages
        if !is_keepalive(sent) || outcome.bytes.is_empty() {
            return vec![];
        }

        let rtt_ms = send_time.elapsed().as_millis() as u64;

        // Not enough samples yet
        if self.window.len() < self.window_size {
            self.window.push_back(rtt_ms);
            return vec![];
        }

        let (mean, stddev) = compute_stats(&self.window);
        let threshold = (mean + self.spike_factor * stddev) as u64;

        if rtt_ms > threshold {
            // Spike detected — don't add to window (would poison baseline)
            vec![Finding::LatencySpike {
                current_ms: rtt_ms,
                baseline_ms: mean as u64,
            }]
        } else {
            // Normal — add to sliding window
            self.window.push_back(rtt_ms);
            if self.window.len() > self.window_size {
                self.window.pop_front();
            }
            vec![]
        }
    }
}

fn is_keepalive(bytes: &[u8]) -> bool {
    matches!(BgpMessage::decode(bytes), Ok((BgpMessage::Keepalive(_), _)))
}

fn compute_stats(window: &VecDeque<u64>) -> (f64, f64) {
    let n = window.len() as f64;
    let sum: f64 = window.iter().map(|&v| v as f64).sum();
    let mean = sum / n;
    let variance = window.iter().map(|&v| {
        let d = v as f64 - mean;
        d * d
    }).sum::<f64>() / n;
    (mean, variance.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_wire::WireEncode;

    fn keepalive_bytes() -> Vec<u8> {
        let mut buf = vec![];
        bgp_wire::keepalive::KeepaliveMessage.encode(&mut buf);
        buf
    }

    fn data_outcome(bytes: &[u8]) -> RecvOutcome {
        RecvOutcome { bytes: bytes.to_vec(), kind: crate::RecvKind::Data }
    }

    #[test]
    fn normal_rtt_no_finding() {
        let mut oracle = LatencyOracle::new(3, 3.0);
        let ka = keepalive_bytes();
        let now = Instant::now();
        // Feed normal RTTs
        for _ in 0..3 {
            let findings = oracle.check(&ka, &data_outcome(&ka), &[], now);
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn window_not_full_no_finding() {
        let mut oracle = LatencyOracle::new(5, 3.0);
        let ka = keepalive_bytes();
        let now = Instant::now();
        for _ in 0..4 {
            let findings = oracle.check(&ka, &data_outcome(&ka), &[], now);
            assert!(findings.is_empty(), "window not full yet");
        }
    }

    #[test]
    fn non_keepalive_ignored() {
        let mut oracle = LatencyOracle::new(5, 3.0);
        let findings = oracle.check(&[0xFF; 29], &data_outcome(&[]), &[], Instant::now());
        assert!(findings.is_empty());
    }
}
