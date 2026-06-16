use std::time::Duration;

use proptest::prelude::*;

/// When to send a message relative to the previous one
#[derive(Debug, Clone)]
pub enum FuzzTiming {
    /// Send immediately after the previous message (70% default)
    Immediate,
    /// Wait for a duration before sending (20% default)
    Delayed(Duration),
    /// Send while still waiting for the previous message's response (10% default)
    Interleaved,
}

/// A fuzz message paired with its send timing
#[derive(Debug, Clone)]
pub struct FuzzMessage {
    pub timing: FuzzTiming,
    pub bytes: Vec<u8>,
}

/// proptest strategy for FuzzTiming
pub fn timing_strategy() -> impl Strategy<Value = FuzzTiming> {
    prop_oneof![
        70 => Just(FuzzTiming::Immediate),
        20 => (1u64..=2000).prop_map(|ms| FuzzTiming::Delayed(Duration::from_millis(ms))),
        10 => Just(FuzzTiming::Interleaved),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;

    #[test]
    fn timing_strategy_produces_all_variants() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = timing_strategy();
        let mut has_immediate = false;
        let mut has_delayed = false;
        let mut has_interleaved = false;
        for _ in 0..100 {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            match value {
                FuzzTiming::Immediate => has_immediate = true,
                FuzzTiming::Delayed(_) => has_delayed = true,
                FuzzTiming::Interleaved => has_interleaved = true,
            }
        }
        assert!(has_immediate);
        assert!(has_delayed);
        assert!(has_interleaved);
    }
}
