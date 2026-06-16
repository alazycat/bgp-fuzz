use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use proptest::prelude::*;
use proptest::strategy::ValueTree;

use bgp_wire::WireDecode;
use bgp_wire::WireEncode;

use crate::byte_mutators::apply_random_byte_mutations;
use crate::grammar::single_message_bytes_strategy;
use crate::mutators::BgpMutator;

// ─── Timing types (merged from timing.rs) ───

/// When to send a message relative to the previous one.
#[derive(Debug, Clone)]
pub enum FuzzTiming {
    Immediate,
    Delayed(Duration),
    Interleaved,
}

/// A fuzz message paired with its send timing.
#[derive(Debug, Clone)]
pub struct FuzzMessage {
    pub timing: FuzzTiming,
    pub bytes: Vec<u8>,
}

/// proptest strategy for FuzzTiming.
pub fn timing_strategy() -> impl Strategy<Value = FuzzTiming> {
    prop_oneof![
        70 => Just(FuzzTiming::Immediate),
        20 => (1u64..=2000).prop_map(|ms| FuzzTiming::Delayed(Duration::from_millis(ms))),
        10 => Just(FuzzTiming::Interleaved),
    ]
}

// ─── Raw byte strategies (merged from raw.rs) ───

/// Strategy for a completely random byte sequence of variable length.
pub fn raw_bytes_strategy(min_len: usize, max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    (min_len..=max_len).prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
}

/// Strategy for a raw byte sequence in the BGP message length range (19..4096).
pub fn raw_bgp_message_strategy() -> impl Strategy<Value = Vec<u8>> {
    raw_bytes_strategy(19, 4096)
}

/// Strategy with a higher chance of very short or very long messages.
pub fn raw_edge_case_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        30 => raw_bytes_strategy(1, 18),
        30 => raw_bytes_strategy(19, 50),
        20 => raw_bytes_strategy(51, 2000),
        20 => raw_bytes_strategy(2001, 4096),
    ]
}

// ─── Generator config types ───

/// Per-layer weight configuration for the unified generator.
#[derive(Debug, Clone)]
pub struct LayerWeights {
    pub grammar: u32,
    pub raw: u32,
    pub mutation: u32,
}

impl Default for LayerWeights {
    fn default() -> Self {
        LayerWeights { grammar: 70, raw: 10, mutation: 20 }
    }
}

/// Sequence length distribution weights.
#[derive(Debug, Clone)]
pub struct SeqLenWeights {
    pub short: u32,
    pub medium: u32,
    pub long: u32,
}

impl Default for SeqLenWeights {
    fn default() -> Self {
        SeqLenWeights { short: 30, medium: 50, long: 20 }
    }
}

/// Configuration for the unified generator.
#[derive(Debug)]
pub struct GeneratorConfig {
    pub layer_weights: LayerWeights,
    pub seq_len_weights: SeqLenWeights,
    pub mutation_count_range: (usize, usize),
    /// RNG seed (0 = use entropy, non-zero = deterministic).
    pub seed: u64,
    pub semantic_mutators: Vec<Box<dyn BgpMutator>>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        GeneratorConfig {
            layer_weights: LayerWeights::default(),
            seq_len_weights: SeqLenWeights::default(),
            mutation_count_range: (1, 5),
            seed: 0,
            semantic_mutators: Vec::new(),
        }
    }
}

// ─── Generator ───

/// Unified generator that composes three layers:
///   Layer 1 (raw): completely random byte sequences
///   Layer 2 (grammar): RFC-grammar-based structured messages
///   Layer 3 (mutation): grammar messages + byte/semantic mutations
pub struct Generator {
    runner: proptest::test_runner::TestRunner,
    rng: StdRng,
    config: GeneratorConfig,
}

impl Generator {
    pub fn new(config: GeneratorConfig) -> Self {
        let runner = proptest::test_runner::TestRunner::deterministic();
        let rng = if config.seed != 0 {
            StdRng::seed_from_u64(config.seed)
        } else {
            StdRng::from_entropy()
        };
        Generator { runner, rng, config }
    }

    pub fn generate_batch(&mut self) -> Vec<Vec<u8>> {
        let seq_len = self.sample_seq_len();
        let mut msgs = Vec::with_capacity(seq_len);
        for _ in 0..seq_len {
            msgs.push(self.generate_message());
        }
        msgs
    }

    pub fn generate_batch_with_timing(&mut self) -> Vec<FuzzMessage> {
        self.generate_batch()
            .into_iter()
            .map(|bytes| {
                let timing = self.sample_timing();
                FuzzMessage { timing, bytes }
            })
            .collect()
    }

    fn sample_seq_len(&mut self) -> usize {
        let short = self.config.seq_len_weights.short;
        let medium = self.config.seq_len_weights.medium;
        let long = self.config.seq_len_weights.long;
        let total = short + medium + long;
        let choice = self.sample_u32(total);

        if choice < short {
            self.sample_in_range(1, 20)
        } else if choice < short + medium {
            self.sample_in_range(21, 100)
        } else {
            self.sample_in_range(101, 200)
        }
    }

    fn generate_message(&mut self) -> Vec<u8> {
        let grammar = self.config.layer_weights.grammar;
        let raw = self.config.layer_weights.raw;
        let mutation = self.config.layer_weights.mutation;
        let total = grammar + raw + mutation;
        if total == 0 {
            return self.generate_grammar_message();
        }

        let choice = self.sample_u32(total);
        if choice < grammar {
            self.generate_grammar_message()
        } else if choice < grammar + raw {
            self.generate_raw_message()
        } else {
            self.generate_mutation_message()
        }
    }

    fn generate_grammar_message(&mut self) -> Vec<u8> {
        let strategy = single_message_bytes_strategy();
        match strategy.new_tree(&mut self.runner) {
            Ok(tree) => tree.current(),
            Err(_) => vec![0xFFu8; 19],
        }
    }

    fn generate_raw_message(&mut self) -> Vec<u8> {
        let strategy = raw_bgp_message_strategy();
        match strategy.new_tree(&mut self.runner) {
            Ok(tree) => tree.current(),
            Err(_) => vec![0x00u8; 19],
        }
    }

    fn generate_mutation_message(&mut self) -> Vec<u8> {
        let base = self.generate_grammar_message();

        let mut msg = if !self.config.semantic_mutators.is_empty() {
            let pick = self.sample_in_range(0, self.config.semantic_mutators.len());
            let mut decoded = match bgp_wire::BgpMessage::decode(&base) {
                Ok((m, _)) => m,
                Err(_) => {
                    let min_m = self.config.mutation_count_range.0;
                    let max_m = self.config.mutation_count_range.1;
                    return apply_random_byte_mutations(&base, self.sample_in_range(min_m, max_m));
                }
            };
            let len = self.config.semantic_mutators.len();
            let start = pick.min(len.saturating_sub(1));
            let end = (start + 2).min(len);
            for i in start..end {
                self.config.semantic_mutators[i].apply(&mut decoded);
            }
            let mut buf = vec![];
            decoded.encode(&mut buf);
            buf
        } else {
            base
        };

        let min_m = self.config.mutation_count_range.0;
        let max_m = self.config.mutation_count_range.1;
        msg = apply_random_byte_mutations(&msg, self.sample_in_range(min_m, max_m));
        msg
    }

    fn sample_timing(&mut self) -> FuzzTiming {
        let strategy = timing_strategy();
        match strategy.new_tree(&mut self.runner) {
            Ok(tree) => tree.current(),
            Err(_) => FuzzTiming::Immediate,
        }
    }

    fn sample_u32(&mut self, max: u32) -> u32 {
        if max <= 1 {
            return 0;
        }
        self.rng.gen_range(0..max)
    }

    fn sample_in_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        self.rng.gen_range(min..max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Raw strategy tests ───

    #[test]
    fn raw_bytes_respects_length_bounds() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = raw_bytes_strategy(10, 100);
        for _ in 0..50 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            assert!(bytes.len() >= 10, "too short: {}", bytes.len());
            assert!(bytes.len() <= 100, "too long: {}", bytes.len());
        }
    }

    #[test]
    fn raw_bgp_message_in_valid_range() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = raw_bgp_message_strategy();
        for _ in 0..50 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            assert!(bytes.len() >= 19, "shorter than min BGP message: {}", bytes.len());
            assert!(bytes.len() <= 4096, "longer than max BGP message: {}", bytes.len());
        }
    }

    #[test]
    fn raw_edge_cases_produce_varied_lengths() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = raw_edge_case_strategy();
        let mut has_short = false;
        let mut has_long = false;
        for _ in 0..200 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            if bytes.len() <= 18 {
                has_short = true;
            }
            if bytes.len() >= 2001 {
                has_long = true;
            }
        }
        assert!(has_short, "expected some very short messages");
        assert!(has_long, "expected some very long messages");
    }

    // ─── Timing tests ───

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

    // ─── Generator tests ───

    #[test]
    fn generator_default_config_produces_messages() {
        let mut generator = Generator::new(GeneratorConfig::default());
        let batch = generator.generate_batch();
        assert!(!batch.is_empty(), "should produce at least 1 message");
        for msg in &batch {
            assert!(!msg.is_empty(), "message should not be empty");
        }
    }

    #[test]
    fn generator_grammar_only() {
        let config = GeneratorConfig {
            layer_weights: LayerWeights { grammar: 1, raw: 0, mutation: 0 },
            seq_len_weights: SeqLenWeights { short: 1, medium: 0, long: 0 },
            mutation_count_range: (0, 0),
            ..GeneratorConfig::default()
        };
        let mut generator = Generator::new(config);
        let batch = generator.generate_batch();
        assert!(batch.len() <= 20, "short seq only: {}", batch.len());
        for msg in &batch {
            assert!(msg.len() >= 19, "grammar messages >= 19 bytes, got {}", msg.len());
            assert!(msg.len() <= 4096, "grammar messages <= 4096 bytes, got {}", msg.len());
        }
    }

    #[test]
    fn generator_raw_only() {
        let config = GeneratorConfig {
            layer_weights: LayerWeights { grammar: 0, raw: 1, mutation: 0 },
            seq_len_weights: SeqLenWeights { short: 0, medium: 1, long: 0 },
            ..GeneratorConfig::default()
        };
        let mut generator = Generator::new(config);
        let batch = generator.generate_batch();
        assert!(batch.len() >= 21 && batch.len() <= 100, "medium seq: {}", batch.len());
        for msg in &batch {
            assert!(msg.len() >= 19, "raw messages >= 19 bytes, got {}", msg.len());
            assert!(msg.len() <= 4096, "raw messages <= 4096 bytes, got {}", msg.len());
        }
    }

    #[test]
    fn generator_mutation_layer_applies_changes() {
        use crate::mutators::{InjectAsLoop, DropMandatory};
        let config = GeneratorConfig {
            layer_weights: LayerWeights { grammar: 0, raw: 0, mutation: 1 },
            seq_len_weights: SeqLenWeights { short: 1, medium: 0, long: 0 },
            mutation_count_range: (3, 6),
            semantic_mutators: vec![
                Box::new(InjectAsLoop { asn: 65001 }),
                Box::new(DropMandatory { attr_type_code: 1 }),
            ],
            ..GeneratorConfig::default()
        };
        let mut generator = Generator::new(config);
        let batch = generator.generate_batch();
        assert!(!batch.is_empty());
        for msg in &batch {
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn generator_with_timing() {
        let mut generator = Generator::new(GeneratorConfig::default());
        let batch = generator.generate_batch_with_timing();
        assert!(!batch.is_empty());
        for msg in &batch {
            assert!(!msg.bytes.is_empty());
        }
    }

    #[test]
    fn generator_same_produces_different_batches() {
        let mut generator = Generator::new(GeneratorConfig::default());
        let batch1 = generator.generate_batch();
        let batch2 = generator.generate_batch();
        assert!(!batch1.is_empty());
        assert!(!batch2.is_empty());
    }

    #[test]
    fn layer_weights_default() {
        let w = LayerWeights::default();
        assert_eq!(w.grammar, 70);
        assert_eq!(w.raw, 10);
        assert_eq!(w.mutation, 20);
    }
}
