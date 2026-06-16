use proptest::prelude::*;
use proptest::strategy::ValueTree;

/// Byte-level mutation operators.
///
/// Unlike `BgpMutator` (which works on decoded BGP structures),
/// these operate directly on raw byte sequences without any parsing.
#[derive(Debug, Clone)]
pub enum ByteMutator {
    /// Flip a single bit at `pos`
    BitFlip { pos: usize, bit: u8 },
    /// Set the byte at `pos` to `value`
    ByteSet { pos: usize, value: u8 },
    /// Insert `value` at `pos`, shifting everything right
    ByteInsert { pos: usize, value: u8 },
    /// Delete the byte at `pos`
    ByteDelete { pos: usize },
    /// Swap the bytes at `a` and `b`
    ByteSwap { a: usize, b: usize },
    /// Splice `from` into the byte sequence at `at`
    Splice { from: Vec<u8>, at: usize },
}

impl ByteMutator {
    /// Apply this mutation to a byte sequence, returning the result.
    pub fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            ByteMutator::BitFlip { pos, bit } => {
                let mut v = bytes.to_vec();
                if *pos < v.len() {
                    v[*pos] ^= 1u8 << bit;
                }
                v
            }
            ByteMutator::ByteSet { pos, value } => {
                let mut v = bytes.to_vec();
                if *pos < v.len() {
                    v[*pos] = *value;
                }
                v
            }
            ByteMutator::ByteInsert { pos, value } => {
                let mut v = bytes.to_vec();
                let idx = (*pos).min(v.len());
                v.insert(idx, *value);
                v
            }
            ByteMutator::ByteDelete { pos } => {
                let mut v = bytes.to_vec();
                if *pos < v.len() {
                    v.remove(*pos);
                }
                v
            }
            ByteMutator::ByteSwap { a, b } => {
                let mut v = bytes.to_vec();
                if *a < v.len() && *b < v.len() {
                    v.swap(*a, *b);
                }
                v
            }
            ByteMutator::Splice { from, at } => {
                let mut v = bytes.to_vec();
                let idx = (*at).min(v.len());
                v.splice(idx..idx, from.iter().copied());
                v
            }
        }
    }
}

/// Strategy that generates a random ByteMutator for a byte sequence of length `len`.
pub fn byte_mutator_strategy(len: usize) -> impl Strategy<Value = ByteMutator> {
    let safe_len = len.max(1);
    let pos_range = 0..safe_len;

    prop_oneof![
        // BitFlip: pick a random byte position and random bit 0-7
        3 => (pos_range.clone(), 0u8..8).prop_map(|(pos, bit)| ByteMutator::BitFlip { pos, bit }),
        // ByteSet: set a random position to a random value
        3 => (pos_range.clone(), any::<u8>()).prop_map(|(pos, value)| ByteMutator::ByteSet { pos, value }),
        // ByteInsert: insert a random byte
        2 => ((0..=safe_len), any::<u8>()).prop_map(|(pos, value)| ByteMutator::ByteInsert { pos, value }),
        // ByteDelete
        2 => pos_range.clone().prop_map(|pos| ByteMutator::ByteDelete { pos }),
        // ByteSwap
        1 => (pos_range.clone(), pos_range.clone()).prop_map(|(a, b)| ByteMutator::ByteSwap { a, b }),
        // Splice: insert 1-8 random bytes
        1 => (prop::collection::vec(any::<u8>(), 1..8), 0..=safe_len)
            .prop_map(|(from, at)| ByteMutator::Splice { from, at }),
    ]
}

/// Apply `n` random byte mutations in sequence.
pub fn apply_random_byte_mutations(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let mut result = bytes.to_vec();
    for _ in 0..n {
        let len = result.len().max(1);
        let strategy = byte_mutator_strategy(len);
        if let Ok(tree) = strategy.new_tree(&mut runner) {
            let m = tree.current();
            result = m.apply(&result);
        }
    }
    result
}

/// Strategy that generates a pair: (input_bytes, mutated_bytes) where
/// `input_bytes` is mutated from a base message strategy.
pub fn mutated_message_strategy(
    base_bytes: Vec<u8>,
    num_mutations: usize,
) -> impl Strategy<Value = Vec<u8>> {
    Just(base_bytes).prop_flat_map(move |bytes| {
        let mut result = bytes;
        for _ in 0..num_mutations {
            let mut runner = proptest::test_runner::TestRunner::deterministic();
            let strategy = byte_mutator_strategy(result.len().max(1));
            if let Ok(tree) = strategy.new_tree(&mut runner) {
                result = tree.current().apply(&result);
            }
        }
        Just(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_flip_changes_one_bit() {
        let m = ByteMutator::BitFlip { pos: 0, bit: 0 };
        let result = m.apply(&[0xFF]);
        assert_eq!(result, vec![0xFE]);
    }

    #[test]
    fn bit_flip_out_of_range_is_noop() {
        let m = ByteMutator::BitFlip { pos: 99, bit: 0 };
        let result = m.apply(&[0x00, 0x00]);
        assert_eq!(result, vec![0x00, 0x00]);
    }

    #[test]
    fn byte_set_changes_value() {
        let m = ByteMutator::ByteSet { pos: 1, value: 0x42 };
        assert_eq!(m.apply(&[0x00, 0x00, 0x00]), vec![0x00, 0x42, 0x00]);
    }

    #[test]
    fn byte_insert_grows_sequence() {
        let m = ByteMutator::ByteInsert { pos: 1, value: 0x99 };
        assert_eq!(m.apply(&[0x00, 0x01]), vec![0x00, 0x99, 0x01]);
    }

    #[test]
    fn byte_delete_shrinks_sequence() {
        let m = ByteMutator::ByteDelete { pos: 1 };
        assert_eq!(m.apply(&[0x00, 0xFF, 0x02]), vec![0x00, 0x02]);
    }

    #[test]
    fn byte_swap_exchanges_positions() {
        let m = ByteMutator::ByteSwap { a: 0, b: 2 };
        assert_eq!(m.apply(&[0x01, 0x02, 0x03]), vec![0x03, 0x02, 0x01]);
    }

    #[test]
    fn splice_inserts_bytes() {
        let m = ByteMutator::Splice { from: vec![0xAA, 0xBB], at: 1 };
        assert_eq!(m.apply(&[0x00, 0xFF]), vec![0x00, 0xAA, 0xBB, 0xFF]);
    }

    #[test]
    fn byte_mutator_strategy_produces_all_types() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = byte_mutator_strategy(10);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let m = strategy.new_tree(&mut runner).unwrap().current();
            let tag = match m {
                ByteMutator::BitFlip { .. } => "bitflip",
                ByteMutator::ByteSet { .. } => "byteset",
                ByteMutator::ByteInsert { .. } => "byteinsert",
                ByteMutator::ByteDelete { .. } => "bytedelete",
                ByteMutator::ByteSwap { .. } => "byteswap",
                ByteMutator::Splice { .. } => "splice",
            };
            seen.insert(tag);
        }
        assert!(seen.len() >= 4, "expected at least 4 distinct mutator types, got {}", seen.len());
    }

    #[test]
    fn apply_random_mutations_modifies_bytes() {
        let original = vec![0xFFu8; 100];
        let mutated = apply_random_byte_mutations(&original, 3);
        // With 3 mutations at different positions, should differ from original
        assert_ne!(original, mutated);
    }
}
