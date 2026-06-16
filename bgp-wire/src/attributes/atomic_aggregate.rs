use crate::attributes::{PathAttribute, ATTR_TRANSITIVE};
use crate::DecodeError;

/// ATOMIC_AGGREGATE (Type Code 6) — RFC 4271 §5.1.6
///
/// Well-known discretionary attribute.
/// Zero-length value — presence alone signals the route was aggregated
/// and some AS path information may have been lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicAggregate;

impl PathAttribute for AtomicAggregate {
    fn attr_type_code(&self) -> u8 {
        6
    }

    fn attr_flags(&self) -> u8 {
        ATTR_TRANSITIVE
    }

    fn encode_value(&self, _buf: &mut Vec<u8>) {
        // zero-length value — nothing to encode
    }

    fn decode_value(_flags: u8, _buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        // Zero-length value, consume nothing
        Ok((AtomicAggregate, 0))
    }

    fn value_len(&self) -> usize {
        0
    }
}
