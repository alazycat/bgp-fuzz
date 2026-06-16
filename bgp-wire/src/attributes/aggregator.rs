use crate::attributes::{PathAttribute, ATTR_OPTIONAL, ATTR_TRANSITIVE};
use crate::DecodeError;

/// AGGREGATOR (Type Code 7) — RFC 4271 §5.1.7
///
/// Optional transitive attribute.
/// Contains the AS number and IP address of the BGP speaker that performed
/// route aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregator {
    /// AS number of the aggregating speaker
    pub as_number: u16,
    /// IP address of the aggregating speaker (typically BGP Identifier)
    pub ip_address: [u8; 4],
}

impl PathAttribute for Aggregator {
    fn attr_type_code(&self) -> u8 {
        7
    }

    fn attr_flags(&self) -> u8 {
        ATTR_OPTIONAL | ATTR_TRANSITIVE
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.as_number.to_be_bytes());
        buf.extend_from_slice(&self.ip_address);
    }

    fn decode_value(_flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 6 {
            return Err(DecodeError::Incomplete {
                min_required: 6,
                actual: buf.len(),
            });
        }
        let as_number = u16::from_be_bytes([buf[0], buf[1]]);
        let mut ip_address = [0u8; 4];
        ip_address.copy_from_slice(&buf[2..6]);
        Ok((Aggregator { as_number, ip_address }, 6))
    }

    fn value_len(&self) -> usize {
        6
    }
}
