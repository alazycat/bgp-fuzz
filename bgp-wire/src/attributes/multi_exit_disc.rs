use crate::attributes::{PathAttribute, ATTR_OPTIONAL};
use crate::DecodeError;

/// MULTI_EXIT_DISC (Type Code 4) — RFC 4271 §5.1.4
///
/// Optional non-transitive attribute.
/// 4-octet unsigned metric used to discriminate among multiple exit points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiExitDisc(pub u32);

impl PathAttribute for MultiExitDisc {
    fn attr_type_code(&self) -> u8 {
        4
    }

    fn attr_flags(&self) -> u8 {
        ATTR_OPTIONAL
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.to_be_bytes());
    }

    fn decode_value(_type_code: u8, _flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Incomplete {
                min_required: 4,
                actual: buf.len(),
            });
        }
        let val = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok((MultiExitDisc(val), 4))
    }

    fn value_len(&self) -> usize {
        4
    }
}
