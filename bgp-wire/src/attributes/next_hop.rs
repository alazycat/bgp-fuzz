use crate::attributes::{PathAttribute, ATTR_TRANSITIVE};
use crate::DecodeError;

/// NEXT_HOP (Type Code 3) — RFC 4271 §5.1.3
///
/// Well-known mandatory attribute.
/// 4-octet IPv4 address of the border router.
/// Illegal values (0.0.0.0, etc.) are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop(pub [u8; 4]);

impl PathAttribute for NextHop {
    fn attr_type_code(&self) -> u8 {
        3
    }

    fn attr_flags(&self) -> u8 {
        ATTR_TRANSITIVE
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    fn decode_value(_type_code: u8, _flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Incomplete {
                min_required: 4,
                actual: buf.len(),
            });
        }
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&buf[0..4]);
        Ok((NextHop(addr), 4))
    }

    fn value_len(&self) -> usize {
        4
    }
}
