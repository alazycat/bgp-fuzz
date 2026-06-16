use crate::attributes::{PathAttribute, ATTR_TRANSITIVE};
use crate::DecodeError;

/// ORIGIN (Type Code 1) — RFC 4271 §5.1.1
///
/// Well-known mandatory attribute.
/// Values: 0=IGP, 1=EGP, 2=INCOMPLETE.
/// Illegal values (3-255) are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(pub u8);

impl PathAttribute for Origin {
    fn attr_type_code(&self) -> u8 {
        1
    }

    fn attr_flags(&self) -> u8 {
        ATTR_TRANSITIVE
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.push(self.0);
    }

    fn decode_value(_type_code: u8, _flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::Incomplete {
                min_required: 1,
                actual: 0,
            });
        }
        Ok((Origin(buf[0]), 1))
    }

    fn value_len(&self) -> usize {
        1
    }
}
