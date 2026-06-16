use crate::attributes::{PathAttribute, ATTR_TRANSITIVE};
use crate::DecodeError;

/// LOCAL_PREF (Type Code 5) — RFC 4271 §5.1.5
///
/// Well-known discretionary attribute.
/// 4-octet unsigned integer indicating the degree of preference.
/// Higher values are preferred. Only included in IBGP updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPref(pub u32);

impl PathAttribute for LocalPref {
    fn attr_type_code(&self) -> u8 {
        5
    }

    fn attr_flags(&self) -> u8 {
        ATTR_TRANSITIVE
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.to_be_bytes());
    }

    fn decode_value(_flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Incomplete {
                min_required: 4,
                actual: buf.len(),
            });
        }
        let val = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok((LocalPref(val), 4))
    }

    fn value_len(&self) -> usize {
        4
    }
}
