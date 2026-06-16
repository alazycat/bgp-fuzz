use std::fmt::Debug;
use crate::DecodeError;

// Path attribute flag bits (RFC 4271 §5, §4.3)
/// Attribute is Optional (bit 0, 0x80)
pub const ATTR_OPTIONAL: u8 = 0x80;
/// Attribute is Transitive (bit 1, 0x40)
pub const ATTR_TRANSITIVE: u8 = 0x40;
/// Attribute is Partial (bit 2, 0x20)
pub const ATTR_PARTIAL: u8 = 0x20;
/// Extended Length encoding (bit 3, 0x10): 2-octet length field instead of 1
pub const ATTR_EXTENDED_LENGTH: u8 = 0x10;

/// Path Attribute trait (RFC 4271 §5)
///
/// Each BGP path attribute type implements this trait.
/// The trait methods operate on the attribute VALUE only —
/// the outer <flags, type_code, length> wrapper is handled
/// by the UPDATE message codec.
pub trait PathAttribute: Debug + Send + Sync {
    /// Attribute Type Code (1=ORIGIN, 2=AS_PATH, 3=NEXT_HOP, ...)
    fn attr_type_code(&self) -> u8;

    /// Attribute Flags octet:
    ///   bit 0 (0x80): Optional (1) / Well-known (0)
    ///   bit 1 (0x40): Transitive (1) / Non-transitive (0)
    ///   bit 2 (0x20): Partial (1) / Complete (0)
    ///   bit 3 (0x10): Extended Length (1) / 1-octet length (0)
    ///   bits 4-7: unused, must be 0
    fn attr_flags(&self) -> u8;

    /// Encode attribute VALUE to buf (no flags/type/length wrapper)
    fn encode_value(&self, buf: &mut Vec<u8>);

    /// Decode attribute VALUE from buf, returning (Self, consumed_byte_count)
    fn decode_value(flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized;

    /// Length of attribute VALUE in octets
    fn value_len(&self) -> usize;
}

/// A raw/unrecognized path attribute — preserves original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub type_code: u8,
    pub flags: u8,
    pub value: Vec<u8>,
}

impl PathAttribute for RawAttribute {
    fn attr_type_code(&self) -> u8 {
        self.type_code
    }

    fn attr_flags(&self) -> u8 {
        self.flags
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.value);
    }

    fn decode_value(flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let value = buf.to_vec();
        let consumed = value.len();
        // type_code must be set externally after decode
        Ok((RawAttribute { type_code: 0, flags, value }, consumed))
    }

    fn value_len(&self) -> usize {
        self.value.len()
    }
}

pub mod origin;
pub mod as_path;
pub mod next_hop;
pub mod multi_exit_disc;
pub mod local_pref;
pub mod atomic_aggregate;
pub mod aggregator;
pub mod mp_reach;
pub mod mp_unreach;

/// Decode a path attribute from its type_code, flags, and value bytes.
pub(crate) fn decode_attribute(
    type_code: u8,
    flags: u8,
    buf: &[u8],
) -> Result<Box<dyn PathAttribute>, DecodeError> {
    match type_code {
        1 => Ok(Box::new(decode_impl::<origin::Origin>(flags, buf)?)),
        2 => Ok(Box::new(decode_impl::<as_path::AsPath>(flags, buf)?)),
        3 => Ok(Box::new(decode_impl::<next_hop::NextHop>(flags, buf)?)),
        4 => Ok(Box::new(decode_impl::<multi_exit_disc::MultiExitDisc>(flags, buf)?)),
        5 => Ok(Box::new(decode_impl::<local_pref::LocalPref>(flags, buf)?)),
        6 => Ok(Box::new(decode_impl::<atomic_aggregate::AtomicAggregate>(flags, buf)?)),
        7 => Ok(Box::new(decode_impl::<aggregator::Aggregator>(flags, buf)?)),
        14 => Ok(Box::new(decode_impl::<mp_reach::MpReachNlri>(flags, buf)?)),
        15 => Ok(Box::new(decode_impl::<mp_unreach::MpUnreachNlri>(flags, buf)?)),
        _ => Ok(Box::new(RawAttribute { type_code, flags, value: buf.to_vec() })),
    }
}

fn decode_impl<T: PathAttribute>(flags: u8, buf: &[u8]) -> Result<T, DecodeError> {
    T::decode_value(flags, buf).map(|(val, _)| val)
}
