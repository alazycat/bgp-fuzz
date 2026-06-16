use crate::attributes::{PathAttribute, ATTR_OPTIONAL};
use crate::{DecodeError, NlriPrefix, WireDecode, WireEncode};

/// MP_UNREACH_NLRI (Type Code 15) — RFC 4760 §4
///
/// Optional non-transitive attribute used to withdraw multiple
/// unfeasible routes for multi-protocol BGP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    /// Address Family Identifier (1=IPv4, 2=IPv6, ...)
    pub afi: u16,
    /// Subsequent Address Family Identifier (1=Unicast, 2=Multicast, ...)
    pub safi: u8,
    /// Withdrawn routes
    pub withdrawn: Vec<NlriPrefix>,
}

impl PathAttribute for MpUnreachNlri {
    fn attr_type_code(&self) -> u8 {
        15
    }

    fn attr_flags(&self) -> u8 {
        ATTR_OPTIONAL
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.afi.to_be_bytes());
        buf.push(self.safi);
        for prefix in &self.withdrawn {
            prefix.encode(buf);
        }
    }

    fn decode_value(_type_code: u8, _flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 3 {
            return Err(DecodeError::Incomplete { min_required: 3, actual: buf.len() });
        }

        let afi = u16::from_be_bytes([buf[0], buf[1]]);
        let safi = buf[2];

        let mut pos = 3;
        let mut withdrawn = Vec::new();
        while pos < buf.len() {
            if let Ok((prefix, consumed)) = NlriPrefix::decode(&buf[pos..]) {
                pos += consumed;
                withdrawn.push(prefix);
            } else {
                break;
            }
        }

        Ok((MpUnreachNlri { afi, safi, withdrawn }, pos))
    }

    fn value_len(&self) -> usize {
        2 + 1 // AFI + SAFI
            + self.withdrawn.iter().map(|p| p.wire_len()).sum::<usize>()
    }
}
