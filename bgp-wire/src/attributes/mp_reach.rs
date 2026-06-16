use crate::attributes::{PathAttribute, ATTR_OPTIONAL};
use crate::{DecodeError, NlriPrefix, WireDecode, WireEncode};

/// MP_REACH_NLRI (Type Code 14) — RFC 4760 §3
///
/// Optional non-transitive attribute used to advertise feasible routes
/// and the next hop for multi-protocol BGP (IPv6, VPN, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    /// Address Family Identifier (1=IPv4, 2=IPv6, ...)
    pub afi: u16,
    /// Subsequent Address Family Identifier (1=Unicast, 2=Multicast, ...)
    pub safi: u8,
    /// Network Address of Next Hop (variable length)
    pub next_hop: Vec<u8>,
    /// Network Layer Reachability Information
    pub nlri: Vec<NlriPrefix>,
}

impl PathAttribute for MpReachNlri {
    fn attr_type_code(&self) -> u8 {
        14
    }

    fn attr_flags(&self) -> u8 {
        ATTR_OPTIONAL
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.afi.to_be_bytes());
        buf.push(self.safi);
        buf.push(self.next_hop.len() as u8);
        buf.extend_from_slice(&self.next_hop);
        buf.push(0x00); // Reserved — MUST be 0 per RFC 4760
        for prefix in &self.nlri {
            prefix.encode(buf);
        }
    }

    fn decode_value(_type_code: u8, _flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 5 {
            return Err(DecodeError::Incomplete { min_required: 5, actual: buf.len() });
        }

        let afi = u16::from_be_bytes([buf[0], buf[1]]);
        let safi = buf[2];
        let nh_len = buf[3] as usize;

        let nh_start = 4;
        if buf.len() < nh_start + nh_len + 1 {
            return Err(DecodeError::Incomplete {
                min_required: nh_start + nh_len + 1,
                actual: buf.len(),
            });
        }
        let next_hop = buf[nh_start..nh_start + nh_len].to_vec();
        // Reserved byte consumed but not stored (RFC says MUST be 0, SHOULD be ignored)

        let nlri_start = nh_start + nh_len + 1;
        let mut pos = nlri_start;
        let mut nlri = Vec::new();
        while pos < buf.len() {
            if let Ok((prefix, consumed)) = NlriPrefix::decode(&buf[pos..]) {
                pos += consumed;
                nlri.push(prefix);
            } else {
                break;
            }
        }

        Ok((MpReachNlri { afi, safi, next_hop, nlri }, pos))
    }

    fn value_len(&self) -> usize {
        2 + 1 + 1 + self.next_hop.len() + 1 // AFI + SAFI + NHlen + NH + Reserved
            + self.nlri.iter().map(|p| p.wire_len()).sum::<usize>()
    }
}
