use crate::{DecodeError, MessageHeader, WireDecode, WireEncode};

/// ROUTE-REFRESH Message (RFC 2918 §2)
///
/// Requests the peer to re-advertise routes for a specific AFI/SAFI.
/// All field values are preserved without validation for fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    /// Address Family Identifier (2 octets)
    pub afi: u16,
    /// Reserved field (1 octet, should be 0 on send, ignored on receive)
    pub reserved: u8,
    /// Subsequent Address Family Identifier (1 octet)
    pub safi: u8,
}

impl RouteRefreshMessage {
    /// Total message size: header (19) + body (4)
    pub const MIN_LEN: usize = MessageHeader::LEN + 4;
}

impl WireEncode for RouteRefreshMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        let header = MessageHeader {
            marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
            length: Self::MIN_LEN as u16,
            type_code: MessageHeader::TYPE_ROUTE_REFRESH,
        };
        header.encode(buf);
        buf.extend_from_slice(&self.afi.to_be_bytes());
        buf.push(self.reserved);
        buf.push(self.safi);
    }
}

impl WireDecode for RouteRefreshMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;

        if buf.len() < Self::MIN_LEN {
            return Err(DecodeError::Incomplete {
                min_required: Self::MIN_LEN,
                actual: buf.len(),
            });
        }

        let body_start = MessageHeader::LEN;
        let afi = u16::from_be_bytes([buf[body_start], buf[body_start + 1]]);
        let reserved = buf[body_start + 2];
        let safi = buf[body_start + 3];

        let consumed = header.length as usize;
        Ok((RouteRefreshMessage { afi, reserved, safi }, consumed.min(buf.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireEncode;

    #[test]
    fn round_trip_legal_values() {
        let msg = RouteRefreshMessage { afi: 1, reserved: 0, safi: 1 };
        let mut buf = vec![];
        msg.encode(&mut buf);
        let (decoded, n) = RouteRefreshMessage::decode(&buf).unwrap();
        assert_eq!(n, 23);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_illegal_values() {
        let msg = RouteRefreshMessage { afi: 0xFFFF, reserved: 0xFF, safi: 0xFF };
        let mut buf = vec![];
        msg.encode(&mut buf);
        let (decoded, _) = RouteRefreshMessage::decode(&buf).unwrap();
        assert_eq!(decoded.afi, 0xFFFF);
        assert_eq!(decoded.reserved, 0xFF);
        assert_eq!(decoded.safi, 0xFF);
    }

    #[test]
    fn decode_incomplete() {
        // Only header, no body
        let header = MessageHeader {
            marker: [0xFF; 16],
            length: 23,
            type_code: MessageHeader::TYPE_ROUTE_REFRESH,
        };
        let mut buf = vec![];
        header.encode(&mut buf);
        let result = RouteRefreshMessage::decode(&buf);
        assert!(matches!(result, Err(DecodeError::Incomplete { .. })));
    }

    #[test]
    fn rfc_test_vector_afi1_safi1() {
        // RFC test vector: AFI=1 (IPv4), SAFI=1 (Unicast), Reserved=0
        let msg = RouteRefreshMessage { afi: 1, reserved: 0, safi: 1 };
        let mut buf = vec![];
        msg.encode(&mut buf);

        assert_eq!(buf.len(), 23);

        // Byte-by-byte verification
        // Marker (16 bytes of 0xFF)
        for i in 0..16 {
            assert_eq!(buf[i], 0xFF, "marker byte {} should be 0xFF", i);
        }
        // Length (2 bytes BE) = 23
        assert_eq!(buf[16], 0x00);
        assert_eq!(buf[17], 0x17); // 23
        // Type code = 5 (ROUTE_REFRESH)
        assert_eq!(buf[18], 5);
        // AFI = 1 (2 bytes BE)
        assert_eq!(buf[19], 0x00);
        assert_eq!(buf[20], 0x01);
        // Reserved = 0
        assert_eq!(buf[21], 0x00);
        // SAFI = 1
        assert_eq!(buf[22], 0x01);
    }

    #[test]
    fn round_trip_nonzero_reserved() {
        // Reserved field with non-zero value should survive round-trip
        let msg = RouteRefreshMessage { afi: 1, reserved: 42, safi: 128 };
        let mut buf = vec![];
        msg.encode(&mut buf);
        let (decoded, _) = RouteRefreshMessage::decode(&buf).unwrap();
        assert_eq!(decoded.reserved, 42);
        assert_eq!(decoded.safi, 128);
    }
}
