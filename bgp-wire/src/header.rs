use crate::{DecodeError, MessageHeader, WireDecode, WireEncode};

impl WireEncode for MessageHeader {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.marker);
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.push(self.type_code);
    }
}

impl WireDecode for MessageHeader {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < MessageHeader::LEN {
            return Err(DecodeError::Incomplete {
                min_required: MessageHeader::LEN,
                actual: buf.len(),
            });
        }
        let mut marker = [0u8; MessageHeader::MARKER_LEN];
        marker.copy_from_slice(&buf[0..MessageHeader::MARKER_LEN]);
        let length = u16::from_be_bytes([buf[16], buf[17]]);
        let type_code = buf[18];
        Ok((MessageHeader { marker, length, type_code }, MessageHeader::LEN))
    }
}
