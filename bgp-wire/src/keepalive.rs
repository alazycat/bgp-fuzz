use crate::{DecodeError, MessageHeader, WireDecode, WireEncode};

/// KEEPALIVE Message (RFC 4271 §4.4)
///
/// Consists of only the 19-byte message header.
/// Sent periodically to confirm that the connection is still alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepaliveMessage;

impl WireEncode for KeepaliveMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        let header = MessageHeader {
            marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
            length: MessageHeader::LEN as u16,
            type_code: MessageHeader::TYPE_KEEPALIVE,
        };
        header.encode(buf);
    }
}

impl WireDecode for KeepaliveMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;
        // Note: we do NOT reject if type_code != 4 or length != 19 —
        // the fuzzer needs to see what the decoder sees.
        Ok((KeepaliveMessage, header.length as usize))
    }
}
