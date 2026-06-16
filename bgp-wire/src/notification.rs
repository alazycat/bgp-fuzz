use crate::{DecodeError, MessageHeader, WireDecode, WireEncode};

/// NOTIFICATION Message (RFC 4271 §4.5)
///
/// Sent when an error condition is detected.
/// The BGP connection is closed immediately after sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    /// Error Code (RFC 4271 §6)
    pub error_code: u8,
    /// Error Subcode — depends on error_code
    pub error_subcode: u8,
    /// Additional diagnostic data (may be empty)
    pub data: Vec<u8>,
}

impl NotificationMessage {
    /// Minimum NOTIFICATION message size (header + error_code + error_subcode)
    pub const MIN_LEN: usize = 21;
}

// ─── Error Code Constants (RFC 4271 §6) ───

impl NotificationMessage {
    pub const ERR_MSG_HEADER: u8 = 1;
    pub const ERR_OPEN: u8 = 2;
    pub const ERR_UPDATE: u8 = 3;
    pub const ERR_HOLD_TIMER: u8 = 4;
    pub const ERR_FSM: u8 = 5;
    pub const ERR_CEASE: u8 = 6;

    // Message Header Error subcodes
    pub const SUB_CONN_NOT_SYNC: u8 = 1;
    pub const SUB_BAD_MSG_LEN: u8 = 2;
    pub const SUB_BAD_MSG_TYPE: u8 = 3;

    // OPEN Message Error subcodes
    pub const SUB_UNSUP_VERSION: u8 = 1;
    pub const SUB_BAD_PEER_AS: u8 = 2;
    pub const SUB_BAD_BGP_ID: u8 = 3;
    pub const SUB_UNSUP_OPT_PARAM: u8 = 4;
    pub const SUB_UNSPECIFIC: u8 = 0;

    // UPDATE Message Error subcodes
    pub const SUB_MALFORMED_ATTR_LIST: u8 = 1;
    pub const SUB_UNRECOG_WELL_KNOWN: u8 = 2;
    pub const SUB_MISSING_WELL_KNOWN: u8 = 3;
    pub const SUB_ATTR_FLAGS: u8 = 4;
    pub const SUB_ATTR_LENGTH: u8 = 5;
    pub const SUB_INVALID_ORIGIN: u8 = 6;
    pub const SUB_INVALID_NEXT_HOP: u8 = 8;
    pub const SUB_OPT_ATTR_ERROR: u8 = 9;
    pub const SUB_INVALID_NET_FIELD: u8 = 10;
    pub const SUB_MALFORMED_AS_PATH: u8 = 11;
}

impl WireEncode for NotificationMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        let total_len = MessageHeader::LEN + 2 + self.data.len();
        let header = MessageHeader {
            marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
            length: total_len as u16,
            type_code: MessageHeader::TYPE_NOTIFICATION,
        };
        header.encode(buf);
        buf.push(self.error_code);
        buf.push(self.error_subcode);
        buf.extend_from_slice(&self.data);
    }
}

impl WireDecode for NotificationMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;
        if buf.len() < NotificationMessage::MIN_LEN {
            return Err(DecodeError::Incomplete {
                min_required: NotificationMessage::MIN_LEN,
                actual: buf.len(),
            });
        }
        let error_code = buf[MessageHeader::LEN];
        let error_subcode = buf[MessageHeader::LEN + 1];
        let data_end = (MessageHeader::LEN + header.length as usize).min(buf.len());
        let data = buf[21..data_end].to_vec();
        Ok((NotificationMessage { error_code, error_subcode, data }, data_end))
    }
}
