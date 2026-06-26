/// BGP Message Header (RFC 4271 §4.1)
///
/// All fields are stored as raw wire-format values without validation.
/// Illegal values (marker ≠ 0xFF, length < 19, unknown type_code, etc.)
/// are preserved through encode/decode round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// 16-octet marker field (normally all 0xFF)
    pub marker: [u8; 16],
    /// Total message length including header (19..=4096 in valid messages)
    pub length: u16,
    /// Message type code: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE
    pub type_code: u8,
}

impl MessageHeader {
    /// Length of the BGP message header in octets
    pub const LEN: usize = 19;
    /// Marker field value per RFC 4271 (all bits set to 1)
    pub const MARKER: u8 = 0xFF;
    /// Marker field length in octets
    pub const MARKER_LEN: usize = 16;

    // Message type codes (RFC 4271 §4.1)
    pub const TYPE_OPEN: u8 = 1;
    pub const TYPE_UPDATE: u8 = 2;
    pub const TYPE_NOTIFICATION: u8 = 3;
    pub const TYPE_KEEPALIVE: u8 = 4;
    pub const TYPE_ROUTE_REFRESH: u8 = 5;
}
