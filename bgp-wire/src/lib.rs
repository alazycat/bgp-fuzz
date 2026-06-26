pub mod error;
pub mod types;
pub mod header;
pub mod attributes;
pub mod nlri;
pub mod open;
pub mod update;
pub mod keepalive;
pub mod notification;
pub mod route_refresh;

/// BGP message type enumeration (RFC 4271 §4)
#[derive(Debug, Clone)]
pub enum BgpMessage {
    Open(open::OpenMessage),
    Update(update::UpdateMessage),
    Keepalive(keepalive::KeepaliveMessage),
    Notification(notification::NotificationMessage),
    RouteRefresh(route_refresh::RouteRefreshMessage),
    /// Unknown/raw message type
    Raw { type_code: u8, data: Vec<u8> },
}

pub use error::DecodeError;
pub use types::MessageHeader;
pub use nlri::NlriPrefix;
pub use open::{OpenMessage, OptionalParameter};
pub use update::UpdateMessage;
pub use keepalive::KeepaliveMessage;
pub use notification::NotificationMessage;
pub use route_refresh::RouteRefreshMessage;

impl WireEncode for BgpMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            BgpMessage::Open(m) => m.encode(buf),
            BgpMessage::Update(m) => m.encode(buf),
            BgpMessage::Keepalive(m) => m.encode(buf),
            BgpMessage::Notification(m) => m.encode(buf),
            BgpMessage::RouteRefresh(m) => m.encode(buf),
            BgpMessage::Raw { type_code, data } => {
                let header = MessageHeader {
                    marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
                    length: (MessageHeader::LEN + data.len()) as u16,
                    type_code: *type_code,
                };
                header.encode(buf);
                buf.extend_from_slice(data);
            }
        }
    }
}

impl WireDecode for BgpMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;
        match header.type_code {
            MessageHeader::TYPE_OPEN => {
                let (msg, n) = open::OpenMessage::decode(buf)?;
                Ok((BgpMessage::Open(msg), n))
            }
            MessageHeader::TYPE_UPDATE => {
                let (msg, n) = update::UpdateMessage::decode(buf)?;
                Ok((BgpMessage::Update(msg), n))
            }
            MessageHeader::TYPE_NOTIFICATION => {
                let (msg, n) = notification::NotificationMessage::decode(buf)?;
                Ok((BgpMessage::Notification(msg), n))
            }
            MessageHeader::TYPE_KEEPALIVE => {
                let (msg, n) = keepalive::KeepaliveMessage::decode(buf)?;
                Ok((BgpMessage::Keepalive(msg), n))
            }
            MessageHeader::TYPE_ROUTE_REFRESH => {
                let (msg, n) = route_refresh::RouteRefreshMessage::decode(buf)?;
                Ok((BgpMessage::RouteRefresh(msg), n))
            }
            unknown_code => {
                let data_end = header.length as usize;
                let data = buf[MessageHeader::LEN..data_end.min(buf.len())].to_vec();
                Ok((BgpMessage::Raw { type_code: unknown_code, data }, data_end.min(buf.len())))
            }
        }
    }
}

pub trait WireEncode {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub trait WireDecode: Sized {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>;
}
