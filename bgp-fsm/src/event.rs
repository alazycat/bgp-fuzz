/// Event types for the BGP FSM (RFC 4271 §8.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    ManualStart,
    ManualStop,
    AutomaticStart,
    ConnectRetryTimerExpires,
    HoldTimerExpires,
    KeepaliveTimerExpires,
    TcpConnectionConfirmed,
    TcpConnectionFails,
    BgpOpen,
    BgpKeepalive,
    BgpUpdate,
    BgpNotification,
    /// Received OPEN with unsupported version
    BgpOpenVersionError,
    /// Received a malformed BGP message
    BgpMsgError,
}

/// A full FSM event including optional message payload
#[derive(Debug, Clone)]
pub enum FsmEvent {
    Admin(EventType),
    Timer(EventType),
    Tcp(EventType),
    Message {
        event_type: EventType,
        /// Raw bytes for oracle inspection
        raw_bytes: Vec<u8>,
    },
}
