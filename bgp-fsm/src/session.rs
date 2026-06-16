/// BGP FSM Session Attributes (RFC 4271 §8, mandatory only)
#[derive(Debug, Clone)]
pub struct SessionAttributes {
    /// Number of times the BGP peer has tried to establish a session
    pub connect_retry_counter: u32,

    /// Configured ConnectRetry time in seconds
    pub connect_retry_time: u32,
    /// Negotiated Hold Time in seconds
    pub hold_time: u32,
    /// Keepalive interval in seconds (typically hold_time / 3)
    pub keepalive_time: u32,

    /// Running ConnectRetry timer (None = not running)
    pub connect_retry_timer: Option<u32>,
    /// Running Hold timer (None = not running)
    pub hold_timer: Option<u32>,
    /// Running Keepalive timer (None = not running)
    pub keepalive_timer: Option<u32>,
}

impl SessionAttributes {
    pub fn new(hold_time: u32) -> Self {
        let keepalive_time = if hold_time > 0 {
            (hold_time / 3).max(1)
        } else {
            0 // hold_time=0 means no keepalives needed
        };
        SessionAttributes {
            connect_retry_counter: 0,
            connect_retry_time: 120, // RFC default: 120 seconds
            hold_time,
            keepalive_time,
            connect_retry_timer: None,
            hold_timer: None,
            keepalive_timer: None,
        }
    }
}
