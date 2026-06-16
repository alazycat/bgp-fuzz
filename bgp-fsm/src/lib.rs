pub mod state;
pub mod event;
pub mod session;
pub mod machine;

use serde::{Deserialize, Serialize};

pub use state::{State, Legality};
pub use event::{EventType, FsmEvent};
pub use session::SessionAttributes;
pub use machine::ShadowFsm;

/// A single entry in the FSM event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// FSM state after the event (e.g. "Idle", "Established")
    pub state_after: String,
    /// RFC legality of the transition (e.g. "Legal", "Illegal", "Unspecified")
    pub legality: String,
    /// Human-readable event description (e.g. "Sent 64 bytes: BgpOpen")
    pub event_description: String,
}
