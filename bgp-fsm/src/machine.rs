use std::collections::HashMap;

use crate::event::{EventType, FsmEvent};
use crate::session::SessionAttributes;
use crate::state::{Legality, State};

pub(crate) type TransitionKey = (State, EventType);
pub(crate) type TransitionEntry = (State, Legality);

/// Shadow FSM — a reference implementation of RFC 4271 §8.
///
/// Maintains the current BGP session state and a transition table.
/// The transition table is mutable — a fuzzer can inject non-standard
/// transition rules to test how a target implementation handles them.
#[derive(Debug)]
pub struct ShadowFsm {
    state: State,
    pub session: SessionAttributes,
    transitions: HashMap<TransitionKey, TransitionEntry>,
}

impl ShadowFsm {
    /// Create a new FSM with the RFC 4271 §8.2.2 default transition table.
    pub fn new(hold_time: u32) -> Self {
        ShadowFsm {
            state: State::Idle,
            session: SessionAttributes::new(hold_time),
            transitions: default_transitions(),
        }
    }

    /// Step the state machine with an event.
    ///
    /// Returns (new_state, legality). If no matching transition exists
    /// in the table, returns (current_state, Legality::Unspecified).
    pub fn step(&mut self, event: &FsmEvent) -> (State, Legality) {
        let etype = match event {
            FsmEvent::Admin(t) | FsmEvent::Timer(t) | FsmEvent::Tcp(t) => *t,
            FsmEvent::Message { event_type, .. } => *event_type,
        };

        let key = (self.state, etype);
        if let Some((next_state, legality)) = self.transitions.get(&key).copied() {
            self.state = next_state;
            (next_state, legality)
        } else {
            (self.state, Legality::Unspecified)
        }
    }

    /// Advance timers by `seconds`. Returns Vec of timer expiry events.
    pub fn tick_seconds(&mut self, seconds: u32) -> Vec<FsmEvent> {
        let mut expired = Vec::new();
        advance_timer(
            &mut self.session.connect_retry_timer,
            seconds,
            EventType::ConnectRetryTimerExpires,
            &mut expired,
        );
        advance_timer(
            &mut self.session.hold_timer,
            seconds,
            EventType::HoldTimerExpires,
            &mut expired,
        );
        advance_timer(
            &mut self.session.keepalive_timer,
            seconds,
            EventType::KeepaliveTimerExpires,
            &mut expired,
        );
        expired
    }

    /// Current FSM state
    pub fn current_state(&self) -> State {
        self.state
    }

    /// Override the current state (for fuzzer injection / test setup)
    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }

    /// Reference to session attributes
    pub fn session_attrs(&self) -> &SessionAttributes {
        &self.session
    }

    /// Mutable reference to session attributes (for fuzzer timer manipulation)
    pub fn session_attrs_mut(&mut self) -> &mut SessionAttributes {
        &mut self.session
    }

    /// Add or override a transition rule (for fuzzer injection)
    pub fn add_transition(&mut self, from: State, event: EventType, to: State, legality: Legality) {
        self.transitions.insert((from, event), (to, legality));
    }

    /// Remove a transition rule
    pub fn remove_transition(&mut self, from: State, event: EventType) {
        self.transitions.remove(&(from, event));
    }
}

fn advance_timer(
    timer: &mut Option<u32>,
    seconds: u32,
    expiry_event: EventType,
    expired: &mut Vec<FsmEvent>,
) {
    let Some(remaining) = *timer else {
        return;
    };
    if remaining <= seconds {
        *timer = None;
        expired.push(FsmEvent::Timer(expiry_event));
    } else {
        *timer = Some(remaining - seconds);
    }
}

/// Build the RFC 4271 §8.2.2 default transition table.
fn default_transitions() -> HashMap<TransitionKey, TransitionEntry> {
    use EventType::*;
    use Legality::*;
    use State::*;

    let mut table = HashMap::new();

    // Event 1: ManualStart
    table.insert((Idle, ManualStart), (Connect, Legal));
    // Event 2: ManualStop — stay in Idle
    table.insert((Idle, ManualStop), (Idle, Legal));
    // Event 3: AutomaticStart
    table.insert((Idle, AutomaticStart), (Connect, Legal));
    // Event 4: ManualStart_with_PassiveTcp → Connect
    table.insert((Idle, ManualStart), (Connect, Legal));
    // Any message event in Idle is illegal
    table.insert((Idle, BgpOpen), (Idle, Illegal));
    table.insert((Idle, BgpKeepalive), (Idle, Illegal));
    table.insert((Idle, BgpUpdate), (Idle, Illegal));
    table.insert((Idle, BgpNotification), (Idle, Illegal));
    table.insert((Idle, BgpRouteRefresh), (Idle, Illegal));
    // TCP events in Idle are ignored
    table.insert((Idle, TcpConnectionConfirmed), (Idle, Illegal));
    // TcpConnectionFails in Idle — stays in Idle
    table.insert((Idle, TcpConnectionFails), (Idle, Legal));

    // TcpConnectionConfirmed → OpenSent
    table.insert((Connect, TcpConnectionConfirmed), (OpenSent, Legal));
    // TcpConnectionFails → Active (after ConnectRetryCounter check)
    table.insert((Connect, TcpConnectionFails), (Active, Legal));
    // ConnectRetryTimerExpires → Connect
    table.insert((Connect, ConnectRetryTimerExpires), (Connect, Legal));
    // ManualStop → Idle
    table.insert((Connect, ManualStop), (Idle, Legal));
    // Any message event in Connect is illegal
    table.insert((Connect, AutomaticStart), (Connect, Unspecified));
    table.insert((Connect, BgpOpen), (Connect, Illegal));
    table.insert((Connect, BgpKeepalive), (Connect, Illegal));
    table.insert((Connect, BgpRouteRefresh), (Connect, Illegal));

    table.insert((Active, TcpConnectionConfirmed), (OpenSent, Legal));
    table.insert((Active, TcpConnectionFails), (Idle, Legal));
    table.insert((Active, ConnectRetryTimerExpires), (Connect, Legal));
    table.insert((Active, ManualStop), (Idle, Legal));
    table.insert((Active, BgpOpen), (Active, Illegal));
    table.insert((Active, BgpRouteRefresh), (Active, Illegal));

    // BgpOpen with correct parameters → OpenConfirm
    table.insert((OpenSent, BgpOpen), (OpenConfirm, Legal));
    // BgpOpenVersionError → Idle (send NOTIFICATION)
    table.insert((OpenSent, BgpOpenVersionError), (Idle, Legal));
    // BgpMsgError → Idle
    table.insert((OpenSent, BgpMsgError), (Idle, Legal));
    // TcpConnectionFails → Active
    table.insert((OpenSent, TcpConnectionFails), (Active, Legal));
    // HoldTimerExpires → Idle
    table.insert((OpenSent, HoldTimerExpires), (Idle, Legal));
    // BGP messages other than OPEN are illegal in OpenSent
    table.insert((OpenSent, BgpKeepalive), (OpenSent, Illegal));
    table.insert((OpenSent, BgpUpdate), (OpenSent, Illegal));
    table.insert((OpenSent, BgpNotification), (OpenSent, Illegal));
    table.insert((OpenSent, BgpRouteRefresh), (OpenSent, Illegal));
    // ManualStop → Idle
    table.insert((OpenSent, ManualStop), (Idle, Legal));

    // BgpKeepalive → Established
    table.insert((OpenConfirm, BgpKeepalive), (Established, Legal));
    // TcpConnectionFails → Active
    table.insert((OpenConfirm, TcpConnectionFails), (Active, Legal));
    // HoldTimerExpires → Idle
    table.insert((OpenConfirm, HoldTimerExpires), (Idle, Legal));
    // KeepaliveTimerExpires → OpenConfirm (send KEEPALIVE, restart timer)
    table.insert((OpenConfirm, KeepaliveTimerExpires), (OpenConfirm, Legal));
    // BgpNotification → Idle
    table.insert((OpenConfirm, BgpNotification), (Idle, Legal));
    // BgpMsgError → Idle
    table.insert((OpenConfirm, BgpMsgError), (Idle, Legal));
    // ManualStop → Idle
    table.insert((OpenConfirm, ManualStop), (Idle, Legal));
    // OPEN in OpenConfirm is illegal
    table.insert((OpenConfirm, BgpOpen), (OpenConfirm, Illegal));
    // UPDATE in OpenConfirm is illegal (must be Established first)
    table.insert((OpenConfirm, BgpUpdate), (OpenConfirm, Illegal));
    table.insert((OpenConfirm, BgpRouteRefresh), (OpenConfirm, Illegal));

    // BgpUpdate → Established (normal update processing)
    table.insert((Established, BgpUpdate), (Established, Legal));
    // BgpKeepalive → Established (reset hold timer)
    table.insert((Established, BgpKeepalive), (Established, Legal));
    // KeepaliveTimerExpires → Established (send KEEPALIVE, restart)
    table.insert((Established, KeepaliveTimerExpires), (Established, Legal));
    // BgpNotification → Idle
    table.insert((Established, BgpNotification), (Idle, Legal));
    // BgpMsgError → Idle
    table.insert((Established, BgpMsgError), (Idle, Legal));
    // HoldTimerExpires → Idle
    table.insert((Established, HoldTimerExpires), (Idle, Legal));
    // TcpConnectionFails → Active
    table.insert((Established, TcpConnectionFails), (Active, Legal));
    // ManualStop → Idle
    table.insert((Established, ManualStop), (Idle, Legal));
    // OPEN in Established is illegal
    table.insert((Established, BgpOpen), (Established, Illegal));
    // ROUTE-REFRESH in Established is legal (RFC 2918)
    table.insert((Established, BgpRouteRefresh), (Established, Legal));

    table.insert((OpenSent, TcpConnectionFails), (Active, Legal));

    table
}
