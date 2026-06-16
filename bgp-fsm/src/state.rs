/// BGP FSM States (RFC 4271 §8)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl State {
    pub const ALL: [State; 6] = [
        State::Idle,
        State::Connect,
        State::Active,
        State::OpenSent,
        State::OpenConfirm,
        State::Established,
    ];
}

/// Legality of an FSM transition per RFC 4271
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Legality {
    /// RFC explicitly allows this transition
    Legal,
    /// RFC explicitly forbids this transition (MUST NOT / SHALL NOT)
    Illegal,
    /// RFC does not specify behavior for this transition (grey area)
    Unspecified,
}
