use bgp_fsm::{EventType, FsmEvent, Legality, ShadowFsm, State};
use bgp_fuzz_oracle::LogEntry;
use bgp_wire::{BgpMessage, MessageHeader, WireDecode};
/// Wraps ShadowFsm with automatic event logging.
///
/// Every send and receive event is classified, fed to the FSM,
/// and recorded in the event log for oracle inspection.
#[derive(Debug)]
pub struct FsmDriver {
    fsm: ShadowFsm,
    event_log: Vec<LogEntry>,
    hold_time: u32,
}

impl FsmDriver {
    pub fn new(hold_time: u32) -> Self {
        FsmDriver {
            fsm: ShadowFsm::new(hold_time),
            event_log: Vec::new(),
            hold_time,
        }
    }

    /// Record a send event and advance the FSM
    pub fn on_send(&mut self, bytes: &[u8]) -> &LogEntry {
        let event_type = classify_message(bytes);
        let event = FsmEvent::Message { event_type, raw_bytes: bytes.to_vec() };
        let (state_after, legality) = self.fsm.step(&event);
        self.push_log(state_after, legality, format!("Sent {}B: {:?}", bytes.len(), event_type))
    }

    /// Record a receive event and advance the FSM
    pub fn on_recv(&mut self, bytes: &[u8]) -> &LogEntry {
        let event_type = classify_message(bytes);
        let event = FsmEvent::Message { event_type, raw_bytes: bytes.to_vec() };
        let (state_after, legality) = self.fsm.step(&event);
        self.push_log(state_after, legality, format!("Recv {}B: {:?}", bytes.len(), event_type))
    }

    /// Record a timer expiry event
    pub fn on_timer(&mut self, event_type: EventType) -> &LogEntry {
        let event = FsmEvent::Timer(event_type);
        let (state_after, legality) = self.fsm.step(&event);
        self.push_log(state_after, legality, format!("Timer: {:?}", event_type))
    }

    fn push_log(&mut self, state_after: State, legality: Legality, desc: String) -> &LogEntry {
        self.event_log.push(LogEntry {
            state_after: format!("{:?}", state_after),
            legality: format!("{:?}", legality),
            event_description: desc,
        });
        self.event_log.last().unwrap()
    }

    pub fn current_state(&self) -> State {
        self.fsm.current_state()
    }

    pub fn set_state(&mut self, state: State) {
        self.fsm.set_state(state);
    }

    pub fn event_log(&self) -> &[LogEntry] {
        &self.event_log
    }

    pub fn tick_seconds(&mut self, seconds: u32) -> Vec<FsmEvent> {
        self.fsm.tick_seconds(seconds)
    }

    pub fn hold_time(&self) -> u32 {
        self.hold_time
    }
}

/// Quick message classification: try BgpMessage::decode, fall back to header type_code
fn classify_message(bytes: &[u8]) -> EventType {
    if let Ok((msg, _)) = BgpMessage::decode(bytes) {
        match msg {
            BgpMessage::Open(_) => EventType::BgpOpen,
            BgpMessage::Update(_) => EventType::BgpUpdate,
            BgpMessage::Keepalive(_) => EventType::BgpKeepalive,
            BgpMessage::Notification(_) => EventType::BgpNotification,
            BgpMessage::Raw { .. } => EventType::BgpMsgError,
        }
    } else if bytes.len() >= 19 {
        match bytes[18] {
            MessageHeader::TYPE_OPEN => EventType::BgpOpen,
            MessageHeader::TYPE_UPDATE => EventType::BgpUpdate,
            MessageHeader::TYPE_NOTIFICATION => EventType::BgpNotification,
            MessageHeader::TYPE_KEEPALIVE => EventType::BgpKeepalive,
            _ => EventType::BgpMsgError,
        }
    } else {
        EventType::BgpMsgError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_send_advances_fsm() {
        let mut driver = FsmDriver::new(180);
        // OPEN message bytes
        let open_bytes = {
            use bgp_wire::open::OpenMessage;
            use bgp_wire::WireEncode;
            let msg = OpenMessage {
                version: 4, my_as: 65001, hold_time: 180,
                bgp_id: [10, 0, 0, 1], optional_parameters: vec![],
            };
            let mut buf = vec![];
            msg.encode(&mut buf);
            buf
        };
        let legality = driver.on_send(&open_bytes).legality.clone();
        let state = driver.current_state();
        assert_eq!(legality, "Illegal"); // Idle + BgpOpen is illegal per RFC
        assert_eq!(state, bgp_fsm::State::Idle);
    }

    #[test]
    fn event_log_grows() {
        let mut driver = FsmDriver::new(180);
        let keepalive = [0xFFu8; 19];
        driver.on_send(&keepalive);
        driver.on_recv(&keepalive);
        assert_eq!(driver.event_log().len(), 2);
    }

    #[test]
    fn classify_unknown_is_msg_error() {
        let etype = classify_message(&[0xAA; 19]);
        assert_eq!(etype, EventType::BgpMsgError);
    }

    #[test]
    fn fsm_full_session_flow() {
        let mut driver = FsmDriver::new(180);
        driver.set_state(bgp_fsm::State::Connect);
        driver.on_send(&[0xFF; 19]); // KEEPALIVE-like
        assert_eq!(driver.event_log().len(), 1);
    }
}
