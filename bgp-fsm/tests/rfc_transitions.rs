/// RFC 4271 §8.2.2 FSM transition tests — one test per transition rule
use bgp_fsm::{State, Legality, EventType, FsmEvent, ShadowFsm};

fn admin(et: EventType) -> FsmEvent { FsmEvent::Admin(et) }
fn timer(et: EventType) -> FsmEvent { FsmEvent::Timer(et) }
fn tcp(et: EventType) -> FsmEvent { FsmEvent::Tcp(et) }
fn msg(et: EventType) -> FsmEvent {
    FsmEvent::Message { event_type: et, raw_bytes: vec![] }
}

#[test]
fn idle_manual_start_to_connect() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&admin(EventType::ManualStart));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn idle_manual_stop_stays_idle() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&admin(EventType::ManualStop));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn idle_automatic_start_to_connect() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&admin(EventType::AutomaticStart));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn idle_bgp_open_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn idle_bgp_keepalive_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&msg(EventType::BgpKeepalive));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn idle_tcp_connection_fails_stays_idle() {
    let mut fsm = ShadowFsm::new(180);
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionFails));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn connect_tcp_confirmed_to_open_sent() {
    let mut fsm = ShadowFsm::new(180);
    fsm.step(&admin(EventType::ManualStart)); // Idle → Connect
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionConfirmed));
    assert_eq!(s, State::OpenSent);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn connect_tcp_fails_to_active() {
    let mut fsm = ShadowFsm::new(180);
    fsm.step(&admin(EventType::ManualStart)); // Idle → Connect
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionFails));
    assert_eq!(s, State::Active);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn connect_retry_timer_expires_to_connect() {
    let mut fsm = ShadowFsm::new(180);
    fsm.step(&admin(EventType::ManualStart));
    let (s, l) = fsm.step(&timer(EventType::ConnectRetryTimerExpires));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn connect_manual_stop_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.step(&admin(EventType::ManualStart));
    let (s, l) = fsm.step(&admin(EventType::ManualStop));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn connect_bgp_open_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.step(&admin(EventType::ManualStart));
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn active_tcp_confirmed_to_open_sent() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Active);
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionConfirmed));
    assert_eq!(s, State::OpenSent);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn active_tcp_fails_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Active);
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionFails));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn active_retry_timer_expires_to_connect() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Active);
    let (s, l) = fsm.step(&timer(EventType::ConnectRetryTimerExpires));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn opensent_bgp_open_to_openconfirm() {
    let mut fsm = ShadowFsm::new(180);
    // Navigate to OpenSent
    fsm.step(&admin(EventType::ManualStart));
    fsm.step(&tcp(EventType::TcpConnectionConfirmed));

    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::OpenConfirm);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn opensent_keepalive_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenSent);
    let (s, l) = fsm.step(&msg(EventType::BgpKeepalive));
    assert_eq!(s, State::OpenSent);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn opensent_update_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenSent);
    let (s, l) = fsm.step(&msg(EventType::BgpUpdate));
    assert_eq!(s, State::OpenSent);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn opensent_hold_timer_expires_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenSent);
    let (s, l) = fsm.step(&timer(EventType::HoldTimerExpires));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn opensent_version_error_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenSent);
    let (s, l) = fsm.step(&msg(EventType::BgpOpenVersionError));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn openconfirm_keepalive_to_established() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenConfirm);
    let (s, l) = fsm.step(&msg(EventType::BgpKeepalive));
    assert_eq!(s, State::Established);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn openconfirm_update_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenConfirm);
    let (s, l) = fsm.step(&msg(EventType::BgpUpdate));
    assert_eq!(s, State::OpenConfirm);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn openconfirm_bgp_open_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenConfirm);
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::OpenConfirm);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn openconfirm_notification_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::OpenConfirm);
    let (s, l) = fsm.step(&msg(EventType::BgpNotification));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn established_update_stays_established() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&msg(EventType::BgpUpdate));
    assert_eq!(s, State::Established);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn established_keepalive_stays_established() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&msg(EventType::BgpKeepalive));
    assert_eq!(s, State::Established);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn established_notification_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&msg(EventType::BgpNotification));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn established_hold_timer_expires_to_idle() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&timer(EventType::HoldTimerExpires));
    assert_eq!(s, State::Idle);
    assert_eq!(l, Legality::Legal);
}

#[test]
fn established_open_is_illegal() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::Established);
    assert_eq!(l, Legality::Illegal);
}

#[test]
fn full_session_establishment_flow() {
    let mut fsm = ShadowFsm::new(180);

    // Idle → Connect
    let (s, l) = fsm.step(&admin(EventType::ManualStart));
    assert_eq!(s, State::Connect, "step 1");
    assert_eq!(l, Legality::Legal);

    // Connect → OpenSent (TCP established)
    let (s, l) = fsm.step(&tcp(EventType::TcpConnectionConfirmed));
    assert_eq!(s, State::OpenSent, "step 2");
    assert_eq!(l, Legality::Legal);

    // OpenSent → OpenConfirm (received valid OPEN)
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::OpenConfirm, "step 3");
    assert_eq!(l, Legality::Legal);

    // OpenConfirm → Established (received KEEPALIVE)
    let (s, l) = fsm.step(&msg(EventType::BgpKeepalive));
    assert_eq!(s, State::Established, "step 4");
    assert_eq!(l, Legality::Legal);

    // Established → Established (UPDATE exchange)
    let (s, l) = fsm.step(&msg(EventType::BgpUpdate));
    assert_eq!(s, State::Established, "step 5");
    assert_eq!(l, Legality::Legal);
}

#[test]
fn tick_seconds_decrements_timers() {
    let mut fsm = ShadowFsm::new(180);
    fsm.session.hold_timer = Some(10);
    fsm.session.keepalive_timer = Some(5);

    let expired = fsm.tick_seconds(3);
    assert!(expired.is_empty());
    assert_eq!(fsm.session.hold_timer, Some(7));
    assert_eq!(fsm.session.keepalive_timer, Some(2));
}

#[test]
fn tick_seconds_fires_expired_timer() {
    let mut fsm = ShadowFsm::new(180);
    fsm.session.hold_timer = Some(3);
    fsm.session.keepalive_timer = Some(5);

    let expired = fsm.tick_seconds(4);
    assert_eq!(expired.len(), 1);
    assert!(matches!(expired[0], FsmEvent::Timer(EventType::HoldTimerExpires)));
    assert_eq!(fsm.session.hold_timer, None);
    assert_eq!(fsm.session.keepalive_timer, Some(1));
}

#[test]
fn tick_seconds_fires_multiple_timers() {
    let mut fsm = ShadowFsm::new(180);
    fsm.session.connect_retry_timer = Some(2);
    fsm.session.hold_timer = Some(2);
    fsm.session.keepalive_timer = Some(2);

    let expired = fsm.tick_seconds(2);
    assert_eq!(expired.len(), 3);
}

#[test]
fn unspecified_transition_for_unmapped_event() {
    let mut fsm = ShadowFsm::new(180);
    fsm.set_state(State::Connect);
    // AutomaticStart in Connect is unspecified
    let (s, l) = fsm.step(&admin(EventType::AutomaticStart));
    assert_eq!(s, State::Connect);
    assert_eq!(l, Legality::Unspecified);
}

#[test]
fn custom_transition_can_be_injected() {
    let mut fsm = ShadowFsm::new(180);
    // Inject: Established + BgpOpen → Idle (non-standard)
    fsm.add_transition(State::Established, EventType::BgpOpen, State::Idle, Legality::Unspecified);
    fsm.set_state(State::Established);
    let (s, l) = fsm.step(&msg(EventType::BgpOpen));
    assert_eq!(s, State::Idle); // custom rule takes effect
    assert_eq!(l, Legality::Unspecified);
}
