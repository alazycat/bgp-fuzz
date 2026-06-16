use bgp_wire::attributes::origin::Origin;
use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};
use bgp_wire::attributes::next_hop::NextHop;
use bgp_wire::attributes::multi_exit_disc::MultiExitDisc;
use bgp_wire::attributes::local_pref::LocalPref;
use bgp_wire::attributes::atomic_aggregate::AtomicAggregate;
use bgp_wire::attributes::aggregator::Aggregator;
use bgp_wire::attributes::mp_reach::MpReachNlri;
use bgp_wire::attributes::mp_unreach::MpUnreachNlri;
use bgp_wire::attributes::PathAttribute;
use bgp_wire::open::{OpenMessage, OptionalParameter};
use bgp_wire::update::UpdateMessage;
use bgp_wire::keepalive::KeepaliveMessage;
use bgp_wire::notification::NotificationMessage;
use bgp_wire::{BgpMessage, NlriPrefix, WireEncode};
use proptest::prelude::*;
use crate::generator::{FuzzMessage, timing_strategy};

// ─── Weighted distribution config ───

/// Weighted distribution for message types in a sequence
#[derive(Debug, Clone)]
pub struct MessageTypeWeights {
    pub open: u32,
    pub update: u32,
    pub keepalive: u32,
    pub notification: u32,
}

impl Default for MessageTypeWeights {
    fn default() -> Self {
        MessageTypeWeights {
            open: 30,
            update: 40,
            keepalive: 20,
            notification: 10,
        }
    }
}

/// Configuration for the grammar-based sequence strategy.
#[derive(Debug, Clone)]
pub struct SeqStrategyConfig {
    pub weights: MessageTypeWeights,
    pub min_seq_len: usize,
    pub max_seq_len: usize,
    pub seed: Option<u64>,
}

impl Default for SeqStrategyConfig {
    fn default() -> Self {
        SeqStrategyConfig {
            weights: MessageTypeWeights::default(),
            min_seq_len: 1,
            max_seq_len: 200,
            seed: None,
        }
    }
}

// ─── NLRI prefix strategy ───

fn nlri_prefix_strategy() -> impl Strategy<Value = NlriPrefix> {
    let prefix_len = prop_oneof![
        80 => 0u8..=32,
        10 => 33u8..=128,
        10 => any::<u8>(),
    ];
    (prefix_len, any::<Vec<u8>>()).prop_map(|(prefix_len, mut prefix)| {
        let byte_len = (prefix_len as usize).div_ceil(8);
        prefix.resize(byte_len, 0);
        NlriPrefix { prefix_len, prefix }
    })
}

// ─── Path attribute strategies ───

fn origin_strategy() -> impl Strategy<Value = Origin> {
    prop_oneof![
        80 => Just(Origin(0)),   // IGP
        10 => Just(Origin(1)),   // EGP
        5  => Just(Origin(2)),   // INCOMPLETE
        5  => any::<u8>().prop_map(Origin),
    ]
}

fn as_path_segment_strategy() -> impl Strategy<Value = AsPathSegment> {
    let asns = prop::collection::vec(1u32..=65535, 1..10);
    prop_oneof![
        80 => asns.clone().prop_map(AsPathSegment::AsSequence),
        20 => asns.prop_map(AsPathSegment::AsSet),
    ]
}

fn as_path_strategy() -> impl Strategy<Value = AsPath> {
    prop::collection::vec(as_path_segment_strategy(), 1..5)
        .prop_map(|segments| AsPath { segments })
}

fn next_hop_strategy() -> impl Strategy<Value = NextHop> {
    prop_oneof![
        90 => any::<[u8; 4]>(),
        10 => Just([0u8; 4]),
    ]
    .prop_map(NextHop)
}

fn med_strategy() -> impl Strategy<Value = MultiExitDisc> {
    any::<u32>().prop_map(MultiExitDisc)
}

fn local_pref_strategy() -> impl Strategy<Value = LocalPref> {
    any::<u32>().prop_map(LocalPref)
}

fn aggregator_strategy() -> impl Strategy<Value = Aggregator> {
    (any::<u16>(), any::<[u8; 4]>())
        .prop_map(|(as_number, ip_address)| Aggregator { as_number, ip_address })
}

fn mp_reach_strategy() -> impl Strategy<Value = MpReachNlri> {
    let afi = prop_oneof![
        80 => Just(1u16),   // IPv4
        15 => Just(2u16),   // IPv6
        5  => any::<u16>(),
    ];
    let safi = prop_oneof![
        80 => Just(1u8),    // Unicast
        20 => any::<u8>(),
    ];
    let nh = prop_oneof![
        80 => any::<Vec<u8>>().prop_filter("non-empty", |v| !v.is_empty()),
        10 => Just(vec![0u8; 4]),    // IPv4 zero
        10 => Just(vec![]),           // illegal: empty
    ];
    let nlri = prop::collection::vec(nlri_prefix_strategy(), 0..10);
    (afi, safi, nh, nlri).prop_map(|(afi, safi, next_hop, nlri)| {
        MpReachNlri { afi, safi, next_hop, nlri }
    })
}

fn mp_unreach_strategy() -> impl Strategy<Value = MpUnreachNlri> {
    let afi = prop_oneof![80 => Just(1u16), 20 => any::<u16>()];
    let safi = prop_oneof![80 => Just(1u8), 20 => any::<u8>()];
    let withdrawn = prop::collection::vec(nlri_prefix_strategy(), 0..10);
    (afi, safi, withdrawn).prop_map(|(afi, safi, withdrawn)| {
        MpUnreachNlri { afi, safi, withdrawn }
    })
}

/// Strategy for any known path attribute (including unknown as RawAttribute)
fn any_path_attribute_strategy() -> impl Strategy<Value = Box<dyn PathAttribute>> {
    prop_oneof![
        1 => origin_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => as_path_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => next_hop_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => med_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => local_pref_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => Just(AtomicAggregate).prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => aggregator_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => mp_reach_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
        1 => mp_unreach_strategy().prop_map(|a| Box::new(a) as Box<dyn PathAttribute>),
    ]
}

// ─── Optional parameter strategy ───

fn optional_param_strategy() -> impl Strategy<Value = OptionalParameter> {
    let param_type = prop_oneof![
        80 => Just(2u8),    // Capabilities (RFC 3392)
        20 => any::<u8>(),
    ];
    let value = prop::collection::vec(any::<u8>(), 0..16);
    (param_type, value).prop_map(|(param_type, param_value)| {
        OptionalParameter {
            param_type,
            param_length: param_value.len() as u8,
            param_value,
        }
    })
}

// ─── Message strategies ───

fn open_strategy() -> impl Strategy<Value = OpenMessage> {
    let version = prop_oneof![95 => Just(4u8), 5 => any::<u8>()];
    let my_as = prop_oneof![
        90 => 1u16..65535,
        5  => Just(0u16),       // reserved
        5  => any::<u16>(),
    ];
    let hold_time = prop_oneof![
        80 => Just(180u16),
        10 => any::<u16>(),
        5  => Just(0u16),
        5  => 1u16..3,
    ];
    let bgp_id = prop_oneof![90 => any::<[u8; 4]>(), 10 => Just([0u8; 4])];
    let opt_params = prop::collection::vec(optional_param_strategy(), 0..5);
    (version, my_as, hold_time, bgp_id, opt_params).prop_map(
        |(version, my_as, hold_time, bgp_id, optional_parameters)| {
            OpenMessage { version, my_as, hold_time, bgp_id, optional_parameters }
        },
    )
}

fn update_strategy() -> impl Strategy<Value = UpdateMessage> {
    let withdrawn = prop::collection::vec(nlri_prefix_strategy(), 0..5);
    let attributes = prop::collection::vec(any_path_attribute_strategy(), 1..6);
    let nlri = prop::collection::vec(nlri_prefix_strategy(), 0..10);
    (withdrawn, attributes, nlri).prop_map(|(withdrawn_routes, path_attributes, nlri)| {
        UpdateMessage { withdrawn_routes, path_attributes, nlri }
    })
}

fn notification_strategy() -> impl Strategy<Value = NotificationMessage> {
    let error_code = prop_oneof![
        1 => Just(1u8),  // Message Header Error
        1 => Just(2u8),  // OPEN Message Error
        1 => Just(3u8),  // UPDATE Message Error
        1 => Just(4u8),  // Hold Timer Expired
        1 => Just(5u8),  // FSM Error
        1 => Just(6u8),  // Cease
        1 => any::<u8>(), // unknown
    ];
    let error_subcode = prop_oneof![
        70 => any::<u8>(),
        30 => Just(0u8),
    ];
    let data = prop::collection::vec(any::<u8>(), 0..64);
    (error_code, error_subcode, data).prop_map(|(error_code, error_subcode, data)| {
        NotificationMessage { error_code, error_subcode, data }
    })
}

/// Strategy for a single BGP message: produces BgpMessage (not bytes)
fn bgp_message_strategy() -> impl Strategy<Value = BgpMessage> {
    bgp_message_strategy_weighted(MessageTypeWeights::default())
}

/// Strategy with custom type weights
fn bgp_message_strategy_weighted(
    weights: MessageTypeWeights,
) -> impl Strategy<Value = BgpMessage> {
    let w_open = weights.open;
    let w_update = weights.update;
    let w_keepalive = weights.keepalive;
    let w_notification = weights.notification;
    prop_oneof![
        w_open => open_strategy().prop_map(BgpMessage::Open),
        w_update => update_strategy().prop_map(BgpMessage::Update),
        w_keepalive => Just(KeepaliveMessage).prop_map(BgpMessage::Keepalive),
        w_notification => notification_strategy().prop_map(BgpMessage::Notification),
    ]
}

/// Strategy for a single fuzz message with custom weights
fn fuzz_message_strategy_weighted(
    weights: MessageTypeWeights,
) -> impl Strategy<Value = FuzzMessage> {
    (timing_strategy(), bgp_message_strategy_weighted(weights.clone())).prop_map(|(timing, msg)| {
        let mut bytes = vec![];
        msg.encode(&mut bytes);
        FuzzMessage { timing, bytes }
    })
}

// ─── Sequence strategy ───

/// Generate a sequence of FuzzMessage with configurable weights and length
pub fn message_sequence_strategy(
    config: &SeqStrategyConfig,
) -> impl Strategy<Value = Vec<FuzzMessage>> {
    let strategy = fuzz_message_strategy_weighted(config.weights.clone());
    prop::collection::vec(strategy, config.min_seq_len..=config.max_seq_len)
}

// ─── Convenience: generate a single message ───

/// Strategy for a single encoded BGP message (bytes only, no timing)
pub fn single_message_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    bgp_message_strategy().prop_map(|msg| {
        let mut bytes = vec![];
        msg.encode(&mut bytes);
        bytes
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_wire::WireDecode;
    use proptest::strategy::ValueTree;

    #[test]
    fn open_strategy_encodes_and_decodes() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = open_strategy().prop_map(|m| {
            let mut buf = vec![];
            m.encode(&mut buf);
            buf
        });
        for _ in 0..20 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            let (msg, _) = OpenMessage::decode(&bytes).unwrap();
            let _ = msg.version;
        }
    }

    #[test]
    fn update_strategy_encodes_and_decodes() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = update_strategy().prop_map(|m| {
            let mut buf = vec![];
            m.encode(&mut buf);
            buf
        });
        for _ in 0..20 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            let result = UpdateMessage::decode(&bytes);
            assert!(result.is_ok(), "UPDATE decode failed");
        }
    }

    #[test]
    fn keepalive_strategy_produces_encodable() {
        let msg = KeepaliveMessage;
        let mut buf = vec![];
        msg.encode(&mut buf);
        assert_eq!(buf.len(), 19);
        let (_, _): (KeepaliveMessage, _) = KeepaliveMessage::decode(&buf).unwrap();
    }

    #[test]
    fn notification_strategy_encodes_and_decodes() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = notification_strategy().prop_map(|m| {
            let mut buf = vec![];
            m.encode(&mut buf);
            buf
        });
        for _ in 0..20 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            let (msg, _) = NotificationMessage::decode(&bytes).unwrap();
            let _ = msg.error_code;
        }
    }

    #[test]
    fn bgp_message_strategy_produces_all_types() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = bgp_message_strategy();
        let mut has_open = false;
        let mut has_update = false;
        let mut has_keepalive = false;
        let mut has_notification = false;
        for _ in 0..200 {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            match value {
                BgpMessage::Open(_) => has_open = true,
                BgpMessage::Update(_) => has_update = true,
                BgpMessage::Keepalive(_) => has_keepalive = true,
                BgpMessage::Notification(_) => has_notification = true,
                _ => {}
            }
        }
        assert!(has_open, "no OPEN generated");
        assert!(has_update, "no UPDATE generated");
        assert!(has_keepalive, "no KEEPALIVE generated");
        assert!(has_notification, "no NOTIFICATION generated");
    }

    #[test]
    fn sequence_strategy_respects_length_config() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let config = SeqStrategyConfig {
            min_seq_len: 5,
            max_seq_len: 10,
            ..Default::default()
        };
        let strategy = message_sequence_strategy(&config);
        for _ in 0..20 {
            let seq = strategy.new_tree(&mut runner).unwrap().current();
            assert!(seq.len() >= 5, "seq too short: {}", seq.len());
            assert!(seq.len() <= 10, "seq too long: {}", seq.len());
            for msg in &seq {
                assert!(msg.bytes.len() >= 19, "message too short: {}", msg.bytes.len());
                assert!(BgpMessage::decode(&msg.bytes).is_ok());
            }
        }
    }

    #[test]
    fn weighted_strategy_skews_distribution() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let open_heavy = MessageTypeWeights { open: 90, update: 10, keepalive: 0, notification: 0 };
        let strategy = bgp_message_strategy_weighted(open_heavy);
        let mut open_count = 0;
        let total = 200;
        for _ in 0..total {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            if matches!(value, BgpMessage::Open(_)) {
                open_count += 1;
            }
        }
        // With 90:10 weights, OPEN should dominate
        assert!(open_count > total / 2, "OPEN: {open_count}/{total} — weights not respected");
    }

    #[test]
    fn single_message_bytes_encodes_to_valid_bgp() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = single_message_bytes_strategy();
        for _ in 0..50 {
            let bytes = strategy.new_tree(&mut runner).unwrap().current();
            assert!(bytes.len() >= 19, "too short: {} bytes", bytes.len());
            let result = BgpMessage::decode(&bytes);
            assert!(result.is_ok(), "BgpMessage decode failed for {} bytes", bytes.len());
        }
    }
}
