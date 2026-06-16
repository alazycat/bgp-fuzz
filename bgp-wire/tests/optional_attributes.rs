/// Tests for optional path attributes: MULTI_EXIT_DISC, LOCAL_PREF,
/// ATOMIC_AGGREGATE, AGGREGATOR
use bgp_wire::attributes::{
    multi_exit_disc::MultiExitDisc,
    local_pref::LocalPref,
    atomic_aggregate::AtomicAggregate,
    aggregator::Aggregator,
    PathAttribute,
};

// ─── MULTI_EXIT_DISC ───

#[test]
fn med_roundtrip() {
    let attr = MultiExitDisc(100);
    assert_eq!(attr.attr_type_code(), 4);
    // Optional non-transitive: Optional=1(0x80), Transitive=0
    assert_eq!(attr.attr_flags(), 0x80);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 100);
    let (decoded, n) = MultiExitDisc::decode_value(4, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(decoded.0, 100);
}

#[test]
fn med_zero_metric() {
    let attr = MultiExitDisc(0);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = MultiExitDisc::decode_value(4, attr.attr_flags(), &buf).unwrap();
    assert_eq!(decoded.0, 0);
}

#[test]
fn med_max_metric() {
    let attr = MultiExitDisc(u32::MAX);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf, [0xFF, 0xFF, 0xFF, 0xFF]);
}

// ─── LOCAL_PREF ───

#[test]
fn local_pref_roundtrip() {
    let attr = LocalPref(200);
    assert_eq!(attr.attr_type_code(), 5);
    // Well-known discretionary: Optional=0, Transitive=1(0x40)
    assert_eq!(attr.attr_flags(), 0x40);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 200);
    let (decoded, n) = LocalPref::decode_value(5, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(decoded.0, 200);
}

#[test]
fn local_pref_high_value() {
    // BGP preference is typically 0..4294967295
    let attr = LocalPref(4294967295);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = LocalPref::decode_value(5, attr.attr_flags(), &buf).unwrap();
    assert_eq!(decoded.0, 4294967295);
}

// ─── ATOMIC_AGGREGATE ───

#[test]
fn atomic_aggregate_roundtrip() {
    let attr = AtomicAggregate;
    assert_eq!(attr.attr_type_code(), 6);
    assert_eq!(attr.attr_flags(), 0x40); // Well-known discretionary
    assert_eq!(attr.value_len(), 0);

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert!(buf.is_empty());

    let (decoded, n) = AtomicAggregate::decode_value(6, attr.attr_flags(), &[]).unwrap();
    assert_eq!(n, 0);
    assert_eq!(format!("{:?}", decoded), "AtomicAggregate");
}

// ─── AGGREGATOR ───

#[test]
fn aggregator_roundtrip() {
    let attr = Aggregator {
        as_number: 65001,
        ip_address: [10, 0, 0, 1],
    };
    assert_eq!(attr.attr_type_code(), 7);
    // Optional transitive: Optional=1(0x80), Transitive=1(0x40) = 0xC0
    assert_eq!(attr.attr_flags(), 0xC0);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf.len(), 6); // AS(2) + IP(4)
    let (decoded, n) = Aggregator::decode_value(7, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(decoded.as_number, 65001);
    assert_eq!(decoded.ip_address, [10, 0, 0, 1]);
}

#[test]
fn aggregator_decode_incomplete() {
    let buf = [0x00, 0x01, 0x0A]; // only 3 bytes
    let err = Aggregator::decode_value(7, 0xC0, &buf).unwrap_err();
    assert!(matches!(
        err,
        bgp_wire::DecodeError::Incomplete {
            min_required: 6,
            actual: 3
        }
    ));
}

// ─── RFC Vector: All Seven Attributes ───

/// Per RFC 4271 §5: verify all 7 attribute type codes and flags
#[test]
fn rfc_all_seven_attribute_type_codes() {
    use bgp_wire::attributes::origin::Origin;
    use bgp_wire::attributes::as_path::AsPath;
    use bgp_wire::attributes::next_hop::NextHop;

    let attrs: Vec<(u8, u8, &str)> = vec![
        (Origin(0).attr_type_code(), Origin(0).attr_flags(), "ORIGIN"),
        (AsPath { segments: vec![] }.attr_type_code(), AsPath { segments: vec![] }.attr_flags(), "AS_PATH"),
        (NextHop([0; 4]).attr_type_code(), NextHop([0; 4]).attr_flags(), "NEXT_HOP"),
        (MultiExitDisc(0).attr_type_code(), MultiExitDisc(0).attr_flags(), "MULTI_EXIT_DISC"),
        (LocalPref(0).attr_type_code(), LocalPref(0).attr_flags(), "LOCAL_PREF"),
        (AtomicAggregate.attr_type_code(), AtomicAggregate.attr_flags(), "ATOMIC_AGGREGATE"),
        (Aggregator { as_number: 0, ip_address: [0; 4] }.attr_type_code(), Aggregator { as_number: 0, ip_address: [0; 4] }.attr_flags(), "AGGREGATOR"),
    ];

    let expected: Vec<(u8, u8, &str)> = vec![
        (1, 0x40, "ORIGIN"),
        (2, 0x40, "AS_PATH"),
        (3, 0x40, "NEXT_HOP"),
        (4, 0x80, "MULTI_EXIT_DISC"),
        (5, 0x40, "LOCAL_PREF"),
        (6, 0x40, "ATOMIC_AGGREGATE"),
        (7, 0xC0, "AGGREGATOR"),
    ];

    for ((code, flags, name), (exp_code, exp_flags, _)) in attrs.iter().zip(expected.iter()) {
        assert_eq!(*code, *exp_code, "type code mismatch for {name}");
        assert_eq!(*flags, *exp_flags, "flags mismatch for {name}");
    }
}
