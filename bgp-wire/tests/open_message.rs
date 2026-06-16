/// Tests for OPEN message encode/decode
use bgp_wire::open::{OpenMessage, OptionalParameter};
use bgp_wire::{WireDecode, WireEncode};

// ─── RFC Test Vectors ───

/// Per RFC 4271 §4.2 (page 13): minimal OPEN with version=4, AS=65001,
/// hold_time=180, bgp_id=10.0.0.1, no optional parameters → 29 bytes
#[test]
fn rfc4271_open_minimal() {
    let open = OpenMessage::builder()
        .version(4)
        .my_as(65001)
        .hold_time(180)
        .bgp_id([10, 0, 0, 1])
        .build();

    let mut buf = vec![];
    open.encode(&mut buf);

    // header + OPEN body = 19 + 10 = 29 bytes
    assert_eq!(buf.len(), 29);

    // Verify per octet diagram
    assert_eq!(&buf[0..16], &[0xFFu8; 16]);       // marker
    assert_eq!(buf[16], 0x00);                      // length hi
    assert_eq!(buf[17], 29);                        // length lo (0x001D)
    assert_eq!(buf[18], 1);                         // type = OPEN
    assert_eq!(buf[19], 4);                         // version
    assert_eq!(&buf[20..22], &[0xFD, 0xE9]);        // AS=65001
    assert_eq!(&buf[22..24], &[0x00, 0xB4]);        // hold_time=180
    assert_eq!(&buf[24..28], &[10, 0, 0, 1]);       // bgp_id
    assert_eq!(buf[28], 0x00);                      // opt_parm_len = 0
}

/// Per RFC 4271 §4.2: OPEN with a Capability Optional Parameter (type=2)
#[test]
fn rfc4271_open_with_capability() {
    let open = OpenMessage::builder()
        .version(4)
        .my_as(65001)
        .hold_time(180)
        .bgp_id([10, 0, 0, 1])
        .add_optional_parameter(OptionalParameter {
            param_type: 2, // Capabilities
            param_length: 4,
            param_value: vec![0x00, 0x01, 0x01, 0x04], // MP-BGP IPv4 unicast
        })
        .build();

    let mut buf = vec![];
    open.encode(&mut buf);

    assert_eq!(buf[19], 4);                          // version
    assert_eq!(buf[28], 6);                          // opt_parm_len = 2+1+4=7 → 7... wait
    // param_type(1) + param_length(1) + param_value(4) = 6
    assert_eq!(buf[28], 6);
    assert_eq!(buf[29], 2);                          // param_type=Capability
    assert_eq!(buf[30], 4);                          // param_length=4
    assert_eq!(&buf[31..35], &[0x00, 0x01, 0x01, 0x04]);
}

// ─── Roundtrip Tests ───

#[test]
fn open_roundtrip_minimal() {
    let open = OpenMessage::builder()
        .version(4)
        .my_as(100)
        .hold_time(90)
        .bgp_id([1, 2, 3, 4])
        .build();

    let mut buf = vec![];
    open.encode(&mut buf);
    let (decoded, n) = OpenMessage::decode(&buf).unwrap();
    assert_eq!(n, 29);
    assert_eq!(decoded.version, 4);
    assert_eq!(decoded.my_as, 100);
    assert_eq!(decoded.hold_time, 90);
    assert_eq!(decoded.bgp_id, [1, 2, 3, 4]);
    assert!(decoded.optional_parameters.is_empty());
}

#[test]
fn open_roundtrip_with_params() {
    let open = OpenMessage::builder()
        .version(4)
        .my_as(65001)
        .hold_time(180)
        .bgp_id([10, 0, 0, 1])
        .add_optional_parameter(OptionalParameter { param_type: 2, param_length: 4, param_value: vec![1, 2, 3, 4] })
        .add_optional_parameter(OptionalParameter { param_type: 3, param_length: 2, param_value: vec![0xAA, 0xBB] })
        .build();

    let mut buf = vec![];
    open.encode(&mut buf);
    let (decoded, _) = OpenMessage::decode(&buf).unwrap();
    assert_eq!(decoded.optional_parameters.len(), 2);
    assert_eq!(decoded.optional_parameters[0].param_type, 2);
    assert_eq!(decoded.optional_parameters[0].param_value, vec![1, 2, 3, 4]);
    assert_eq!(decoded.optional_parameters[1].param_type, 3);
}

// ─── Illegal Value Preservation ───

#[test]
fn open_preserves_version_not_4() {
    let open = OpenMessage::builder().version(3).my_as(0).hold_time(0).bgp_id([0; 4]).build();
    let mut buf = vec![];
    open.encode(&mut buf);
    let (decoded, _) = OpenMessage::decode(&buf).unwrap();
    assert_eq!(decoded.version, 3);
}

#[test]
fn open_preserves_hold_time_illegal() {
    for ht in [0u16, 1, 2] {
        let open = OpenMessage::builder().version(4).my_as(0).hold_time(ht).bgp_id([0; 4]).build();
        let mut buf = vec![];
        open.encode(&mut buf);
        let (decoded, _) = OpenMessage::decode(&buf).unwrap();
        assert_eq!(decoded.hold_time, ht);
    }
}

#[test]
fn open_preserves_zero_bgp_id() {
    let open = OpenMessage::builder().version(4).my_as(0).hold_time(0).bgp_id([0; 4]).build();
    let mut buf = vec![];
    open.encode(&mut buf);
    let (decoded, _) = OpenMessage::decode(&buf).unwrap();
    assert_eq!(decoded.bgp_id, [0, 0, 0, 0]);
}

#[test]
fn open_param_length_mismatch_preserved() {
    // param_length says 4 but actual value is 2 bytes
    let open = OpenMessage::builder()
        .version(4).my_as(0).hold_time(0).bgp_id([0; 4])
        .add_optional_parameter(OptionalParameter { param_type: 99, param_length: 4, param_value: vec![0xAA, 0xBB] })
        .build();

    let mut buf = vec![];
    open.encode(&mut buf);
    let (decoded, _) = OpenMessage::decode(&buf).unwrap();
    assert_eq!(decoded.optional_parameters[0].param_length, 4);
    // The actual value decoded may be shorter than declared param_length
}
