/// Tests for KEEPALIVE and NOTIFICATION message encode/decode
use bgp_wire::{KeepaliveMessage, NotificationMessage, WireDecode, WireEncode};

// ─── KEEPALIVE ───

/// Per RFC 4271 §4.4: KEEPALIVE is exactly 19 bytes (header only)
#[test]
fn rfc4271_keepalive_19bytes() {
    let ka = KeepaliveMessage;
    let mut buf = vec![];
    ka.encode(&mut buf);
    assert_eq!(buf.len(), 19);
    assert_eq!(&buf[0..16], &[0xFFu8; 16]);
    assert_eq!(buf[16], 0x00);
    assert_eq!(buf[17], 19);   // length
    assert_eq!(buf[18], 4);    // type = KEEPALIVE
}

#[test]
fn keepalive_roundtrip() {
    let ka = KeepaliveMessage;
    let mut buf = vec![];
    ka.encode(&mut buf);
    let (decoded, n) = KeepaliveMessage::decode(&buf).unwrap();
    assert_eq!(n, 19);
    // KeepaliveMessage is a unit struct — just verify we decoded
    assert_eq!(format!("{:?}", decoded), "KeepaliveMessage");
}

// ─── NOTIFICATION ───

/// Per RFC 4271 §4.5: NOTIFICATION with OPEN Error / Bad Peer AS
#[test]
fn rfc4271_notification_open_error() {
    let notif = NotificationMessage {
        error_code: NotificationMessage::ERR_OPEN,     // 2
        error_subcode: NotificationMessage::SUB_BAD_PEER_AS, // 2
        data: vec![],
    };
    let mut buf = vec![];
    notif.encode(&mut buf);

    assert_eq!(buf[18], 3);    // type = NOTIFICATION
    assert_eq!(buf[19], 2);    // error_code = OPEN Message Error
    assert_eq!(buf[20], 2);    // error_subcode = Bad Peer AS
    assert_eq!(buf.len(), 21); // 19 header + 2 body
}

#[test]
fn notification_roundtrip_all_error_codes() {
    let test_cases = vec![
        (1, 1, "Message Header Error / Connection Not Sync"),
        (1, 2, "Message Header Error / Bad Message Length"),
        (1, 3, "Message Header Error / Bad Message Type"),
        (2, 0, "OPEN Error / Unspecific"),
        (2, 1, "OPEN Error / Unsupported Version"),
        (2, 2, "OPEN Error / Bad Peer AS"),
        (2, 3, "OPEN Error / Bad BGP ID"),
        (2, 4, "OPEN Error / Unsupported Optional Param"),
        (3, 1, "UPDATE Error / Malformed Attribute List"),
        (3, 2, "UPDATE Error / Unrecognized Well-known Attr"),
        (3, 3, "UPDATE Error / Missing Well-known Attr"),
        (3, 4, "UPDATE Error / Attribute Flags Error"),
        (3, 5, "UPDATE Error / Attribute Length Error"),
        (3, 6, "UPDATE Error / Invalid Origin"),
        (3, 8, "UPDATE Error / Invalid NEXT_HOP"),
        (3, 9, "UPDATE Error / Optional Attr Error"),
        (3, 10, "UPDATE Error / Invalid Network Field"),
        (3, 11, "UPDATE Error / Malformed AS_PATH"),
        (4, 0, "Hold Timer Expired"),
        (5, 0, "FSM Error"),
        (6, 0, "Cease"),
    ];

    for (code, subcode, name) in &test_cases {
        let notif = NotificationMessage {
            error_code: *code,
            error_subcode: *subcode,
            data: vec![],
        };
        let mut buf = vec![];
        notif.encode(&mut buf);
        let (decoded, _) = NotificationMessage::decode(&buf)
            .expect(&format!("decode failed for {name}"));
        assert_eq!(decoded.error_code, *code, "code mismatch for {name}");
        assert_eq!(decoded.error_subcode, *subcode, "subcode mismatch for {name}");
    }
}

#[test]
fn notification_with_data_field() {
    let notif = NotificationMessage {
        error_code: 3,  // UPDATE error
        error_subcode: 1, // Malformed Attribute List
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let mut buf = vec![];
    notif.encode(&mut buf);
    let (decoded, _) = NotificationMessage::decode(&buf).unwrap();
    assert_eq!(decoded.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn notification_preserves_unknown_error_code() {
    let notif = NotificationMessage {
        error_code: 99,
        error_subcode: 255,
        data: vec![],
    };
    let mut buf = vec![];
    notif.encode(&mut buf);
    let (decoded, _) = NotificationMessage::decode(&buf).unwrap();
    assert_eq!(decoded.error_code, 99);
    assert_eq!(decoded.error_subcode, 255);
}

#[test]
fn notification_decode_too_short() {
    let buf = vec![0xFFu8; 20]; // 20 bytes (need at least 21)
    let err = NotificationMessage::decode(&buf).unwrap_err();
    assert!(matches!(
        err,
        bgp_wire::DecodeError::Incomplete { min_required: 21, actual: 20 }
    ));
}
