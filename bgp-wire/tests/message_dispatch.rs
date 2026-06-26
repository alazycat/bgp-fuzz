/// Tests for BgpMessage::type_code() and dispatch logic.
use bgp_wire::{
    BgpMessage, KeepaliveMessage, MessageHeader, NotificationMessage,
    OpenMessage, RouteRefreshMessage, UpdateMessage, WireDecode, WireEncode,
};

#[test]
fn type_code_all_variants() {
    let open = BgpMessage::Open(OpenMessage {
        version: 4, my_as: 1, hold_time: 180, bgp_id: [0; 4],
        optional_parameters: vec![],
    });
    assert_eq!(open.type_code(), MessageHeader::TYPE_OPEN);

    let update = BgpMessage::Update(UpdateMessage {
        withdrawn_routes: vec![],
        path_attributes: vec![],
        nlri: vec![],
    });
    assert_eq!(update.type_code(), MessageHeader::TYPE_UPDATE);

    let keepalive = BgpMessage::Keepalive(KeepaliveMessage);
    assert_eq!(keepalive.type_code(), MessageHeader::TYPE_KEEPALIVE);

    let notification = BgpMessage::Notification(NotificationMessage {
        error_code: 1, error_subcode: 0, data: vec![],
    });
    assert_eq!(notification.type_code(), MessageHeader::TYPE_NOTIFICATION);

    let rr = BgpMessage::RouteRefresh(RouteRefreshMessage {
        afi: 1, reserved: 0, safi: 1,
    });
    assert_eq!(rr.type_code(), MessageHeader::TYPE_ROUTE_REFRESH);

    let raw = BgpMessage::Raw { type_code: 200, data: vec![1, 2, 3] };
    assert_eq!(raw.type_code(), 200);
}

#[test]
fn type_code_raw_route_refresh_returns_5() {
    let raw = BgpMessage::Raw { type_code: MessageHeader::TYPE_ROUTE_REFRESH, data: vec![] };
    assert_eq!(raw.type_code(), 5);
}

#[test]
fn decode_route_refresh_short_body_falls_back_to_raw() {
    // Construct a message with type=5 and body < 4 bytes
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: (MessageHeader::LEN + 2) as u16, // body is 2 bytes
        type_code: MessageHeader::TYPE_ROUTE_REFRESH,
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    buf.extend_from_slice(&[0x00, 0x01]); // 2-byte body

    let (msg, _) = BgpMessage::decode(&buf).unwrap();
    assert!(matches!(msg, BgpMessage::Raw { type_code: 5, .. }));
    if let BgpMessage::Raw { type_code, data } = msg {
        assert_eq!(type_code, 5);
        assert_eq!(data, vec![0x00, 0x01]);
    }
}

#[test]
fn decode_route_refresh_full_body_parses() {
    // Full 4-byte body: AFI=1, Reserved=0, SAFI=1
    let msg = RouteRefreshMessage { afi: 1, reserved: 0, safi: 1 };
    let mut buf = vec![];
    msg.encode(&mut buf);

    let (decoded, _) = BgpMessage::decode(&buf).unwrap();
    match decoded {
        BgpMessage::RouteRefresh(rr) => {
            assert_eq!(rr.afi, 1);
            assert_eq!(rr.reserved, 0);
            assert_eq!(rr.safi, 1);
        }
        other => panic!("Expected RouteRefresh, got {:?}", other.type_code()),
    }
}

#[test]
fn bgp_message_roundtrip_all_types() {
    let messages: Vec<BgpMessage> = vec![
        BgpMessage::Open(OpenMessage {
            version: 4, my_as: 100, hold_time: 180, bgp_id: [1, 2, 3, 4],
            optional_parameters: vec![],
        }),
        BgpMessage::Update(UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: vec![],
            nlri: vec![],
        }),
        BgpMessage::Keepalive(KeepaliveMessage),
        BgpMessage::Notification(NotificationMessage {
            error_code: 3, error_subcode: 1, data: vec![],
        }),
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 2, reserved: 0, safi: 1,
        }),
        BgpMessage::Raw { type_code: 200, data: vec![0xAA, 0xBB] },
    ];

    for msg in messages {
        let mut buf = vec![];
        msg.encode(&mut buf);
        let (decoded, _) = BgpMessage::decode(&buf).unwrap();
        assert_eq!(decoded.type_code(), msg.type_code(),
            "type_code mismatch for {:?}", msg.type_code());
    }
}
