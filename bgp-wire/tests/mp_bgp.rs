/// Tests for RFC 4760 MP_REACH_NLRI and MP_UNREACH_NLRI attributes
use bgp_wire::attributes::PathAttribute;
use bgp_wire::attributes::mp_reach::MpReachNlri;
use bgp_wire::attributes::mp_unreach::MpUnreachNlri;
use bgp_wire::{NlriPrefix, UpdateMessage, WireDecode, WireEncode};

// ─── MP_REACH_NLRI ───

#[test]
fn mp_reach_ipv6_unicast_roundtrip() {
    let attr = MpReachNlri {
        afi: 2,   // IPv6
        safi: 1,  // Unicast
        next_hop: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        nlri: vec![
            NlriPrefix { prefix_len: 32, prefix: vec![0x20, 0x01, 0x0d, 0xb8] },
        ],
    };

    assert_eq!(attr.attr_type_code(), 14);
    assert_eq!(attr.attr_flags(), 0x80);

    let mut buf = vec![];
    attr.encode_value(&mut buf);

    // Verify encoding: AFI(2) + SAFI(1) + NHlen(1) + NH(16) + Reserved(1) + NLRI(1+4)
    assert_eq!(&buf[0..2], &[0x00, 0x02]);  // AFI=2 (IPv6)
    assert_eq!(buf[2], 1);                   // SAFI=1 (Unicast)
    assert_eq!(buf[3], 16);                  // NextHopLen=16
    assert_eq!(&buf[4..20], &[0x20, 0x01, 0x0d, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,1]);
    assert_eq!(buf[20], 0x00);               // Reserved
    assert_eq!(buf[21], 32);                 // NLRI prefix_len

    let (decoded, n) = MpReachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(n, 26); // 2+1+1+16+1+1+4 = 26
    assert_eq!(decoded.afi, 2);
    assert_eq!(decoded.safi, 1);
    assert_eq!(decoded.next_hop.len(), 16);
    assert_eq!(decoded.nlri.len(), 1);
}

#[test]
fn mp_reach_ipv4_unicast_roundtrip() {
    let attr = MpReachNlri {
        afi: 1,   // IPv4
        safi: 1,  // Unicast
        next_hop: vec![10, 0, 0, 1],
        nlri: vec![
            NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] },
            NlriPrefix { prefix_len: 32, prefix: vec![172, 16, 0, 1] },
        ],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = MpReachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(decoded.afi, 1);
    assert_eq!(decoded.safi, 1);
    assert_eq!(decoded.next_hop, vec![10, 0, 0, 1]);
    assert_eq!(decoded.nlri.len(), 2);
}

#[test]
fn mp_reach_zero_next_hop_len() {
    // RFC says MUST be > 0 but fuzzer tests this boundary
    let attr = MpReachNlri {
        afi: 1,
        safi: 1,
        next_hop: vec![],
        nlri: vec![NlriPrefix { prefix_len: 24, prefix: vec![10, 0, 0] }],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf[3], 0); // NextHopLen=0

    let (decoded, _) = MpReachNlri::decode_value(0x80, &buf).unwrap();
    assert!(decoded.next_hop.is_empty());
    assert_eq!(decoded.nlri.len(), 1);
}

#[test]
fn mp_reach_unknown_afi_safi() {
    // Unknown AFI/SAFI combinations are preserved
    let attr = MpReachNlri {
        afi: 0xFFFF,
        safi: 200,
        next_hop: vec![0xAA, 0xBB],
        nlri: vec![],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = MpReachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(decoded.afi, 0xFFFF);
    assert_eq!(decoded.safi, 200);
}

#[test]
fn mp_reach_multiple_nlri() {
    let attr = MpReachNlri {
        afi: 2,
        safi: 1,
        next_hop: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        nlri: vec![
            NlriPrefix { prefix_len: 32, prefix: vec![0x20, 0x01, 0x0d, 0xb8] },
            NlriPrefix { prefix_len: 48, prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01] },
            NlriPrefix { prefix_len: 64, prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00] },
        ],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = MpReachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(decoded.nlri.len(), 3);
}

// ─── MP_UNREACH_NLRI ───

#[test]
fn mp_unreach_ipv6_roundtrip() {
    let attr = MpUnreachNlri {
        afi: 2,   // IPv6
        safi: 1,  // Unicast
        withdrawn: vec![
            NlriPrefix { prefix_len: 32, prefix: vec![0x20, 0x01, 0x0d, 0xb8] },
            NlriPrefix { prefix_len: 48, prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02] },
        ],
    };

    assert_eq!(attr.attr_type_code(), 15);
    assert_eq!(attr.attr_flags(), 0x80);

    let mut buf = vec![];
    attr.encode_value(&mut buf);

    assert_eq!(&buf[0..2], &[0x00, 0x02]);  // AFI=2
    assert_eq!(buf[2], 1);                   // SAFI=1

    let (decoded, _) = MpUnreachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(decoded.afi, 2);
    assert_eq!(decoded.safi, 1);
    assert_eq!(decoded.withdrawn.len(), 2);
    assert_eq!(decoded.withdrawn[0].prefix_len, 32);
}

#[test]
fn mp_unreach_ipv4_roundtrip() {
    let attr = MpUnreachNlri {
        afi: 1,
        safi: 1,
        withdrawn: vec![NlriPrefix { prefix_len: 24, prefix: vec![10, 0, 0] }],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = MpUnreachNlri::decode_value(0x80, &buf).unwrap();
    assert_eq!(decoded.afi, 1);
    assert_eq!(decoded.withdrawn.len(), 1);
}

#[test]
fn mp_unreach_empty_withdrawn() {
    let attr = MpUnreachNlri {
        afi: 2,
        safi: 1,
        withdrawn: vec![],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf.len(), 3); // just AFI + SAFI
    let (decoded, _) = MpUnreachNlri::decode_value(0x80, &buf).unwrap();
    assert!(decoded.withdrawn.is_empty());
}

// ─── Integration: UPDATE with MP attributes ───

#[test]
fn update_with_mp_reach_nlri() {
    use bgp_wire::attributes::origin::Origin;
    use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};

    let update = UpdateMessage::builder()
        .add_attribute(Origin(0))
        .add_attribute(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] })
        .add_attribute(MpReachNlri {
            afi: 2,
            safi: 1,
            next_hop: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            nlri: vec![NlriPrefix { prefix_len: 32, prefix: vec![0x20, 0x01, 0x0d, 0xb8] }],
        })
        .build();

    let mut buf = vec![];
    update.encode(&mut buf);
    let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
    assert_eq!(decoded.path_attributes.len(), 3);

    let mp = &decoded.path_attributes[2];
    assert_eq!(mp.attr_type_code(), 14);
}

#[test]
fn update_with_mp_unreach_nlri() {
    let update = UpdateMessage::builder()
        .add_attribute(MpUnreachNlri {
            afi: 2,
            safi: 1,
            withdrawn: vec![NlriPrefix { prefix_len: 48, prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01] }],
        })
        .build();

    let mut buf = vec![];
    update.encode(&mut buf);
    let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
    assert_eq!(decoded.path_attributes.len(), 1);
    assert_eq!(decoded.path_attributes[0].attr_type_code(), 15);
}

// ─── RFC 4760 Test Vectors ───

/// Per RFC 4760 §3 (page 3): MP_REACH_NLRI octet diagram verification
#[test]
fn rfc4760_mp_reach_nlri_octet_diagram() {
    let attr = MpReachNlri {
        afi: 2,    // IPv6
        safi: 1,   // Unicast
        next_hop: vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        nlri: vec![NlriPrefix { prefix_len: 64, prefix: vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        ]}],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);

    // Verify per RFC 4760 §3 field layout:
    // +---------------------------------------------------------+
    // | Address Family Identifier (2 octets)                    |
    // +---------------------------------------------------------+
    // | Subsequent Address Family Identifier (1 octet)          |
    // +---------------------------------------------------------+
    // | Length of Next Hop Network Address (1 octet)            |
    // +---------------------------------------------------------+
    // | Network Address of Next Hop (variable)                  |
    // +---------------------------------------------------------+
    // | Reserved (1 octet)                                      |
    // +---------------------------------------------------------+
    // | Network Layer Reachability Information (variable)       |
    // +---------------------------------------------------------+
    assert_eq!(&buf[0..2], &[0x00, 0x02]);   // AFI=IPv6
    assert_eq!(buf[2], 0x01);               // SAFI=Unicast
    assert_eq!(buf[3], 16);                 // NextHopLen=16 bytes
    // NextHop: 2001:db8::1
    assert_eq!(&buf[4..20], &[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    assert_eq!(buf[20], 0x00);              // Reserved=0
    // NLRI: 2001:db8::/64
    assert_eq!(buf[21], 64);                // prefix_len
    assert_eq!(&buf[22..30], &[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    ]);
}

/// Per RFC 4760 §4 (page 5): MP_UNREACH_NLRI octet diagram verification
#[test]
fn rfc4760_mp_unreach_nlri_octet_diagram() {
    let attr = MpUnreachNlri {
        afi: 2,    // IPv6
        safi: 1,   // Unicast
        withdrawn: vec![NlriPrefix { prefix_len: 64, prefix: vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        ]}],
    };

    let mut buf = vec![];
    attr.encode_value(&mut buf);

    // Verify per RFC 4760 §4 field layout:
    // +---------------------------------------------------------+
    // | Address Family Identifier (2 octets)                    |
    // +---------------------------------------------------------+
    // | Subsequent Address Family Identifier (1 octet)          |
    // +---------------------------------------------------------+
    // | Withdrawn Routes (variable)                             |
    // +---------------------------------------------------------+
    assert_eq!(&buf[0..2], &[0x00, 0x02]);   // AFI=IPv6
    assert_eq!(buf[2], 0x01);               // SAFI=Unicast
    // Withdrawn Routes: 2001:db8::/64
    assert_eq!(buf[3], 64);                 // prefix_len
    assert_eq!(&buf[4..12], &[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    ]);
}
