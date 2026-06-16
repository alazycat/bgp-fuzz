/// Tests for PathAttribute trait implementations: ORIGIN, AS_PATH, NEXT_HOP
use bgp_wire::attributes::{origin::Origin, as_path::{AsPath, AsPathSegment}, next_hop::NextHop};
use bgp_wire::attributes::PathAttribute;
use bgp_wire::{NlriPrefix, WireDecode, WireEncode};

// ─── ORIGIN ───

#[test]
fn origin_roundtrip_igp() {
    let attr = Origin(0);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf, [0x00]);
    let (decoded, n) = Origin::decode_value(1, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(decoded.0, 0);
}

#[test]
fn origin_roundtrip_egp() {
    let attr = Origin(1);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf, [0x01]);
}

#[test]
fn origin_roundtrip_incomplete() {
    let attr = Origin(2);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf, [0x02]);
}

#[test]
fn origin_preserves_illegal_values() {
    for v in [3u8, 99, 255] {
        let attr = Origin(v);
        let mut buf = vec![];
        attr.encode_value(&mut buf);
        let (decoded, _) = Origin::decode_value(1, attr.attr_flags(), &buf).unwrap();
        assert_eq!(decoded.0, v);
    }
}

#[test]
fn origin_flags_are_well_known_mandatory() {
    let attr = Origin(0);
    let flags = attr.attr_flags();
    assert_eq!(flags & 0x80, 0x00); // Optional=0
    assert_eq!(flags & 0x40, 0x40); // Transitive=1
}

// ─── AS_PATH ───

#[test]
fn as_path_roundtrip_single_as_sequence() {
    let attr = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
    };
    let mut buf = vec![];
    attr.encode_value(&mut buf);

    // segment type=2, len=3, 3×4 bytes ASNs
    assert_eq!(buf[0], 2);        // AS_SEQUENCE
    assert_eq!(buf[1], 3);        // 3 AS numbers
    assert_eq!(u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]), 65001);
    assert_eq!(u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]), 65002);

    let (decoded, n) = AsPath::decode_value(2, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 14); // 2 + 3*4
    assert_eq!(decoded.segments.len(), 1);
    match &decoded.segments[0] {
        AsPathSegment::AsSequence(asns) => assert_eq!(asns, &[65001, 65002, 65003]),
        _ => panic!("expected AsSequence"),
    }
}

#[test]
fn as_path_roundtrip_as_set() {
    let attr = AsPath {
        segments: vec![AsPathSegment::AsSet(vec![100, 200])],
    };
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf[0], 1); // AS_SET
    assert_eq!(buf[1], 2); // 2 AS numbers

    let (decoded, _) = AsPath::decode_value(2, attr.attr_flags(), &buf).unwrap();
    match &decoded.segments[0] {
        AsPathSegment::AsSet(asns) => assert_eq!(asns, &[100, 200]),
        _ => panic!("expected AsSet"),
    }
}

#[test]
fn as_path_multi_segment() {
    let attr = AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![65001]),
            AsPathSegment::AsSet(vec![65002, 65003]),
            AsPathSegment::AsSequence(vec![65004]),
        ],
    };
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = AsPath::decode_value(2, attr.attr_flags(), &buf).unwrap();
    assert_eq!(decoded.segments.len(), 3);
}

#[test]
fn as_path_empty_is_valid() {
    // Empty AS_PATH is used in IBGP origination
    let attr = AsPath { segments: vec![] };
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert!(buf.is_empty());
    let (decoded, _) = AsPath::decode_value(2, attr.attr_flags(), &buf).unwrap();
    assert!(decoded.segments.is_empty());
}

// ─── NEXT_HOP ───

#[test]
fn next_hop_roundtrip() {
    let attr = NextHop([10, 0, 0, 1]);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(buf, [10, 0, 0, 1]);
    let (decoded, n) = NextHop::decode_value(3, attr.attr_flags(), &buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(decoded.0, [10, 0, 0, 1]);
}

#[test]
fn next_hop_preserves_zero_addr() {
    let attr = NextHop([0, 0, 0, 0]);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    let (decoded, _) = NextHop::decode_value(3, attr.attr_flags(), &buf).unwrap();
    assert_eq!(decoded.0, [0, 0, 0, 0]);
}

// ─── NLRI ───

#[test]
fn nlri_ipv4_prefix_roundtrip() {
    let nlri = NlriPrefix {
        prefix_len: 24,
        prefix: vec![192, 168, 0],
    };
    let mut buf = vec![];
    nlri.encode(&mut buf);
    assert_eq!(buf.len(), 4); // 1 byte len + 3 bytes prefix
    assert_eq!(buf[0], 24);
    assert_eq!(&buf[1..4], &[192, 168, 0]);

    let (decoded, n) = NlriPrefix::decode(&buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(decoded.prefix_len, 24);
    assert_eq!(decoded.prefix, vec![192, 168, 0]);
}

#[test]
fn nlri_default_route() {
    let nlri = NlriPrefix {
        prefix_len: 0,
        prefix: vec![],
    };
    let mut buf = vec![];
    nlri.encode(&mut buf);
    assert_eq!(buf, [0x00]);
    let (decoded, _) = NlriPrefix::decode(&buf).unwrap();
    assert_eq!(decoded.prefix_len, 0);
    assert!(decoded.prefix.is_empty());
}

#[test]
fn nlri_ipv4_host_route() {
    let nlri = NlriPrefix {
        prefix_len: 32,
        prefix: vec![10, 0, 0, 1],
    };
    let mut buf = vec![];
    nlri.encode(&mut buf);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf[0], 32);
    let (decoded, _) = NlriPrefix::decode(&buf).unwrap();
    assert_eq!(decoded.prefix_len, 32);
    assert_eq!(decoded.prefix, vec![10, 0, 0, 1]);
}

#[test]
fn nlri_preserves_illegal_prefix_len() {
    // IPv4 prefix_len > 32 is illegal but preserved
    let nlri = NlriPrefix {
        prefix_len: 64,
        prefix: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],
    };
    let mut buf = vec![];
    nlri.encode(&mut buf);
    assert_eq!(buf[0], 64);
    let (decoded, _) = NlriPrefix::decode(&buf).unwrap();
    assert_eq!(decoded.prefix_len, 64);
}

#[test]
fn rfc_vector_origin_igp() {
    // Per RFC 4271 §5: ORIGIN=IGP is 0x00
    let attr = Origin(0);
    assert_eq!(attr.attr_type_code(), 1);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(&buf, &[0x00]);
}

#[test]
fn rfc_vector_next_hop() {
    // Per RFC 4271 §5.1.3: NEXT_HOP is 4-octet IPv4 address
    let attr = NextHop([10, 0, 0, 1]);
    let mut buf = vec![];
    attr.encode_value(&mut buf);
    assert_eq!(&buf, &[10, 0, 0, 1]);
}
