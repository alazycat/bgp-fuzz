/// RFC 4271 test vectors — verify field offsets and wire format
/// against the octet diagrams in the RFC.
use bgp_wire::{MessageHeader, WireDecode, WireEncode};

/// Per RFC 4271 §4.1 (page 12):
/// Header layout: marker(0..16) | length(16..18) | type(18)
#[test]
fn rfc4271_header_field_offsets() {
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: 0x0029, // 41 bytes
        type_code: 0x01, // OPEN
    };
    let mut buf = vec![];
    header.encode(&mut buf);

    // Verify exact field positions per octet diagram
    assert_eq!(&buf[0..16], &[0xFFu8; 16], "marker at bytes 0-15 must be all ones");
    assert_eq!(buf[16], 0x00, "length high byte");
    assert_eq!(buf[17], 0x29, "length low byte");
    assert_eq!(buf[18], 0x01, "type = OPEN");
    assert_eq!(buf.len(), 19, "header is exactly 19 bytes");
}

/// Per RFC 4271 §4.1: typical KEEPALIVE header
#[test]
fn rfc4271_keepalive_header() {
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: 19, // KEEPALIVE is exactly 19 bytes (header only)
        type_code: 4, // KEEPALIVE
    };
    let mut buf = vec![];
    header.encode(&mut buf);

    assert_eq!(buf.len(), 19);
    assert_eq!(buf[16], 0x00);
    assert_eq!(buf[17], 19);
    assert_eq!(buf[18], 4);
}

/// Verify decode correctly parses a known-good wire format header
#[test]
fn rfc4271_decode_known_header() {
    let wire = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // marker
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // marker cont.
        0x00, 0x1D, // length = 29
        0x01,       // type = OPEN
    ];
    let (header, consumed) = MessageHeader::decode(&wire).unwrap();
    assert_eq!(consumed, 19);
    assert_eq!(header.marker, [0xFF; 16]);
    assert_eq!(header.length, 29);
    assert_eq!(header.type_code, 1);
}
