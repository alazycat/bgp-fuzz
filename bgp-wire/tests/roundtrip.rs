/// Round-trip tests: random bytes → decode → encode → bytes match.
use bgp_wire::{MessageHeader, WireDecode, WireEncode};

#[test]
fn roundtrip_valid_header() {
    // A typical valid BGP header: marker=all-ones, length=29, type=OPEN(1)
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: 29,
        type_code: 1,
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    assert_eq!(buf.len(), 19);

    let (decoded, consumed) = MessageHeader::decode(&buf).unwrap();
    assert_eq!(consumed, 19);
    assert_eq!(decoded, header);
}

#[test]
fn roundtrip_illegal_values() {
    // Illegal values must survive a round-trip
    let header = MessageHeader {
        marker: [0x00; 16],       // marker should be all 0xFF per RFC
        length: 0,                 // length < 19 is illegal
        type_code: 99,             // unknown message type
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    let (decoded, _) = MessageHeader::decode(&buf).unwrap();
    assert_eq!(decoded.marker, [0x00; 16]);
    assert_eq!(decoded.length, 0);
    assert_eq!(decoded.type_code, 99);
}

#[test]
fn roundtrip_random_bytes() {
    // Random bytes should survive encode→decode round-trip exactly
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    for seed in 0..100u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        let h = hasher.finish();

        let mut marker = [0u8; 16];
        for (i, b) in marker.iter_mut().enumerate() {
            *b = ((h >> (i % 8 * 8)) & 0xFF) as u8;
        }
        let length = ((h >> 16) & 0xFFFF) as u16;
        let type_code = ((h >> 32) & 0xFF) as u8;

        let header = MessageHeader { marker, length, type_code };
        let mut buf = vec![];
        header.encode(&mut buf);
        let (decoded, _) = MessageHeader::decode(&buf).unwrap();
        assert_eq!(decoded, header, "roundtrip failed for seed {seed}");
    }
}
