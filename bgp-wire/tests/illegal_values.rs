/// Illegal value preservation tests.
/// Verify that encode/decode does NOT reject or normalize illegal values.
use bgp_wire::{MessageHeader, WireDecode, WireEncode};

#[test]
fn marker_not_all_ones_is_preserved() {
    let header = MessageHeader {
        marker: [0xAB; 16],
        length: 29,
        type_code: 1,
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    let (decoded, _) = MessageHeader::decode(&buf).unwrap();
    assert_eq!(decoded.marker, [0xAB; 16]);
}

#[test]
fn length_zero_is_preserved() {
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: 0,
        type_code: 1,
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    assert_eq!(buf[16], 0x00);
    assert_eq!(buf[17], 0x00);
    let (decoded, _) = MessageHeader::decode(&buf).unwrap();
    assert_eq!(decoded.length, 0);
}

#[test]
fn length_65535_is_preserved() {
    let header = MessageHeader {
        marker: [0xFF; 16],
        length: 65535,
        type_code: 1,
    };
    let mut buf = vec![];
    header.encode(&mut buf);
    assert_eq!(buf[16], 0xFF);
    assert_eq!(buf[17], 0xFF);
    let (decoded, _) = MessageHeader::decode(&buf).unwrap();
    assert_eq!(decoded.length, 65535);
}

#[test]
fn unknown_type_code_is_preserved() {
    for tc in [0u8, 5, 99, 255] {
        let header = MessageHeader {
            marker: [0xFF; 16],
            length: 29,
            type_code: tc,
        };
        let mut buf = vec![];
        header.encode(&mut buf);
        assert_eq!(buf[18], tc, "type_code {tc} not preserved");
        let (decoded, _) = MessageHeader::decode(&buf).unwrap();
        assert_eq!(decoded.type_code, tc);
    }
}

#[test]
fn decode_too_short_buf() {
    let buf = [0u8; 10];
    let err = MessageHeader::decode(&buf).unwrap_err();
    assert!(matches!(
        err,
        bgp_wire::DecodeError::Incomplete {
            min_required: 19,
            actual: 10
        }
    ));
}
