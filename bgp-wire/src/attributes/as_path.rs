use crate::attributes::{PathAttribute, ATTR_TRANSITIVE};
use crate::DecodeError;

/// AS_PATH (Type Code 2) — RFC 4271 §5.1.2
///
/// Well-known mandatory attribute.
/// Contains an ordered list of AS path segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

/// An AS path segment: a sequence or set of AS numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    /// AS_SET: unordered set of ASes (segment type 1)
    AsSet(Vec<u32>),
    /// AS_SEQUENCE: ordered list of ASes (segment type 2)
    AsSequence(Vec<u32>),
}

impl AsPathSegment {
    fn segment_type(&self) -> u8 {
        match self {
            AsPathSegment::AsSet(_) => 1,
            AsPathSegment::AsSequence(_) => 2,
        }
    }

    fn as_numbers(&self) -> &[u32] {
        match self {
            AsPathSegment::AsSet(v) => v,
            AsPathSegment::AsSequence(v) => v,
        }
    }
}

impl PathAttribute for AsPath {
    fn attr_type_code(&self) -> u8 {
        2
    }

    fn attr_flags(&self) -> u8 {
        ATTR_TRANSITIVE
    }

    fn encode_value(&self, buf: &mut Vec<u8>) {
        for seg in &self.segments {
            let asns = seg.as_numbers();
            // Segment length is capped at 255 AS numbers per RFC
            for chunk in asns.chunks(255) {
                buf.push(seg.segment_type());
                buf.push(chunk.len() as u8);
                for asn in chunk {
                    buf.extend_from_slice(&asn.to_be_bytes());
                }
            }
        }
    }

    fn decode_value(_flags: u8, buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut segments = Vec::new();
        let mut pos = 0;

        while pos < buf.len() {
            if pos + 2 > buf.len() {
                // Partial segment at end — stop rather than error
                break;
            }
            let seg_type = buf[pos];
            let seg_len = buf[pos + 1] as usize;
            pos += 2;

            let _bytes_needed = seg_len * 4;
            let mut asns = Vec::with_capacity(seg_len);
            for _ in 0..seg_len {
                if pos + 4 > buf.len() {
                    // Truncated AS number — take what we can
                    break;
                }
                let asn = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                asns.push(asn);
                pos += 4;
            }

            let segment = match seg_type {
                1 => AsPathSegment::AsSet(asns),
                _ => AsPathSegment::AsSequence(asns), // default to SEQUENCE for unknown types
            };
            segments.push(segment);
        }

        Ok((AsPath { segments }, pos))
    }

    fn value_len(&self) -> usize {
        self.segments
            .iter()
            .map(|seg| 2 + seg.as_numbers().len() * 4) // type(1) + length(1) + ASNs
            .sum()
    }
}
