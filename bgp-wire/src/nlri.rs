use crate::{DecodeError, WireDecode, WireEncode};

/// NLRI prefix: <length(1 octet), prefix(variable)> 2-tuple (RFC 4271 §4.3)
///
/// prefix_len is in bits. prefix bytes are ceil(prefix_len/8).
/// Illegal values (prefix_len > 32 for IPv4, prefix_len inconsistent with prefix bytes)
/// are preserved through encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlriPrefix {
    /// Prefix length in bits
    pub prefix_len: u8,
    /// Prefix octets (minimum needed to hold prefix_len bits, rounded up)
    pub prefix: Vec<u8>,
}

impl NlriPrefix {
    /// Wire-format byte length (1 for prefix_len + ceil(prefix_len/8) for prefix)
    pub fn wire_len(&self) -> usize {
        1 + (self.prefix_len as usize).div_ceil(8)
    }
}

impl WireEncode for NlriPrefix {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.prefix_len);
        let byte_len = (self.prefix_len as usize).div_ceil(8);
        // Use min to handle inconsistent prefix/prefix_len gracefully
        let len = byte_len.min(self.prefix.len());
        buf.extend_from_slice(&self.prefix[..len]);
        // Pad with zeros if prefix is shorter than what prefix_len requires
        buf.resize(buf.len() + byte_len.saturating_sub(len), 0);
    }
}

impl WireDecode for NlriPrefix {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::Incomplete {
                min_required: 1,
                actual: 0,
            });
        }
        let prefix_len = buf[0];
        let byte_len = (prefix_len as usize).div_ceil(8);
        if buf.len() < 1 + byte_len {
            return Err(DecodeError::Incomplete {
                min_required: 1 + byte_len,
                actual: buf.len(),
            });
        }
        let prefix = buf[1..1 + byte_len].to_vec();
        Ok((NlriPrefix { prefix_len, prefix }, 1 + byte_len))
    }
}
