use crate::{DecodeError, MessageHeader, WireDecode, WireEncode};

/// OPEN Message (RFC 4271 §4.2)
///
/// First message sent after TCP connection establishment.
/// All fields are stored as-is; no validation is performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// Protocol version (4 for BGP-4), but any value is preserved
    pub version: u8,
    /// Autonomous System number of the sender (2 octets)
    pub my_as: u16,
    /// Proposed Hold Time in seconds (0 or >=3 per RFC, but all values preserved)
    pub hold_time: u16,
    /// BGP Identifier (4-octet unsigned integer, typically an IP address)
    pub bgp_id: [u8; 4],
    /// Optional Parameters list
    pub optional_parameters: Vec<OptionalParameter>,
}

/// Optional Parameter (RFC 4271 §4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalParameter {
    /// Parameter type (e.g., 2 for Capabilities per RFC 3392)
    pub param_type: u8,
    /// Declared length of Parameter Value in octets.
    /// May not match the actual value length (preserved for fuzzing).
    pub param_length: u8,
    /// Parameter Value bytes
    pub param_value: Vec<u8>,
}

impl OpenMessage {
    /// The minimum valid OPEN message size (header + 10-byte body, no optional params)
    pub const MIN_LEN: usize = 29;

    /// Create a new builder for an OpenMessage
    pub fn builder() -> OpenBuilder {
        OpenBuilder::default()
    }
}

#[derive(Default)]
pub struct OpenBuilder {
    version: u8,
    my_as: u16,
    hold_time: u16,
    bgp_id: [u8; 4],
    optional_parameters: Vec<OptionalParameter>,
}

impl OpenBuilder {
    pub fn version(mut self, v: u8) -> Self { self.version = v; self }
    pub fn my_as(mut self, asn: u16) -> Self { self.my_as = asn; self }
    pub fn hold_time(mut self, t: u16) -> Self { self.hold_time = t; self }
    pub fn bgp_id(mut self, id: [u8; 4]) -> Self { self.bgp_id = id; self }
    pub fn add_optional_parameter(mut self, p: OptionalParameter) -> Self { self.optional_parameters.push(p); self }

    pub fn build(self) -> OpenMessage {
        OpenMessage {
            version: self.version,
            my_as: self.my_as,
            hold_time: self.hold_time,
            bgp_id: self.bgp_id,
            optional_parameters: self.optional_parameters,
        }
    }
}

impl WireEncode for OpenMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        // Encode body first to compute length
        let mut body = vec![];
        body.push(self.version);
        body.extend_from_slice(&self.my_as.to_be_bytes());
        body.extend_from_slice(&self.hold_time.to_be_bytes());
        body.extend_from_slice(&self.bgp_id);

        // Optional Parameters
        let mut opt_bytes = vec![];
        for param in &self.optional_parameters {
            opt_bytes.push(param.param_type);
            opt_bytes.push(param.param_length);
            opt_bytes.extend_from_slice(&param.param_value);
        }
        let opt_parm_len = opt_bytes.len() as u8;
        body.push(opt_parm_len);
        body.extend_from_slice(&opt_bytes);

        let total_len = MessageHeader::LEN + body.len();
        let header = MessageHeader {
            marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
            length: total_len as u16,
            type_code: MessageHeader::TYPE_OPEN,
        };

        header.encode(buf);
        buf.extend_from_slice(&body);
    }
}

impl WireDecode for OpenMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;
        let body_start = MessageHeader::LEN;

        if buf.len() < OpenMessage::MIN_LEN {
            return Err(DecodeError::Incomplete {
                min_required: OpenMessage::MIN_LEN,
                actual: buf.len(),
            });
        }

        let version = buf[body_start];
        let my_as = u16::from_be_bytes([buf[body_start + 1], buf[body_start + 2]]);
        let hold_time = u16::from_be_bytes([buf[body_start + 3], buf[body_start + 4]]);
        let mut bgp_id = [0u8; 4];
        bgp_id.copy_from_slice(&buf[body_start + 5..body_start + 9]);
        let opt_parm_len = buf[body_start + 9] as usize;

        let mut optional_parameters = Vec::new();
        let mut pos = body_start + 10;
        let opt_end = pos + opt_parm_len;

        while pos + 2 <= opt_end && pos + 2 <= buf.len() {
            let param_type = buf[pos];
            let param_length = buf[pos + 1] as usize;
            pos += 2;
            let val_end = (pos + param_length).min(buf.len()).min(opt_end);
            let param_value = buf[pos..val_end].to_vec();
            optional_parameters.push(OptionalParameter {
                param_type,
                param_length: param_length as u8,
                param_value,
            });
            pos = val_end;
        }

        let consumed = header.length as usize;
        Ok((OpenMessage {
            version,
            my_as,
            hold_time,
            bgp_id,
            optional_parameters,
        }, consumed.min(buf.len())))
    }
}
