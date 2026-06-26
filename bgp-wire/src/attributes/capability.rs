use crate::{DecodeError, OptionalParameter};

/// BGP Capability (RFC 5492)
///
/// All values including `declared_len` are preserved through encode/decode
/// round-trips without validation. Mismatch between `declared_len` and the
/// actual value length is preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Multiprotocol Extensions Capability (type 1, RFC 4760)
    MultiProtocol { declared_len: u8, afi: u16, safi: u8 },
    /// Route Refresh Capability (type 2, RFC 2918)
    RouteRefresh { declared_len: u8 },
    /// Graceful Restart Capability (type 64, RFC 4724)
    GracefulRestart { declared_len: u8, flags: u16, families: Vec<u8> },
    /// Four-Octet AS Number Capability (type 65, RFC 6793)
    FourOctetAsn { declared_len: u8, asn: u32 },
    /// Unknown/raw capability type
    Raw { type_code: u8, declared_len: u8, value: Vec<u8> },
}

impl Capability {
    /// Optional Parameter type code for Capabilities (RFC 5492 §4)
    pub const OPT_PARAM_TYPE: u8 = 2;

    fn type_code(&self) -> u8 {
        match self {
            Capability::MultiProtocol { .. } => 1,
            Capability::RouteRefresh { .. } => 2,
            Capability::GracefulRestart { .. } => 64,
            Capability::FourOctetAsn { .. } => 65,
            Capability::Raw { type_code, .. } => *type_code,
        }
    }

    fn declared_len(&self) -> u8 {
        match self {
            Capability::MultiProtocol { declared_len, .. } => *declared_len,
            Capability::RouteRefresh { declared_len } => *declared_len,
            Capability::GracefulRestart { declared_len, .. } => *declared_len,
            Capability::FourOctetAsn { declared_len, .. } => *declared_len,
            Capability::Raw { declared_len, .. } => *declared_len,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut value_bytes = vec![];
        match self {
            Capability::MultiProtocol { afi, safi, .. } => {
                value_bytes.extend_from_slice(&afi.to_be_bytes());
                value_bytes.push(0); // reserved
                value_bytes.push(*safi);
            }
            Capability::RouteRefresh { .. } => {}
            Capability::GracefulRestart { flags, families, .. } => {
                value_bytes.extend_from_slice(&flags.to_be_bytes());
                value_bytes.extend_from_slice(families);
            }
            Capability::FourOctetAsn { asn, .. } => {
                value_bytes.extend_from_slice(&asn.to_be_bytes());
            }
            Capability::Raw { value, .. } => {
                value_bytes.extend_from_slice(value);
            }
        }

        let declared_len = self.declared_len() as usize;
        buf.push(self.type_code());
        buf.push(self.declared_len());
        let write_len = declared_len.min(value_bytes.len());
        buf.extend_from_slice(&value_bytes[..write_len]);
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 2 {
            return Err(DecodeError::Incomplete { min_required: 2, actual: buf.len() });
        }
        let type_code = buf[0];
        let declared_len = buf[1] as usize;
        let value_start = 2;
        let value_end = (value_start + declared_len).min(buf.len());
        let value = &buf[value_start..value_end];
        let consumed = 2 + declared_len;

        match type_code {
            1 => {
                let afi = if value.len() >= 2 {
                    u16::from_be_bytes([value[0], value[1]])
                } else {
                    0
                };
                let safi = if value.len() >= 4 { value[3] } else { 0 };
                Ok((Capability::MultiProtocol { declared_len: declared_len as u8, afi, safi }, consumed))
            }
            2 => {
                Ok((Capability::RouteRefresh { declared_len: declared_len as u8 }, consumed))
            }
            64 => {
                let flags = if value.len() >= 2 {
                    u16::from_be_bytes([value[0], value[1]])
                } else {
                    0
                };
                let families = if value.len() > 2 {
                    value[2..].to_vec()
                } else {
                    vec![]
                };
                Ok((Capability::GracefulRestart { declared_len: declared_len as u8, flags, families }, consumed))
            }
            65 => {
                let asn = if value.len() >= 4 {
                    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
                } else {
                    0
                };
                Ok((Capability::FourOctetAsn { declared_len: declared_len as u8, asn }, consumed))
            }
            _ => {
                Ok((Capability::Raw { type_code, declared_len: declared_len as u8, value: value.to_vec() }, consumed))
            }
        }
    }
}

/// Helper for constructing a Capabilities Optional Parameter from a list of capabilities.
///
/// Encodes as OPEN Optional Parameter type=2 per RFC 5492 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesOptParam {
    pub capabilities: Vec<Capability>,
}

impl CapabilitiesOptParam {
    /// Convert to an OpenMessage OptionalParameter.
    pub fn to_optional_parameter(&self) -> OptionalParameter {
        let mut cap_bytes = vec![];
        for cap in &self.capabilities {
            cap.encode(&mut cap_bytes);
        }
        OptionalParameter {
            param_type: Capability::OPT_PARAM_TYPE,
            param_length: cap_bytes.len() as u8,
            param_value: cap_bytes,
        }
    }

    /// Parse from an OptionalParameter (best-effort, even if param_type != 2).
    pub fn from_optional_parameter(param: &OptionalParameter) -> Self {
        let mut capabilities = Vec::new();
        let mut pos = 0;
        while pos + 2 <= param.param_value.len() {
            match Capability::decode(&param.param_value[pos..]) {
                Ok((cap, n)) => {
                    capabilities.push(cap);
                    pos += n.min(param.param_value.len() - pos);
                }
                Err(_) => break,
            }
        }
        CapabilitiesOptParam { capabilities }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- MultiProtocol ---

    #[test]
    fn mp_capability_roundtrip() {
        let cap = Capability::MultiProtocol { declared_len: 4, afi: 1, safi: 1 };
        let mut buf = vec![];
        cap.encode(&mut buf);
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    #[test]
    fn mp_capability_declared_len_mismatch() {
        // declared_len=2 truncates value to afi only (SAFI is cut off)
        let cap = Capability::MultiProtocol { declared_len: 2, afi: 1, safi: 1 };
        let mut buf = vec![];
        cap.encode(&mut buf);
        assert_eq!(buf[0], 1); // type
        assert_eq!(buf[1], 2); // declared_len
        assert_eq!(buf.len(), 4); // type(1) + len(1) + 2 value bytes (truncated)
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, Capability::MultiProtocol { declared_len: 2, afi: 1, safi: 0 });
    }

    // --- RouteRefresh ---

    #[test]
    fn rr_capability_roundtrip() {
        let cap = Capability::RouteRefresh { declared_len: 0 };
        let mut buf = vec![];
        cap.encode(&mut buf);
        assert_eq!(buf, vec![2, 0]); // type=2, len=0
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    #[test]
    fn rr_capability_nonzero_declared_len() {
        let cap = Capability::RouteRefresh { declared_len: 3 };
        let mut buf = vec![];
        cap.encode(&mut buf);
        assert_eq!(buf[1], 3);
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    // --- FourOctetAsn ---

    #[test]
    fn four_octet_asn_roundtrip() {
        let cap = Capability::FourOctetAsn { declared_len: 4, asn: 65536 };
        let mut buf = vec![];
        cap.encode(&mut buf);
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    #[test]
    fn four_octet_asn_truncated_decode() {
        // Buffer has type=65, len=4 but only 2 value bytes available.
        // decode defaults to 0 for fields when value is too short.
        let buf = vec![65, 4, 0x00, 0x01];
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, Capability::FourOctetAsn { declared_len: 4, asn: 0 });
    }

    // --- GracefulRestart ---

    #[test]
    fn graceful_restart_roundtrip() {
        let cap = Capability::GracefulRestart {
            declared_len: 6,
            flags: 0x8000,
            families: vec![0x00, 0x01, 0x01, 0x80], // AFI=1, SAFI=1, flags=0x80
        };
        let mut buf = vec![];
        cap.encode(&mut buf);
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    #[test]
    fn graceful_restart_empty_families() {
        let cap = Capability::GracefulRestart {
            declared_len: 2,
            flags: 0x1234,
            families: vec![],
        };
        let mut buf = vec![];
        cap.encode(&mut buf);
        assert_eq!(buf.len(), 4); // type(1) + len(1) + flags(2)
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    #[test]
    fn graceful_restart_truncated_decode() {
        // Buffer has type=64, len=6 but only 3 value bytes
        let buf = vec![64, 6, 0x80, 0x00, 0x01];
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, Capability::GracefulRestart {
            declared_len: 6,
            flags: 0x8000,
            families: vec![0x01],
        });
    }

    // --- Raw ---

    #[test]
    fn raw_capability_roundtrip() {
        let cap = Capability::Raw { type_code: 128, declared_len: 5, value: vec![1, 2, 3, 4, 5] };
        let mut buf = vec![];
        cap.encode(&mut buf);
        let (decoded, _) = Capability::decode(&buf).unwrap();
        assert_eq!(decoded, cap);
    }

    // --- CapabilitiesOptParam ---

    #[test]
    fn capabilities_opt_param_roundtrip() {
        let caps = CapabilitiesOptParam {
            capabilities: vec![
                Capability::MultiProtocol { declared_len: 4, afi: 1, safi: 1 },
                Capability::RouteRefresh { declared_len: 0 },
                Capability::FourOctetAsn { declared_len: 4, asn: 65536 },
            ],
        };
        let param = caps.to_optional_parameter();
        assert_eq!(param.param_type, 2);

        let decoded = CapabilitiesOptParam::from_optional_parameter(&param);
        assert_eq!(decoded.capabilities.len(), 3);
        assert_eq!(decoded.capabilities[0], caps.capabilities[0]);
        assert_eq!(decoded.capabilities[1], caps.capabilities[1]);
        assert_eq!(decoded.capabilities[2], caps.capabilities[2]);
    }

    #[test]
    fn capabilities_opt_param_empty_list() {
        let caps = CapabilitiesOptParam { capabilities: vec![] };
        let param = caps.to_optional_parameter();
        assert_eq!(param.param_type, 2);
        assert_eq!(param.param_length, 0);
        assert!(param.param_value.is_empty());

        let decoded = CapabilitiesOptParam::from_optional_parameter(&param);
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn capabilities_opt_param_mismatched_lens_sequence() {
        // Test that a sequence of capabilities with declared_len mismatches
        // round-trips correctly through CapabilitiesOptParam.
        // The declared_len=2 on MultiProtocol should truncate value bytes,
        // but decode should still find the RouteRefresh at the correct offset.
        let caps = CapabilitiesOptParam {
            capabilities: vec![
                Capability::MultiProtocol { declared_len: 2, afi: 1, safi: 1 },
                Capability::RouteRefresh { declared_len: 0 },
            ],
        };
        let param = caps.to_optional_parameter();
        let decoded = CapabilitiesOptParam::from_optional_parameter(&param);

        // Both capabilities should be recovered, though MP safi is truncated to 0
        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.capabilities[0], Capability::MultiProtocol { declared_len: 2, afi: 1, safi: 0 });
        assert_eq!(decoded.capabilities[1], Capability::RouteRefresh { declared_len: 0 });
    }

    // --- OpenMessage helpers ---

    #[test]
    fn open_message_capabilities_accessor() {
        use crate::OpenMessage;

        let mut open = OpenMessage {
            version: 4, my_as: 1, hold_time: 180, bgp_id: [0; 4],
            optional_parameters: vec![],
        };
        assert!(open.capabilities().is_empty());

        open.set_capabilities(vec![
            Capability::RouteRefresh { declared_len: 0 },
            Capability::FourOctetAsn { declared_len: 4, asn: 100 },
        ]);
        let caps = open.capabilities();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], Capability::RouteRefresh { declared_len: 0 });

        // Replace capabilities
        open.set_capabilities(vec![Capability::MultiProtocol { declared_len: 4, afi: 1, safi: 1 }]);
        let caps = open.capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0], Capability::MultiProtocol { declared_len: 4, afi: 1, safi: 1 });
    }

    // --- RFC 5492 test vector: OPEN with MPBGP (IPv6 unicast) + Four-Octet ASN ---

    #[test]
    fn rfc5492_open_with_capabilities() {
        use crate::{OpenMessage, WireEncode};

        // Build capabilities
        let caps = CapabilitiesOptParam {
            capabilities: vec![
                Capability::MultiProtocol { declared_len: 4, afi: 2, safi: 1 }, // IPv6 unicast
                Capability::FourOctetAsn { declared_len: 4, asn: 65536 },
            ],
        };
        let opt_param = caps.to_optional_parameter();

        let open = OpenMessage {
            version: 4,
            my_as: 23456, // AS_TRANS
            hold_time: 180,
            bgp_id: [192, 168, 1, 1],
            optional_parameters: vec![opt_param],
        };

        let mut buf = vec![];
        open.encode(&mut buf);

        // Byte-level verification
        // Header: marker(16) + length(2) + type(1) = 19 bytes
        assert_eq!(&buf[0..16], &[0xFFu8; 16]);
        assert_eq!(buf[18], 1); // OPEN type

        // Body: version(1) + my_as(2) + hold_time(2) + bgp_id(4) + opt_parm_len(1)
        let body_start = 19;
        assert_eq!(buf[body_start], 4); // version
        assert_eq!(buf[body_start + 1], 0x5B); // AS_TRANS hi
        assert_eq!(buf[body_start + 2], 0xA0); // AS_TRANS lo
        assert_eq!(u16::from_be_bytes([buf[body_start + 3], buf[body_start + 4]]), 180); // hold_time
        assert_eq!(&buf[body_start + 5..body_start + 9], &[192, 168, 1, 1]); // bgp_id

        // Optional parameters: type(1)=2 + len(1) + value
        let opt_start = body_start + 10;
        assert_eq!(buf[opt_start], 2); // type = Capabilities
        let cap_len = buf[opt_start + 1] as usize;

        // Decode capabilities from the optional parameter
        let cap_value = &buf[opt_start + 2..opt_start + 2 + cap_len];
        let (decoded_cap1, _) = Capability::decode(cap_value).unwrap();
        assert_eq!(decoded_cap1, Capability::MultiProtocol { declared_len: 4, afi: 2, safi: 1 });

        let cap2_start = 2 + 4; // type(1) + len(1) + mp_value(4)
        let (decoded_cap2, _) = Capability::decode(&cap_value[cap2_start..]).unwrap();
        assert_eq!(decoded_cap2, Capability::FourOctetAsn { declared_len: 4, asn: 65536 });

        // Total OPEN length
        let open_len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
        assert_eq!(buf.len(), open_len);
    }
}
