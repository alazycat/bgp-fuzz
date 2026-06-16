use std::fmt::Debug;

use bgp_wire::BgpMessage;

/// A semantic mutation that operates on a decoded BgpMessage
pub trait BgpMutator: Debug + Send + Sync {
    fn name(&self) -> &str;
    fn apply(&self, msg: &mut BgpMessage);
}

// ─── Mutator implementations ───

/// Swap the order of two path attributes in an UPDATE message
#[derive(Debug)]
pub struct ReorderAttributes;

impl BgpMutator for ReorderAttributes {
    fn name(&self) -> &str { "ReorderAttributes" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            if update.path_attributes.len() >= 2 {
                update.path_attributes.swap(0, 1);
            }
        }
    }
}

/// Flip Optional (0x80) and Transitive (0x40) flags on a path attribute
#[derive(Debug)]
pub struct FlipAttrFlags {
    pub attr_index: usize,
}

impl BgpMutator for FlipAttrFlags {
    fn name(&self) -> &str { "FlipAttrFlags" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            if let Some(attr) = update.path_attributes.get_mut(self.attr_index) {
                let mut flags = attr.attr_flags();
                flags ^= 0xC0; // flip both Optional and Transitive
                // Re-encode the value with modified flags via encode/decode roundtrip
                let type_code = attr.attr_type_code();
                let mut val = vec![];
                attr.encode_value(&mut val);
                // Replace with raw attribute carrying flipped flags
                let raw = RawAttribute { type_code, flags, value: val };
                update.path_attributes[self.attr_index] = Box::new(raw);
            }
        }
    }
}

use bgp_wire::attributes::RawAttribute;

/// Corrupt NLRI prefix_len so it no longer matches the actual prefix byte count
#[derive(Debug)]
pub struct CorruptNlriPrefixLen {
    pub delta: i8,
}

impl BgpMutator for CorruptNlriPrefixLen {
    fn name(&self) -> &str { "CorruptNlriPrefixLen" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            for nlri in &mut update.nlri {
                let new_len = nlri.prefix_len as i16 + self.delta as i16;
                nlri.prefix_len = new_len.clamp(0, 255) as u8;
            }
        }
    }
}

/// Inject a target ASN into the AS_PATH to create a loop
#[derive(Debug)]
pub struct InjectAsLoop {
    pub asn: u32,
}

impl BgpMutator for InjectAsLoop {
    fn name(&self) -> &str { "InjectAsLoop" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            for attr in &mut update.path_attributes {
                if attr.attr_type_code() == 2 {
                    let type_code = attr.attr_type_code();
                    let flags = attr.attr_flags();
                    let mut val = vec![];
                    attr.encode_value(&mut val);
                    // Prepend the loop ASN at the start of the encoded value
                    let mut new_val = vec![2u8, 1u8]; // AS_SEQUENCE, length=1
                    new_val.extend_from_slice(&self.asn.to_be_bytes());
                    new_val.extend_from_slice(&val);
                    *attr = Box::new(RawAttribute { type_code, flags, value: new_val });
                    break;
                }
            }
        }
    }
}

/// Set NEXT_HOP to the target IP (self-referencing)
#[derive(Debug)]
pub struct SelfReferencingNextHop;

impl BgpMutator for SelfReferencingNextHop {
    fn name(&self) -> &str { "SelfReferencingNextHop" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            for attr in &mut update.path_attributes {
                if attr.attr_type_code() == 3 {
                    let flags = attr.attr_flags();
                    *attr = Box::new(RawAttribute {
                        type_code: 3,
                        flags,
                        value: vec![127, 0, 0, 1], // loopback
                    });
                    break;
                }
            }
        }
    }
}

/// Remove a mandatory attribute (ORIGIN=1, AS_PATH=2, NEXT_HOP=3)
#[derive(Debug)]
pub struct DropMandatory {
    pub attr_type_code: u8,
}

impl BgpMutator for DropMandatory {
    fn name(&self) -> &str { "DropMandatory" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            update.path_attributes.retain(|a| a.attr_type_code() != self.attr_type_code);
        }
    }
}

/// Duplicate an attribute at the given index
#[derive(Debug)]
pub struct DuplicateAttribute {
    pub attr_index: usize,
}

impl BgpMutator for DuplicateAttribute {
    fn name(&self) -> &str { "DuplicateAttribute" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Update(update) = msg {
            if let Some(attr) = update.path_attributes.get(self.attr_index) {
                let type_code = attr.attr_type_code();
                let flags = attr.attr_flags();
                let mut val = vec![];
                attr.encode_value(&mut val);
                let clone = Box::new(RawAttribute { type_code, flags, value: val });
                update.path_attributes.push(clone);
            }
        }
    }
}

/// Truncate a Capability optional parameter in an OPEN message
#[derive(Debug)]
pub struct TruncateCapParam {
    pub cap_code: u8,
}

impl BgpMutator for TruncateCapParam {
    fn name(&self) -> &str { "TruncateCapParam" }

    fn apply(&self, msg: &mut BgpMessage) {
        if let BgpMessage::Open(open) = msg {
            for param in &mut open.optional_parameters {
                if param.param_type == self.cap_code && !param.param_value.is_empty() {
                    let new_len = param.param_value.len() / 2;
                    param.param_value.truncate(new_len);
                    param.param_length = new_len as u8;
                    break;
                }
            }
        }
    }
}

/// Apply a list of mutators to a message in sequence
pub fn apply_mutators(msg: &mut BgpMessage, mutators: &[Box<dyn BgpMutator>]) {
    for m in mutators {
        m.apply(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_wire::WireEncode;

    fn make_update() -> BgpMessage {
        use bgp_wire::update::UpdateMessage;
        use bgp_wire::attributes::origin::Origin;
        use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};
        use bgp_wire::attributes::next_hop::NextHop;
        use bgp_wire::NlriPrefix;

        BgpMessage::Update(UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: vec![
                Box::new(Origin(0)),
                Box::new(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] }),
                Box::new(NextHop([10, 0, 0, 1])),
            ],
            nlri: vec![
                NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] },
                NlriPrefix { prefix_len: 32, prefix: vec![172, 16, 0, 1] },
            ],
        })
    }

    #[test]
    fn reorder_attributes_modifies_message() {
        let mut msg = make_update();
        let orig_bytes = {
            let mut b = vec![];
            msg.encode(&mut b);
            b
        };
        ReorderAttributes.apply(&mut msg);
        let mut new_bytes = vec![];
        msg.encode(&mut new_bytes);
        assert_ne!(orig_bytes, new_bytes, "message should change after reorder");
    }

    #[test]
    fn drop_mandatory_removes_attribute() {
        let mut msg = make_update();
        let attr_count_before = if let BgpMessage::Update(ref u) = msg {
            u.path_attributes.len()
        } else { 0 };
        DropMandatory { attr_type_code: 1 }.apply(&mut msg);
        let attr_count_after = if let BgpMessage::Update(ref u) = msg {
            assert!(!u.path_attributes.iter().any(|a| a.attr_type_code() == 1));
            u.path_attributes.len()
        } else { 0 };
        assert!(attr_count_after < attr_count_before);
    }

    #[test]
    fn duplicate_attribute_increases_count() {
        let mut msg = make_update();
        let count_before = if let BgpMessage::Update(ref u) = msg { u.path_attributes.len() } else { 0 };
        DuplicateAttribute { attr_index: 0 }.apply(&mut msg);
        let count_after = if let BgpMessage::Update(ref u) = msg { u.path_attributes.len() } else { 0 };
        assert_eq!(count_after, count_before + 1);
    }

    #[test]
    fn corrupt_nlri_modifies_prefix_len() {
        let mut msg = make_update();
        CorruptNlriPrefixLen { delta: 5 }.apply(&mut msg);
        if let BgpMessage::Update(ref u) = msg {
            assert_ne!(u.nlri[0].prefix_len, 24, "prefix_len should have changed");
        } else {
            panic!("expected UPDATE");
        }
    }

    #[test]
    fn inject_as_loop_encodes() {
        let mut msg = make_update();
        InjectAsLoop { asn: 65001 }.apply(&mut msg);
        let mut buf = vec![];
        msg.encode(&mut buf);
        assert!(buf.len() > 19);
    }

    #[test]
    fn mutators_no_panic_on_open() {
        let msg = BgpMessage::Keepalive(bgp_wire::keepalive::KeepaliveMessage);
        let mut msgs = vec![msg];
        let mutators: Vec<(&str, Box<dyn BgpMutator>)> = vec![
            ("ReorderAttributes", Box::new(ReorderAttributes)),
            ("DropMandatory", Box::new(DropMandatory { attr_type_code: 1 })),
            ("CorruptNlri", Box::new(CorruptNlriPrefixLen { delta: 1 })),
            ("InjectAsLoop", Box::new(InjectAsLoop { asn: 1 })),
            ("SelfRefNH", Box::new(SelfReferencingNextHop)),
            ("DuplicateAttr", Box::new(DuplicateAttribute { attr_index: 0 })),
        ];
        for (name, m) in &mutators {
            m.apply(&mut msgs[0]);
            let mut buf = vec![];
            msgs[0].encode(&mut buf);
            assert!(!buf.is_empty(), "{name}: should still encode");
        }
    }

    #[test]
    fn truncate_cap_param_shortens_value() {
        let mut msg = BgpMessage::Open(bgp_wire::open::OpenMessage {
            version: 4, my_as: 1, hold_time: 180, bgp_id: [0; 4],
            optional_parameters: vec![bgp_wire::open::OptionalParameter {
                param_type: 2, param_length: 4, param_value: vec![1, 2, 3, 4],
            }],
        });
        TruncateCapParam { cap_code: 2 }.apply(&mut msg);
        if let BgpMessage::Open(ref o) = msg {
            assert!(o.optional_parameters[0].param_value.len() < 4);
        }
    }
}
