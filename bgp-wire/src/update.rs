use crate::attributes::{PathAttribute, ATTR_EXTENDED_LENGTH, decode_attribute};
use crate::{DecodeError, MessageHeader, NlriPrefix, WireDecode, WireEncode};

/// UPDATE Message (RFC 4271 §4.3)
///
/// Used to advertise feasible routes, withdraw unfeasible routes, or both.
/// Path attributes are stored as trait objects for maximum flexibility.
#[derive(Debug)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<NlriPrefix>,
    pub path_attributes: Vec<Box<dyn PathAttribute>>,
    pub nlri: Vec<NlriPrefix>,
}

impl UpdateMessage {
    pub fn builder() -> UpdateBuilder {
        UpdateBuilder::default()
    }
}

#[derive(Default)]
pub struct UpdateBuilder {
    withdrawn: Vec<NlriPrefix>,
    attributes: Vec<Box<dyn PathAttribute>>,
    nlri: Vec<NlriPrefix>,
}

impl UpdateBuilder {
    pub fn withdraw(mut self, prefix: NlriPrefix) -> Self { self.withdrawn.push(prefix); self }
    pub fn add_attribute(mut self, attr: impl PathAttribute + 'static) -> Self { self.attributes.push(Box::new(attr)); self }
    pub fn add_nlri(mut self, prefix: NlriPrefix) -> Self { self.nlri.push(prefix); self }

    pub fn build(self) -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: self.withdrawn,
            path_attributes: self.attributes,
            nlri: self.nlri,
        }
    }
}

impl WireEncode for UpdateMessage {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut withdrawn_bytes = vec![];
        for w in &self.withdrawn_routes {
            w.encode(&mut withdrawn_bytes);
        }

        let mut attr_bytes = vec![];
        for attr in &self.path_attributes {
            let flags = attr.attr_flags();
            let type_code = attr.attr_type_code();
            let mut val = vec![];
            attr.encode_value(&mut val);

            attr_bytes.push(flags);
            attr_bytes.push(type_code);
            // Use extended length (2 octets) if value > 255
            if val.len() > 255 || (flags & ATTR_EXTENDED_LENGTH != 0) {
                attr_bytes.extend_from_slice(&(val.len() as u16).to_be_bytes());
            } else {
                attr_bytes.push(val.len() as u8);
            }
            attr_bytes.extend_from_slice(&val);
        }

        let mut nlri_bytes = vec![];
        for n in &self.nlri {
            n.encode(&mut nlri_bytes);
        }

        let total_len = MessageHeader::LEN + 2 + withdrawn_bytes.len()
            + 2 + attr_bytes.len()
            + nlri_bytes.len();

        let header = MessageHeader {
            marker: [MessageHeader::MARKER; MessageHeader::MARKER_LEN],
            length: total_len as u16,
            type_code: MessageHeader::TYPE_UPDATE,
        };

        header.encode(buf);
        buf.extend_from_slice(&(withdrawn_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&withdrawn_bytes);
        buf.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&attr_bytes);
        buf.extend_from_slice(&nlri_bytes);
    }
}

impl WireDecode for UpdateMessage {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (header, _) = MessageHeader::decode(buf)?;
        if buf.len() < 23 {
            return Err(DecodeError::Incomplete { min_required: 23, actual: buf.len() });
        }

        let mut pos = MessageHeader::LEN;
        let withdrawn_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        let withdrawn_end = (pos + withdrawn_len).min(buf.len());
        let mut withdrawn_routes = Vec::new();
        let mut wpos = pos;
        while wpos < withdrawn_end {
            if let Ok((nlri, consumed)) = NlriPrefix::decode(&buf[wpos..withdrawn_end]) {
                wpos += consumed;
                withdrawn_routes.push(nlri);
            } else {
                break;
            }
        }
        pos = withdrawn_end;

        if pos + 2 > buf.len() {
            return Err(DecodeError::Incomplete { min_required: pos + 2, actual: buf.len() });
        }
        let attr_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        let attr_end = (pos + attr_len).min(buf.len());
        let mut path_attributes: Vec<Box<dyn PathAttribute>> = Vec::new();
        let mut apos = pos;
        while apos + 3 <= attr_end {
            let flags = buf[apos];
            let type_code = buf[apos + 1];
            apos += 2;
            let val_len = if flags & ATTR_EXTENDED_LENGTH != 0 {
                if apos + 2 > attr_end { break; }
                let len = u16::from_be_bytes([buf[apos], buf[apos + 1]]) as usize;
                apos += 2;
                len
            } else {
                let len = buf[apos] as usize;
                apos += 1;
                len
            };
            let val_end = (apos + val_len).min(attr_end);
            let val_buf = &buf[apos..val_end];

            let attr = decode_attribute(type_code, flags, val_buf)?;
            path_attributes.push(attr);
            apos = val_end;
        }
        pos = attr_end;

        let mut nlri = Vec::new();
        while pos < buf.len() {
            if let Ok((n, consumed)) = NlriPrefix::decode(&buf[pos..]) {
                pos += consumed;
                nlri.push(n);
            } else {
                // If we can't decode NLRI, just consume remaining bytes as-is
                break;
            }
        }

        let consumed = header.length as usize;
        Ok((UpdateMessage { withdrawn_routes, path_attributes, nlri }, consumed.min(buf.len())))
    }
}

// Workaround for PartialEq on dyn PathAttribute
impl PartialEq for UpdateMessage {
    fn eq(&self, other: &Self) -> bool {
        if self.withdrawn_routes != other.withdrawn_routes { return false; }
        if self.nlri != other.nlri { return false; }
        if self.path_attributes.len() != other.path_attributes.len() { return false; }
        for (a, b) in self.path_attributes.iter().zip(other.path_attributes.iter()) {
            if a.attr_type_code() != b.attr_type_code() { return false; }
            let mut va = vec![];
            let mut vb = vec![];
            a.encode_value(&mut va);
            b.encode_value(&mut vb);
            if va != vb { return false; }
        }
        true
    }
}

impl Clone for UpdateMessage {
    fn clone(&self) -> Self {
        // Re-encode and decode to clone trait objects
        let mut buf = vec![];
        self.encode(&mut buf);
        UpdateMessage::decode(&buf).unwrap().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::origin::Origin;
    use crate::attributes::as_path::{AsPath, AsPathSegment};
    use crate::attributes::next_hop::NextHop;

    /// Per RFC 4271 §4.3: UPDATE withdrawing a single route
    #[test]
    fn rfc4271_update_withdrawn_only() {
        let update = UpdateMessage::builder()
            .withdraw(NlriPrefix { prefix_len: 24, prefix: vec![10, 0, 0] })
            .build();

        let mut buf = vec![];
        update.encode(&mut buf);

        assert_eq!(buf[18], 2); // type = UPDATE
        let withdrawn_len = u16::from_be_bytes([buf[19], buf[20]]);
        assert_eq!(withdrawn_len, 4);
        assert_eq!(buf[21], 24);
        assert_eq!(&buf[22..25], &[10, 0, 0]);
        let attr_len_pos = 19 + 2 + withdrawn_len as usize;
        let attr_len = u16::from_be_bytes([buf[attr_len_pos], buf[attr_len_pos + 1]]);
        assert_eq!(attr_len, 0);
    }

    #[test]
    fn rfc4271_update_attribute_nlri() {
        let update = UpdateMessage::builder()
            .add_attribute(Origin(0))
            .add_attribute(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] })
            .add_attribute(NextHop([10, 0, 0, 1]))
            .add_nlri(NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] })
            .build();

        let mut buf = vec![];
        update.encode(&mut buf);
        let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
        assert_eq!(decoded.withdrawn_routes.len(), 0);
        assert_eq!(decoded.path_attributes.len(), 3);
        assert_eq!(decoded.nlri.len(), 1);
    }

    #[test]
    fn rfc4271_update_full() {
        let update = UpdateMessage::builder()
            .withdraw(NlriPrefix { prefix_len: 24, prefix: vec![10, 0, 0] })
            .add_attribute(Origin(2))
            .add_attribute(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])] })
            .add_attribute(NextHop([10, 0, 0, 1]))
            .add_nlri(NlriPrefix { prefix_len: 24, prefix: vec![192, 168, 0] })
            .add_nlri(NlriPrefix { prefix_len: 32, prefix: vec![172, 16, 0, 1] })
            .build();

        let mut buf = vec![];
        update.encode(&mut buf);
        let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
        assert_eq!(decoded.withdrawn_routes.len(), 1);
        assert_eq!(decoded.path_attributes.len(), 3);
        assert_eq!(decoded.nlri.len(), 2);
    }

    #[test]
    fn update_empty_is_valid() {
        let update = UpdateMessage::builder().build();
        let mut buf = vec![];
        update.encode(&mut buf);
        let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
        assert!(decoded.withdrawn_routes.is_empty());
        assert!(decoded.path_attributes.is_empty());
        assert!(decoded.nlri.is_empty());
    }

    #[test]
    fn update_4096_byte_boundary() {
        let mut builder = UpdateMessage::builder()
            .add_attribute(Origin(0))
            .add_attribute(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] })
            .add_attribute(NextHop([10, 0, 0, 1]));

        for i in 0u8..40 {
            builder = builder.add_nlri(NlriPrefix { prefix_len: 32, prefix: vec![10, i, i, i] });
        }

        let update = builder.build();
        let mut buf = vec![];
        update.encode(&mut buf);
        assert!(buf.len() < 4096, "message is {} bytes", buf.len());

        let (decoded, _) = UpdateMessage::decode(&buf).unwrap();
        assert_eq!(decoded.nlri.len(), 40);
    }

    #[test]
    fn update_unknown_attribute_preserved() {
        let mut attr_bytes = vec![];
        attr_bytes.push(0x80);
        attr_bytes.push(99);
        attr_bytes.push(2);
        attr_bytes.extend_from_slice(&[0xAB, 0xCD]);

        let mut update_bytes = vec![];
        let total_len = 19 + 2 + 0 + 2 + attr_bytes.len() + 0;
        update_bytes.extend_from_slice(&[0xFF; 16]);
        update_bytes.extend_from_slice(&(total_len as u16).to_be_bytes());
        update_bytes.push(2);
        update_bytes.extend_from_slice(&[0x00, 0x00]);
        update_bytes.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        update_bytes.extend_from_slice(&attr_bytes);

        let result = UpdateMessage::decode(&update_bytes);
        assert!(result.is_ok(), "should not fail on unknown attr: {:?}", result.err());
    }
}
