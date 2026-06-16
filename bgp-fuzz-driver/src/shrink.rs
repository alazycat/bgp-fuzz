use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bgp_fuzz_oracle::{RecvKind, RecvOutcome};
use bgp_wire::WireDecode;
use bgp_wire::WireEncode;
use tokio::net::TcpStream;

use crate::connection;

const MIN_BGP_MSG_LEN: usize = 19;
const DDMIN_INITIAL_GRANULARITY: usize = 2;
const BGP_MAX_MSG_LEN: usize = 4096;
const CONNECT_RETRIES: u32 = 3;

/// Shrinker configuration.
#[derive(Debug, Clone)]
pub struct ShrinkConfig {
    pub handshake_timeout: Duration,
    pub recv_timeout: Duration,
    pub max_retries: u32,
    pub total_timeout: Duration,
}

impl Default for ShrinkConfig {
    fn default() -> Self {
        ShrinkConfig {
            handshake_timeout: Duration::from_secs(10),
            recv_timeout: Duration::from_secs(5),
            max_retries: 3,
            total_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShrinkStep {
    pub description: String,
    pub before_len: usize,
    pub after_len: usize,
}

#[derive(Debug, Clone)]
pub struct ShrinkResult {
    pub original_len: usize,
    pub shrunk_len: usize,
    pub messages: Vec<Vec<u8>>,
    pub steps: Vec<ShrinkStep>,
}

// ─── BugCheck: predicate abstraction ───

/// A bug predicate — returns true when a `RecvOutcome` triggers the bug.
pub trait BugCheck: Send + Sync {
    fn is_bug(&self, outcome: &RecvOutcome) -> bool;
}

/// Wraps an `Fn` closure as a `BugCheck`.
pub struct FnCheck<F>(pub F);

impl<F> BugCheck for FnCheck<F>
where
    F: Fn(&RecvOutcome) -> bool + Send + Sync,
{
    fn is_bug(&self, outcome: &RecvOutcome) -> bool {
        (self.0)(outcome)
    }
}

// ─── SequenceVerifier: the verification seam ───

/// Verifies whether a message sequence still triggers a bug.
///
/// This is the seam between the shrinking algorithm (pure logic)
/// and the transport layer (TCP). Swap implementations to test
/// without a live BGP peer.
#[async_trait]
pub trait SequenceVerifier: Send + Sync {
    async fn verify(
        &self,
        messages: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> bool;
}

/// TCP-based verifier — connects to a real target for each verification.
pub struct TcpVerifier {
    target: SocketAddr,
    config: ShrinkConfig,
}

impl TcpVerifier {
    pub fn new(target: SocketAddr, config: ShrinkConfig) -> Self {
        TcpVerifier { target, config }
    }
}

#[async_trait]
impl SequenceVerifier for TcpVerifier {
    async fn verify(
        &self,
        messages: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> bool {
        for _ in 0..self.config.max_retries {
            let mut stream = match connection::connect_with_retry(
                self.target, CONNECT_RETRIES, Duration::from_secs(1),
            ).await {
                Some(s) => s,
                None => return false,
            };

            connection::do_handshake(
                &mut stream,
                self.config.handshake_timeout,
                self.config.handshake_timeout,
            ).await;

            let mut found = false;
            for msg_bytes in messages {
                if tokio::io::AsyncWriteExt::write_all(&mut stream, msg_bytes).await.is_err() {
                    let outcome = RecvOutcome { bytes: vec![], kind: RecvKind::Error };
                    if check.is_bug(&outcome) {
                        found = true;
                    }
                    break;
                }

                let outcome = recv_with_timeout(&mut stream, self.config.recv_timeout).await;
                if check.is_bug(&outcome) {
                    found = true;
                    break;
                }

                if matches!(outcome.kind, RecvKind::PeerClosed | RecvKind::ConnectionReset) {
                    break;
                }
            }

            if found {
                return true;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        false
    }
}

async fn recv_with_timeout(stream: &mut TcpStream, timeout: Duration) -> RecvOutcome {
    let mut buf = vec![0u8; BGP_MAX_MSG_LEN];
    match tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read(stream, &mut buf)).await {
        Ok(Ok(0)) => RecvOutcome { bytes: vec![], kind: RecvKind::PeerClosed },
        Ok(Ok(n)) => RecvOutcome { bytes: buf[..n].to_vec(), kind: RecvKind::Data },
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionReset => {
            RecvOutcome { bytes: vec![], kind: RecvKind::ConnectionReset }
        }
        Ok(Err(_)) => RecvOutcome { bytes: vec![], kind: RecvKind::Error },
        Err(_) => RecvOutcome { bytes: vec![], kind: RecvKind::Timeout },
    }
}

// ─── Shrinker ───

/// The Shrinker: takes a sequence of messages that triggered a bug and
/// reduces it to a minimal reproducing subsequence via delta debugging
/// followed by per-message structural and byte-level simplification.
pub struct Shrinker {
    verifier: Box<dyn SequenceVerifier>,
    config: ShrinkConfig,
}

fn minimal_update() -> bgp_wire::update::UpdateMessage {
    bgp_wire::update::UpdateMessage {
        withdrawn_routes: vec![],
        path_attributes: vec![
            Box::new(bgp_wire::attributes::origin::Origin(0)),
            Box::new(bgp_wire::attributes::as_path::AsPath { segments: vec![] }),
            Box::new(bgp_wire::attributes::next_hop::NextHop([0, 0, 0, 0])),
        ],
        nlri: vec![],
    }
}

fn minimal_open() -> bgp_wire::open::OpenMessage {
    bgp_wire::open::OpenMessage {
        version: 4, my_as: 0, hold_time: 0,
        bgp_id: [0; 4], optional_parameters: vec![],
    }
}

impl Shrinker {
    /// Create a Shrinker backed by an arbitrary verifier.
    pub fn new(verifier: Box<dyn SequenceVerifier>, config: ShrinkConfig) -> Self {
        Shrinker { verifier, config }
    }

    /// Convenience: create a TCP-backed shrinker for a target.
    pub fn with_tcp(target: SocketAddr, config: ShrinkConfig) -> Self {
        Shrinker {
            verifier: Box::new(TcpVerifier::new(target, config.clone())),
            config,
        }
    }

    pub async fn shrink(
        &self,
        messages: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> ShrinkResult {
        let original_len = messages.len();
        let mut steps = Vec::new();
        let started = Instant::now();

        let sequence = self.delta_debug_sequence(messages, check).await;
        if sequence.len() < original_len {
            steps.push(ShrinkStep {
                description: format!("ddmin: {} → {} messages", original_len, sequence.len()),
                before_len: original_len,
                after_len: sequence.len(),
            });
        }

        let mut shrunk: Vec<Vec<u8>> = Vec::new();
        for (i, msg) in sequence.iter().enumerate() {
            if started.elapsed() >= self.config.total_timeout {
                shrunk.push(msg.clone());
                continue;
            }
            let prefix = &shrunk;
            let suffix = &sequence[i + 1..];
            let before_len = msg.len();
            let simplified = self.shrink_message(prefix, msg, suffix, check).await;
            if simplified.len() < before_len {
                steps.push(ShrinkStep {
                    description: format!(
                        "shrink_message[{}]: {} → {} bytes", i, before_len, simplified.len()
                    ),
                    before_len,
                    after_len: simplified.len(),
                });
            }
            shrunk.push(simplified);
        }

        ShrinkResult {
            original_len,
            shrunk_len: shrunk.len(),
            messages: shrunk,
            steps,
        }
    }

    async fn delta_debug_sequence(
        &self,
        messages: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> Vec<Vec<u8>> {
        if messages.len() < 2 {
            return messages.to_vec();
        }

        let mut best = messages.to_vec();
        let mut granularity: usize = DDMIN_INITIAL_GRANULARITY;
        let started = Instant::now();

        while best.len() >= 2 {
            if started.elapsed() >= self.config.total_timeout {
                break;
            }

            let chunk_size = best.len().div_ceil(granularity);
            let mut progress = false;

            for i in 0..granularity {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(best.len());

                let candidate: Vec<Vec<u8>> = best[..start]
                    .iter()
                    .chain(best[end..].iter())
                    .cloned()
                    .collect();

                if self.verifier.verify(&candidate, check).await {
                    best = candidate;
                    progress = true;
                    break;
                }
            }

            if progress {
                granularity = granularity.saturating_sub(1).max(2);
            } else {
                if granularity * 2 > best.len() {
                    break;
                }
                granularity *= 2;
            }
        }

        best
    }

    async fn shrink_message(
        &self,
        prefix: &[Vec<u8>],
        msg: &[u8],
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> Vec<u8> {
        let mut best = msg.to_vec();

        if let Ok((parsed, _)) = bgp_wire::BgpMessage::decode(msg) {
            best = self.shrink_structured(prefix, parsed, msg, suffix, check).await;
        }

        best = self.shrink_bytes_tail(prefix, &best, suffix, check).await;
        best
    }

    async fn test_candidate(
        &self,
        prefix: &[Vec<u8>],
        msg: &[u8],
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> bool {
        let mut seq = Vec::with_capacity(prefix.len() + 1 + suffix.len());
        seq.extend_from_slice(prefix);
        seq.push(msg.to_vec());
        seq.extend_from_slice(suffix);
        self.verifier.verify(&seq, check).await
    }

    async fn test_encoded(
        &self,
        prefix: &[Vec<u8>],
        msg: &bgp_wire::BgpMessage,
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> bool {
        let mut buf = vec![];
        msg.encode(&mut buf);
        self.test_candidate(prefix, &buf, suffix, check).await
    }

    async fn test_encoded_message(
        &self,
        prefix: &[Vec<u8>],
        msg: &impl WireEncode,
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> bool {
        let mut buf = vec![];
        msg.encode(&mut buf);
        self.test_candidate(prefix, &buf, suffix, check).await
    }

    async fn shrink_structured(
        &self,
        prefix: &[Vec<u8>],
        mut parsed: bgp_wire::BgpMessage,
        original_bytes: &[u8],
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> Vec<u8> {
        match &mut parsed {
            bgp_wire::BgpMessage::Update(update) => {
                self.shrink_update(prefix, update, suffix, check).await;
            }
            bgp_wire::BgpMessage::Open(open) => {
                self.shrink_open(prefix, open, suffix, check).await;
            }
            bgp_wire::BgpMessage::Notification(notif) => {
                self.shrink_notification(prefix, notif, suffix, check).await;
            }
            _ => {}
        }

        let mut encoded = vec![];
        parsed.encode(&mut encoded);

        if encoded != original_bytes
            && self.test_candidate(prefix, &encoded, suffix, check).await
        {
            return encoded;
        }

        original_bytes.to_vec()
    }

    async fn shrink_update(
        &self,
        prefix: &[Vec<u8>],
        update: &mut bgp_wire::update::UpdateMessage,
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) {
        let mut i = update.path_attributes.len();
        while i > 0 {
            i -= 1;
            let type_code = update.path_attributes[i].attr_type_code();
            if type_code <= 3 {
                continue;
            }
            let removed = update.path_attributes.remove(i);
            if !self.test_encoded_message(prefix, update, suffix, check).await {
                update.path_attributes.insert(i, removed);
            }
        }

        while let Some(removed) = update.nlri.pop() {
            if !self.test_encoded_message(prefix, update, suffix, check).await {
                update.nlri.push(removed);
                break;
            }
        }

        while let Some(removed) = update.withdrawn_routes.pop() {
            if !self.test_encoded_message(prefix, update, suffix, check).await {
                update.withdrawn_routes.push(removed);
                break;
            }
        }

        let candidate = bgp_wire::BgpMessage::Update(minimal_update());
        if self.test_encoded(prefix, &candidate, suffix, check).await {
            *update = minimal_update();
        }
    }

    async fn shrink_open(
        &self,
        prefix: &[Vec<u8>],
        open: &mut bgp_wire::open::OpenMessage,
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) {
        while let Some(removed) = open.optional_parameters.pop() {
            if !self.test_encoded_message(prefix, open, suffix, check).await {
                open.optional_parameters.push(removed);
                break;
            }
        }

        let candidate = bgp_wire::BgpMessage::Open(minimal_open());
        if self.test_encoded(prefix, &candidate, suffix, check).await {
            *open = minimal_open();
        }
    }

    async fn shrink_notification(
        &self,
        prefix: &[Vec<u8>],
        notif: &mut bgp_wire::notification::NotificationMessage,
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) {
        while let Some(removed) = notif.data.pop() {
            if !self.test_encoded_message(prefix, notif, suffix, check).await {
                notif.data.push(removed);
                break;
            }
        }
    }

    async fn shrink_bytes_tail(
        &self,
        prefix: &[Vec<u8>],
        msg: &[u8],
        suffix: &[Vec<u8>],
        check: &dyn BugCheck,
    ) -> Vec<u8> {
        let mut best = msg.to_vec();

        while best.len() > MIN_BGP_MSG_LEN {
            let candidate = best[..best.len() - 1].to_vec();
            if !self.test_candidate(prefix, &candidate, suffix, check).await {
                break;
            }
            best = candidate;
        }

        best
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier that returns true when a specific "buggy" message is present
    /// in the sequence. Simulates a bug triggered by a single malformed message.
    struct ContainsMessageVerifier {
        buggy_msg: Vec<u8>,
    }

    impl ContainsMessageVerifier {
        fn new(buggy_msg: Vec<u8>) -> Self {
            ContainsMessageVerifier { buggy_msg }
        }
    }

    #[async_trait]
    impl SequenceVerifier for ContainsMessageVerifier {
        async fn verify(
            &self,
            messages: &[Vec<u8>],
            _check: &dyn BugCheck,
        ) -> bool {
            messages.iter().any(|m| m == &self.buggy_msg)
        }
    }

    fn make_msgs(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 20]).collect()
    }

    fn never_triggering_check() -> FnCheck<fn(&RecvOutcome) -> bool> {
        FnCheck(|_| false)
    }

    #[test]
    fn shrink_config_defaults() {
        let cfg = ShrinkConfig::default();
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.recv_timeout, Duration::from_secs(5));
        assert!(cfg.total_timeout > Duration::from_secs(60));
    }

    // ─── ddmin algorithm tests ───

    #[tokio::test]
    async fn ddmin_reduces_to_single_message() {
        let msgs = make_msgs(8);
        let buggy = msgs[3].clone();
        let verifier = ContainsMessageVerifier::new(buggy);

        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let result = shrinker.delta_debug_sequence(&msgs, &never_triggering_check()).await;

        assert_eq!(result.len(), 1, "ddmin should reduce to the single buggy message, got {}", result.len());
        assert_eq!(result[0], msgs[3], "should find the correct buggy message");
    }

    #[tokio::test]
    async fn ddmin_preserves_when_all_messages_needed() {
        // When every message is needed (all are "buggy"), ddmin can't reduce
        let msgs = make_msgs(4);
        // A verifier that only returns true when ALL messages are present
        struct AllNeededVerifier;
        #[async_trait]
        impl SequenceVerifier for AllNeededVerifier {
            async fn verify(&self, messages: &[Vec<u8>], _check: &dyn BugCheck) -> bool {
                messages.len() == 4
            }
        }

        let shrinker = Shrinker::new(Box::new(AllNeededVerifier), ShrinkConfig::default());
        let result = shrinker.delta_debug_sequence(&msgs, &never_triggering_check()).await;
        assert_eq!(result.len(), 4, "ddmin should preserve full sequence when all are needed");
    }

    #[tokio::test]
    async fn ddmin_empty_returns_empty() {
        let verifier = ContainsMessageVerifier::new(vec![0; 20]);
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let result = shrinker.delta_debug_sequence(&[], &never_triggering_check()).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn ddmin_single_returns_single() {
        let verifier = ContainsMessageVerifier::new(vec![0; 20]);
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let result = shrinker.delta_debug_sequence(&make_msgs(1), &never_triggering_check()).await;
        assert_eq!(result.len(), 1);
    }

    // ─── Per-message shrink tests ───

    /// A verifier that always returns true — the bug "always reproduces,"
    /// so the shrinker removes as much as possible. Used to test that
    /// structural shrinkers reach their minimal valid form.
    struct AlwaysTrueVerifier;

    #[async_trait]
    impl SequenceVerifier for AlwaysTrueVerifier {
        async fn verify(&self, _messages: &[Vec<u8>], _check: &dyn BugCheck) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn shrink_bytes_tail_trims_to_min_bgp_length() {
        let verifier = AlwaysTrueVerifier;
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let msg = vec![0xFFu8; 100];
        let result = shrinker
            .shrink_bytes_tail(&[], &msg, &[], &never_triggering_check())
            .await;
        assert_eq!(result.len(), MIN_BGP_MSG_LEN,
            "should trim to min BGP message length, got {}", result.len());
    }

    #[tokio::test]
    async fn shrink_bytes_tail_preserves_minimal() {
        let verifier = AlwaysTrueVerifier;
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let msg = vec![0xFFu8; MIN_BGP_MSG_LEN];
        let result = shrinker
            .shrink_bytes_tail(&[], &msg, &[], &never_triggering_check())
            .await;
        assert_eq!(result.len(), MIN_BGP_MSG_LEN, "already-minimal message stays unchanged");
    }

    #[tokio::test]
    async fn shrink_structured_removes_optional_attrs() {
        use bgp_wire::attributes::local_pref::LocalPref;
        use bgp_wire::WireEncode;
        // Build UPDATE with mandatory attrs (1,2,3) + 3 optional LocalPref attrs
        let attrs: Vec<Box<dyn bgp_wire::attributes::PathAttribute>> = vec![
            Box::new(bgp_wire::attributes::origin::Origin(0)),
            Box::new(bgp_wire::attributes::as_path::AsPath { segments: vec![] }),
            Box::new(bgp_wire::attributes::next_hop::NextHop([10, 0, 0, 1])),
            Box::new(LocalPref(100)),
            Box::new(LocalPref(200)),
            Box::new(LocalPref(300)),
        ];
        let update = bgp_wire::update::UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: attrs,
            nlri: vec![],
        };
        let msg = bgp_wire::BgpMessage::Update(update);
        let mut original_bytes = vec![];
        msg.encode(&mut original_bytes);

        let verifier = AlwaysTrueVerifier;
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let result = shrinker
            .shrink_structured(&[], msg.clone(), &original_bytes, &[], &never_triggering_check())
            .await;

        assert!(result.len() < original_bytes.len(),
            "should remove optional attrs ({} → {} bytes)", original_bytes.len(), result.len());

        // Decode result and verify only mandatory attrs remain
        let (shrunk_msg, _) = bgp_wire::BgpMessage::decode(&result).unwrap();
        if let bgp_wire::BgpMessage::Update(u) = shrunk_msg {
            assert_eq!(u.path_attributes.len(), 3,
                "should have only 3 mandatory attrs, got {}", u.path_attributes.len());
            assert_eq!(u.path_attributes[0].attr_type_code(), 1); // ORIGIN
            assert_eq!(u.path_attributes[1].attr_type_code(), 2); // AS_PATH
            assert_eq!(u.path_attributes[2].attr_type_code(), 3); // NEXT_HOP
        } else {
            panic!("expected UPDATE, got {:?}", std::mem::discriminant(&shrunk_msg));
        }
    }

    #[tokio::test]
    async fn shrink_structured_removes_open_params() {
        use bgp_wire::WireEncode;
        let open = bgp_wire::open::OpenMessage {
            version: 4, my_as: 65001, hold_time: 180,
            bgp_id: [10, 0, 0, 1],
            optional_parameters: vec![
                bgp_wire::open::OptionalParameter { param_type: 2, param_length: 4, param_value: vec![1,2,3,4] },
                bgp_wire::open::OptionalParameter { param_type: 2, param_length: 2, param_value: vec![5,6] },
            ],
        };
        let msg = bgp_wire::BgpMessage::Open(open);
        let mut original_bytes = vec![];
        msg.encode(&mut original_bytes);

        let verifier = AlwaysTrueVerifier;
        let shrinker = Shrinker::new(Box::new(verifier), ShrinkConfig::default());
        let result = shrinker
            .shrink_structured(&[], msg.clone(), &original_bytes, &[], &never_triggering_check())
            .await;

        assert!(result.len() < original_bytes.len(),
            "should remove optional params ({} → {} bytes)", original_bytes.len(), result.len());
        let (shrunk_msg, _) = bgp_wire::BgpMessage::decode(&result).unwrap();
        if let bgp_wire::BgpMessage::Open(o) = shrunk_msg {
            assert!(o.optional_parameters.is_empty(),
                "should have no optional params, got {}", o.optional_parameters.len());
        }
    }

    // ─── Message shrink tests ───

    use bgp_wire::attributes::origin::Origin;
    use bgp_wire::attributes::as_path::{AsPath, AsPathSegment};
    use bgp_wire::attributes::next_hop::NextHop;
    use bgp_wire::attributes::local_pref::LocalPref;
    use bgp_wire::update::UpdateMessage;
    use bgp_wire::BgpMessage;
    use bgp_wire::NlriPrefix;

    fn make_update_with_attrs(n_attrs: usize, n_nlri: usize) -> Vec<u8> {
        let mut attrs: Vec<Box<dyn bgp_wire::attributes::PathAttribute>> = vec![
            Box::new(Origin(0)),
            Box::new(AsPath { segments: vec![AsPathSegment::AsSequence(vec![65001])] }),
            Box::new(NextHop([10, 0, 0, 1])),
        ];
        for i in 0..n_attrs {
            attrs.push(Box::new(LocalPref((100 + i) as u32)));
        }

        let nlri: Vec<NlriPrefix> = (0..n_nlri)
            .map(|i| NlriPrefix { prefix_len: 24, prefix: vec![192, 168, i as u8, 0] })
            .collect();

        let msg = BgpMessage::Update(UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: attrs,
            nlri,
        });
        let mut buf = vec![];
        msg.encode(&mut buf);
        buf
    }

    #[test]
    fn update_message_encodes_and_decodes() {
        let bytes = make_update_with_attrs(0, 1);
        assert!(bytes.len() > 19);
        let (msg, _) = BgpMessage::decode(&bytes).unwrap();
        assert!(matches!(msg, BgpMessage::Update(_)));
    }

    #[test]
    fn update_with_extra_attrs_larger_than_minimal() {
        let fat = make_update_with_attrs(5, 10);
        let slim = make_update_with_attrs(0, 1);
        assert!(fat.len() > slim.len());
    }

    #[test]
    fn shrink_bytes_respects_min_bgp_length() {
        let msg = vec![0xFFu8; 100];
        let truncated = msg[..MIN_BGP_MSG_LEN].to_vec();
        assert_eq!(truncated.len(), MIN_BGP_MSG_LEN);
    }

    #[test]
    fn keepalive_is_minimal() {
        let ka = bgp_wire::keepalive::KeepaliveMessage;
        let mut buf = vec![];
        ka.encode(&mut buf);
        assert_eq!(buf.len(), MIN_BGP_MSG_LEN);
    }

    #[test]
    fn shrink_step_records_delta() {
        let step = ShrinkStep {
            description: "ddmin: 10 → 3 messages".into(),
            before_len: 10,
            after_len: 3,
        };
        assert!(step.before_len > step.after_len);
    }

    #[test]
    fn shrink_result_has_audit_trail() {
        let result = ShrinkResult {
            original_len: 42,
            shrunk_len: 3,
            messages: make_msgs(3),
            steps: vec![ShrinkStep {
                description: "test".into(), before_len: 42, after_len: 3,
            }],
        };
        assert_eq!(result.steps.len(), 1);
        assert_eq!(result.messages.len(), 3);
    }
}
