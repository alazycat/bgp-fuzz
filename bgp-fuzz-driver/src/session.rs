use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgp_fuzz_oracle::{
    BugReport, BugSeverity, Direction, Oracle, RecvKind, RecvOutcome, ReproStep, SessionStats,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::connection;
use crate::fsm_driver::FsmDriver;
use crate::shrink::{FnCheck, ShrinkConfig, Shrinker};

/// Fuzz session configuration.
pub struct FuzzConfig {
    pub target: SocketAddr,
    pub duration: Duration,
    pub rate_limit: u32,
    pub output_dir: String,
    pub verbose: bool,
    pub enable_shrink: bool,
}

pub struct FuzzSession {
    config: FuzzConfig,
    fsm_driver: FsmDriver,
    oracles: Vec<Box<dyn Oracle>>,
    stats: SessionStats,
    shutdown: Arc<AtomicBool>,
    message_history: Vec<Vec<u8>>,
    shrinker: Option<Shrinker>,
}

impl FuzzSession {
    pub fn new(
        config: FuzzConfig,
        fsm_driver: FsmDriver,
        oracles: Vec<Box<dyn Oracle>>,
    ) -> Self {
        let shrinker = if config.enable_shrink {
            Some(Shrinker::with_tcp(config.target, ShrinkConfig::default()))
        } else {
            None
        };

        FuzzSession {
            config,
            fsm_driver,
            oracles,
            stats: SessionStats::default(),
            shutdown: Arc::new(AtomicBool::new(false)),
            message_history: Vec::new(),
            shrinker,
        }
    }

    pub async fn run<G>(&mut self, generator: G) -> Vec<BugReport>
    where
        G: Fn() -> Vec<Vec<u8>>,
    {
        let shutdown_flag = self.shutdown.clone();
        let _ = tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            shutdown_flag.store(true, Ordering::SeqCst);
        });

        let mut bugs = Vec::new();
        let started = Instant::now();

        while started.elapsed() < self.config.duration
            && !self.shutdown.load(Ordering::SeqCst)
        {
            let stream = match connection::connect_with_retry(
                self.config.target, 3, Duration::from_secs(1),
            ).await {
                Some(s) => s,
                None => break,
            };
            self.stats.connections += 1;
            self.message_history.clear();

            if self.run_session(stream, &generator, &mut bugs).await.is_err() {}
        }

        self.stats.elapsed_secs = started.elapsed().as_secs();
        self.print_summary(&bugs);
        bugs
    }

    async fn run_session<G>(
        &mut self,
        mut stream: TcpStream,
        generator: &G,
        bugs: &mut Vec<BugReport>,
    ) -> Result<(), ()>
    where
        G: Fn() -> Vec<Vec<u8>>,
    {
        connection::do_handshake(&mut stream, Duration::from_secs(5), Duration::from_secs(3)).await;

        let messages = generator();
        let rate_delay = Duration::from_secs_f64(1.0 / self.config.rate_limit as f64);

        for msg_bytes in &messages {
            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }

            let (outcome, current_history_len, send_time) =
                self.send_and_recv(&mut stream, msg_bytes).await?;

            self.process_outcome(msg_bytes, outcome, send_time, current_history_len, bugs).await;

            tokio::time::sleep(rate_delay).await;
        }

        Ok(())
    }

    async fn send_and_recv(
        &mut self,
        stream: &mut TcpStream,
        msg_bytes: &[u8],
    ) -> Result<(RecvOutcome, usize, Instant), ()> {
        if tokio::io::AsyncWriteExt::write_all(stream, msg_bytes).await.is_err() {
            return Err(());
        }
        let send_time = Instant::now();
        self.fsm_driver.on_send(msg_bytes);
        self.stats.msgs_sent += 1;
        self.message_history.push(msg_bytes.to_vec());

        if self.config.verbose {
            eprintln!("SEND {} bytes", msg_bytes.len());
        }

        let mut buf = vec![0u8; 4096];
        let recv = tokio::time::timeout(
            Duration::from_secs(self.fsm_driver.hold_time() as u64),
            stream.read(&mut buf),
        )
        .await;

        let history_len = self.message_history.len();
        let outcome = match recv {
            Ok(Ok(0)) => RecvOutcome { bytes: vec![], kind: RecvKind::PeerClosed },
            Ok(Ok(n)) => {
                self.stats.msgs_recv += 1;
                let data = buf[..n].to_vec();
                self.fsm_driver.on_recv(&data);
                RecvOutcome { bytes: data, kind: RecvKind::Data }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                RecvOutcome { bytes: vec![], kind: RecvKind::ConnectionReset }
            }
            Ok(Err(_)) => RecvOutcome { bytes: vec![], kind: RecvKind::Error },
            Err(_) => RecvOutcome { bytes: vec![], kind: RecvKind::Timeout },
        };

        Ok((outcome, history_len, send_time))
    }

    async fn process_outcome(
        &mut self,
        sent: &[u8],
        outcome: RecvOutcome,
        send_time: Instant,
        history_len: usize,
        bugs: &mut Vec<BugReport>,
    ) {
        let bug_kind = outcome.kind;
        let log = self.fsm_driver.event_log().to_vec();

        let mut findings = Vec::new();
        for oracle in &mut self.oracles {
            findings.extend(oracle.check(sent, &outcome, &log, send_time));
        }

        let target = self.config.target.to_string();
        for finding in findings {
            let mut report = finding.into_report(target.clone(), sent, &log);

            if let Some(ref shrinker) = self.shrinker {
                self.shrink_bug_report(shrinker, &mut report, history_len, bug_kind).await;
            }

            if self.config.verbose {
                eprintln!("BUG: [{}] {}", severity_name(&report.severity), report.title);
            }

            if let Ok(path) = bgp_fuzz_oracle::report::write_report(
                &report,
                &std::path::PathBuf::from(&self.config.output_dir),
            ) {
                if self.config.verbose {
                    eprintln!("  Report: {path}");
                }
            }

            match report.severity {
                BugSeverity::Critical => self.stats.bugs_critical += 1,
                BugSeverity::High => self.stats.bugs_high += 1,
                BugSeverity::Medium => self.stats.bugs_medium += 1,
            }
            bugs.push(report);
        }
    }

    async fn shrink_bug_report(
        &self,
        shrinker: &Shrinker,
        report: &mut BugReport,
        history_len: usize,
        bug_kind: RecvKind,
    ) {
        if history_len == 0 {
            return;
        }

        let original_exp = report.repro.first().map(|r| r.expected.clone());
        let original_ret = report.repro.first().map(|r| r.actual.clone());

        let predicate = move |outcome: &RecvOutcome| outcome.kind == bug_kind;

        let result = shrinker
            .shrink(&self.message_history[..history_len], &FnCheck(predicate))
            .await;

        let expected = original_exp
            .unwrap_or_else(|| "peer should accept and respond normally".into());
        let actual = original_ret
            .unwrap_or_else(|| "reproduction verified".into());

        report.repro = result
            .messages
            .iter()
            .map(|msg| ReproStep {
                direction: Direction::Send,
                hex: hex::encode(msg),
                expected: expected.clone(),
                actual: actual.clone(),
            })
            .collect();

        if self.config.verbose {
            eprintln!(
                "  Shrinker: {} → {} messages ({} steps)",
                history_len,
                result.shrunk_len,
                result.steps.len()
            );
        }
    }

    fn print_summary(&self, bugs: &[BugReport]) {
        let critical = bugs.iter().filter(|b| b.severity == BugSeverity::Critical).count();
        let high = bugs.iter().filter(|b| b.severity == BugSeverity::High).count();
        let medium = bugs.iter().filter(|b| b.severity == BugSeverity::Medium).count();
        eprintln!(
            "[SUMMARY] {}s | sent: {} | recv: {} | bugs: {} ({} critical, {} high, {} medium)",
            self.stats.elapsed_secs, self.stats.msgs_sent, self.stats.msgs_recv,
            bugs.len(), critical, high, medium,
        );
    }
}

fn severity_name(sev: &BugSeverity) -> &str {
    match sev {
        BugSeverity::Critical => "CRITICAL",
        BugSeverity::High => "HIGH",
        BugSeverity::Medium => "MEDIUM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_name_returns_correct_labels() {
        assert_eq!(severity_name(&BugSeverity::Critical), "CRITICAL");
        assert_eq!(severity_name(&BugSeverity::High), "HIGH");
        assert_eq!(severity_name(&BugSeverity::Medium), "MEDIUM");
    }

    #[test]
    fn fuzz_config_default_fields() {
        let cfg = FuzzConfig {
            target: "127.0.0.1:179".parse().unwrap(),
            duration: Duration::from_secs(60),
            rate_limit: 100,
            output_dir: "reports".into(),
            verbose: false,
            enable_shrink: false,
        };
        assert_eq!(cfg.rate_limit, 100);
        assert!(!cfg.verbose);
        assert!(!cfg.enable_shrink);
    }

    #[test]
    fn session_stats_initial_state() {
        let stats = SessionStats::default();
        assert_eq!(stats.msgs_sent, 0);
        assert_eq!(stats.msgs_recv, 0);
        assert_eq!(stats.bugs_critical, 0);
        assert_eq!(stats.bugs_high, 0);
        assert_eq!(stats.bugs_medium, 0);
    }
}
