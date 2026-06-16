use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgp_fuzz_oracle::{BugReport, BugSeverity, Oracle, RecvKind, RecvOutcome, SessionStats};
use bgp_wire::WireEncode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::fsm_driver::FsmDriver;

/// Fuzz session configuration
pub struct FuzzConfig {
    pub target: SocketAddr,
    pub duration: Duration,
    pub rate_limit: u32,
    pub output_dir: String,
    pub verbose: bool,
}

/// Orchestrates a single fuzz run: connect, generate, send, observe, report.
pub struct FuzzSession {
    config: FuzzConfig,
    fsm_driver: FsmDriver,
    oracles: Vec<Box<dyn Oracle>>,
    stats: SessionStats,
    shutdown: Arc<AtomicBool>,
}

impl FuzzSession {
    pub fn new(
        config: FuzzConfig,
        fsm_driver: FsmDriver,
        oracles: Vec<Box<dyn Oracle>>,
    ) -> Self {
        FuzzSession {
            config,
            fsm_driver,
            oracles,
            stats: SessionStats::default(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run the fuzz loop. Returns all bug reports found.
    pub async fn run<G>(&mut self, generator: G) -> Vec<BugReport>
    where
        G: Fn() -> Vec<Vec<u8>>,
    {
        let shutdown_flag = self.shutdown.clone();
        // Handle Ctrl+C gracefully
        let _ = tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            shutdown_flag.store(true, Ordering::SeqCst);
        });

        let mut bugs = Vec::new();
        let started = Instant::now();

        while started.elapsed() < self.config.duration
            && !self.shutdown.load(Ordering::SeqCst)
        {
            // Connect (with retry)
            let stream = match self.connect_with_retry().await {
                Some(s) => s,
                None => break,
            };
            self.stats.connections += 1;

            if let Err(_) = self.run_session(stream, &generator, &mut bugs).await {
                // Session ended (disconnect, error) — reconnect
            }
        }

        self.stats.elapsed_secs = started.elapsed().as_secs();
        self.print_summary(&bugs);
        bugs
    }

    async fn connect_with_retry(&mut self) -> Option<TcpStream> {
        for attempt in 0..3 {
            match TcpStream::connect(self.config.target).await {
                Ok(s) => {
                    if self.config.verbose {
                        eprintln!("CONNECT {} OK", self.config.target);
                    }
                    return Some(s);
                }
                Err(e) if attempt < 2 => {
                    eprintln!("WARN: connect attempt {} failed: {e}", attempt + 1);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    eprintln!("ERROR: connect failed after 3 attempts: {e}");
                    return None;
                }
            }
        }
        None
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
        // Quick handshake: send OPEN, wait for OPEN, send KEEPALIVE
        self.do_handshake(&mut stream).await;

        let messages = generator();
        let rate_delay = Duration::from_secs_f64(1.0 / self.config.rate_limit as f64);

        for msg_bytes in &messages {
            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }

            // Send
            if let Err(_) = stream.write_all(msg_bytes).await {
                return Err(());
            }
            self.fsm_driver.on_send(msg_bytes);
            self.stats.msgs_sent += 1;

            if self.config.verbose {
                eprintln!("SEND {} bytes", msg_bytes.len());
            }

            // Receive (with timeout)
            let mut buf = vec![0u8; 4096];
            let recv = tokio::time::timeout(
                Duration::from_secs(self.fsm_driver.hold_time() as u64),
                stream.read(&mut buf),
            )
            .await;

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

            let log = self.fsm_driver.event_log().to_vec();

            // Run oracles
            for oracle in &mut self.oracles {
                let found = oracle.check(msg_bytes, &outcome, &log, &self.stats);
                for bug in found {
                    let mut report = bug;
                    report.target = self.config.target.to_string();
                    if self.config.verbose {
                        eprintln!("BUG: [{}] {}", severity_name(&report.severity), report.title);
                    }
                    // Write report
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

            tokio::time::sleep(rate_delay).await;
        }

        Ok(())
    }

    async fn do_handshake(&mut self, stream: &mut TcpStream) {
        // Send a minimal OPEN
        let open = bgp_wire::open::OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 180,
            bgp_id: [127, 0, 0, 1],
            optional_parameters: vec![],
        };
        let mut buf = vec![];
        open.encode(&mut buf);
        let _ = stream.write_all(&buf).await;
        self.fsm_driver.on_send(&buf);

        // Wait for peer OPEN
        let mut recv_buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut recv_buf)).await;

        // Send KEEPALIVE
        let keepalive = bgp_wire::keepalive::KeepaliveMessage;
        let mut kb = vec![];
        keepalive.encode(&mut kb);
        let _ = stream.write_all(&kb).await;
        self.fsm_driver.on_send(&kb);
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
