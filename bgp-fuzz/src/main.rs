use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};

enum Shutdown {
    SendFin,
    KeepOpen,
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

/// BGP Protocol Fuzzer v0.1
#[derive(Parser)]
#[command(version = "0.1")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send raw BGP bytes to a target and print the response
    Run {
        /// Target BGP speaker address (e.g., 127.0.0.1:179)
        #[arg(short, long)]
        target: SocketAddr,

        /// Hex-encoded byte sequence to send
        #[arg(short = 'x', long, group = "input")]
        hex: Option<String>,

        /// File containing hex-encoded byte sequence
        #[arg(short, long, group = "input")]
        file: Option<String>,

        /// TCP connect timeout in seconds
        #[arg(long, default_value = "5")]
        connect_timeout: u64,

        /// Receive response timeout in seconds
        #[arg(long, default_value = "3")]
        recv_timeout: u64,

        /// Send TCP FIN after sending data
        #[arg(long, default_value = "false")]
        send_close: bool,

        /// Verbose output (includes FSM trace)
        #[arg(short, long, default_value = "false")]
        verbose: bool,
    },
    /// Automated fuzz loop: generate, send, observe, report
    Fuzz {
        /// Target BGP speaker address (e.g., 127.0.0.1:179)
        #[arg(short, long)]
        target: SocketAddr,

        /// Fuzz duration (e.g., 30s, 5m, 1h)
        #[arg(short, long)]
        duration: String,

        /// Max messages per second (default: 100)
        #[arg(long, default_value = "100")]
        rate_limit: u32,

        /// Report output directory (default: ./reports)
        #[arg(short, long, default_value = "reports")]
        output: String,

        /// RNG seed for reproducible runs
        #[arg(long)]
        seed: Option<u64>,

        /// Generation strategy: all, grammar, raw, mutation (default: all)
        #[arg(long, default_value = "all")]
        strategy: String,

        /// Enable automatic repro shrinking (delta debugging)
        #[arg(long, default_value = "false")]
        shrink: bool,

        /// Verbose output
        #[arg(short, long, default_value = "false")]
        verbose: bool,
    },
    /// Replay a bug report to verify reproduction
    Replay {
        /// Path to the bug report JSON file
        #[arg(short, long)]
        report: String,

        /// Target BGP speaker address
        #[arg(short, long)]
        target: SocketAddr,
    },
}

fn generator_config_for_strategy(strategy: &str, seed: Option<u64>) -> bgp_fuzz_gen::GeneratorConfig {
    use bgp_fuzz_gen::{GeneratorConfig, LayerWeights, SeqLenWeights};

    let layer_weights = match strategy {
        "grammar" => LayerWeights { grammar: 1, raw: 0, mutation: 0 },
        "raw" => LayerWeights { grammar: 0, raw: 1, mutation: 0 },
        "mutation" => LayerWeights { grammar: 0, raw: 0, mutation: 1 },
        _ => LayerWeights::default(), // "all" or unknown
    };

    GeneratorConfig {
        layer_weights,
        seq_len_weights: SeqLenWeights::default(),
        seed: seed.unwrap_or(0),
        ..GeneratorConfig::default()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            target,
            hex,
            file,
            connect_timeout,
            recv_timeout,
            send_close,
            verbose,
        } => {
            let hex_str = if let Some(h) = hex {
                h
            } else if let Some(f) = file {
                match std::fs::read_to_string(&f) {
                    Ok(s) => s.trim().to_string(),
                    Err(e) => {
                        eprintln!("ERROR: cannot read file '{f}': {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("ERROR: must specify --hex or --file");
                std::process::exit(1);
            };

            let bytes = match decode_hex(&hex_str) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("ERROR: invalid hex: {e}");
                    std::process::exit(1);
                }
            };

            if verbose {
                eprintln!("[VERBOSE] target: {target}");
                eprintln!("[VERBOSE] payload: {} bytes", bytes.len());
                dump_hex(&bytes);
            }

            let shutdown = if send_close { Shutdown::SendFin } else { Shutdown::KeepOpen };
            run_fuzz(target, &bytes, connect_timeout, recv_timeout, shutdown, verbose).await;
        }
        Command::Fuzz { target, duration, rate_limit, output, seed, shrink, strategy, verbose } => {
            let dur = humantime::parse_duration(&duration)
                .unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid duration '{duration}': {e}");
                    std::process::exit(1);
                });

            let config = bgp_fuzz_driver::FuzzConfig {
                target,
                duration: dur,
                rate_limit,
                output_dir: output,
                verbose,
                enable_shrink: shrink,
            };

            let fsm_driver = bgp_fuzz_driver::FsmDriver::new(180);

            use bgp_fuzz_oracle::{CrashOracle, FsmConsistencyOracle, ResponseOracle};
            let oracles: Vec<Box<dyn bgp_fuzz_oracle::Oracle>> = vec![
                Box::new(CrashOracle::default()),
                Box::new(FsmConsistencyOracle::default()),
                Box::new(ResponseOracle::new(30)),
            ];

            let mut session = bgp_fuzz_driver::FuzzSession::new(config, fsm_driver, oracles);

            let gen_config = generator_config_for_strategy(strategy.as_str(), seed);

            let bgp_gen = std::cell::RefCell::new(bgp_fuzz_gen::Generator::new(gen_config));
            let generator = move || bgp_gen.borrow_mut().generate_batch();

            eprintln!("[INFO] target: {target}  duration: {duration}  strategy: {strategy}");
            if seed.is_some() {
                eprintln!("[INFO] seed: {}", seed.unwrap());
            }
            let _bugs = session.run(generator).await;
        }
        Command::Replay { report: report_path, target } => {
            let content = match std::fs::read_to_string(&report_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("ERROR: cannot read report '{report_path}': {e}");
                    std::process::exit(1);
                }
            };
            let bug: bgp_fuzz_oracle::BugReport = match serde_json::from_str(&content) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("ERROR: invalid report JSON: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("REPLAY: {} (target: {target})", bug.title);
            eprintln!("Severity: {:?}", bug.severity);
            if let Some(ref rfc) = bug.rfc_reference {
                eprintln!("RFC: {rfc}");
            }
            eprintln!("Steps: {}\n", bug.repro.len());

            for (i, step) in bug.repro.iter().enumerate() {
                eprintln!("[{}/{}] {} ({} bytes)", i + 1, bug.repro.len(), step.direction.direction_label(), step.hex.len() / 2);

                match step.direction {
                    bgp_fuzz_oracle::Direction::Send => {
                        let bytes = match decode_hex(&step.hex) {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("  ERROR: cannot decode hex: {e}");
                                continue;
                            }
                        };
                        let mut stream = connect_to_peer(target, 5).await;
                        send_payload(&mut stream, &bytes).await;

                        let mut buf = vec![0u8; 4096];
                        let recv = tokio::time::timeout(
                            Duration::from_secs(3),
                            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                        )
                        .await;

                        match recv {
                            Ok(Ok(0)) => eprintln!("  → PEER CLOSED (FIN)"),
                            Ok(Ok(n)) => {
                                eprintln!("  → RECV {n} bytes");
                                dump_hex(&buf[..n]);
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                                eprintln!("  → PEER SENT RST — crash reproduced");
                            }
                            Ok(Err(e)) => eprintln!("  → ERROR: {e}"),
                            Err(_) => eprintln!("  → TIMEOUT (no response)"),
                        }
                    }
                    bgp_fuzz_oracle::Direction::Receive => {
                        eprintln!("  (expected to receive: {} bytes)", step.hex.len() / 2);
                    }
                }
                eprintln!();
            }
        }
    }
}

async fn run_fuzz(
    target: SocketAddr,
    payload: &[u8],
    connect_timeout: u64,
    recv_timeout: u64,
    shutdown: Shutdown,
    verbose: bool,
) {
    let mut stream = connect_to_peer(target, connect_timeout).await;
    send_payload(&mut stream, payload).await;
    if matches!(shutdown, Shutdown::SendFin) {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        if verbose {
            eprintln!("[VERBOSE] sent FIN (half-close)");
        }
    }

    let mut buf = vec![0u8; 4096];
    let recv = tokio::time::timeout(
        Duration::from_secs(recv_timeout),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await;

    match recv {
        Ok(Ok(0)) => eprintln!("PEER CLOSED (FIN)"),
        Ok(Ok(n)) => {
            eprintln!("RECV {n} bytes");
            dump_hex(&buf[..n]);
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
            eprintln!("PEER SENT RST — possible crash");
        }
        Ok(Err(e)) => {
            eprintln!("ERROR: recv failed: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("WARN: recv timeout after {recv_timeout}s (no response from peer)");
        }
    }

    if verbose && !buf.is_empty() {
        eprintln!("[VERBOSE] response hex dump:");
        dump_hex(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]);
    }
}

async fn connect_to_peer(target: SocketAddr, timeout_secs: u64) -> tokio::net::TcpStream {
    let conn = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(target),
    )
    .await;

    match conn {
        Ok(Ok(s)) => {
            eprintln!("CONNECT {target} OK");
            s
        }
        Ok(Err(e)) => {
            eprintln!("ERROR: connect {target}: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("ERROR: connect {target}: timeout after {timeout_secs}s");
            std::process::exit(1);
        }
    }
}

async fn send_payload(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
    match tokio::io::AsyncWriteExt::write_all(stream, payload).await {
        Ok(()) => eprintln!("SEND {} bytes", payload.len()),
        Err(e) => {
            eprintln!("ERROR: send failed: {e}");
            std::process::exit(1);
        }
    }
}

fn dump_hex(data: &[u8]) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    for (i, chunk) in data.chunks(16).enumerate() {
        let _ = write!(handle, "{:08x}: ", i * 16);
        for (j, b) in chunk.iter().enumerate() {
            let _ = write!(handle, "{b:02x}");
            if j % 2 == 1 && j < chunk.len() - 1 {
                let _ = write!(handle, " ");
            }
        }
        let _ = handle.write_all(b"\n");
    }
    let _ = handle.flush();
}
