use std::net::SocketAddr;
use std::time::Duration;

use bgp_wire::WireEncode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Connect to a BGP peer with retry. Returns None after `max_attempts` failures.
pub async fn connect_with_retry(
    target: SocketAddr,
    max_attempts: u32,
    delay: Duration,
) -> Option<TcpStream> {
    for attempt in 0..max_attempts {
        match TcpStream::connect(target).await {
            Ok(s) => return Some(s),
            Err(_) if attempt + 1 < max_attempts => {
                tokio::time::sleep(delay).await;
            }
            Err(_) => return None,
        }
    }
    None
}

/// Replay the BGP handshake preamble: send OPEN, drain response, send KEEPALIVE, drain response.
/// Best-effort — never fails, even if the peer sends RST or times out.
pub async fn do_handshake(
    stream: &mut TcpStream,
    open_recv_timeout: Duration,
    keepalive_recv_timeout: Duration,
) {
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

    let mut recv_buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(open_recv_timeout, stream.read(&mut recv_buf)).await;

    let keepalive = bgp_wire::keepalive::KeepaliveMessage;
    let mut kb = vec![];
    keepalive.encode(&mut kb);
    let _ = stream.write_all(&kb).await;

    let _ = tokio::time::timeout(keepalive_recv_timeout, stream.read(&mut recv_buf)).await;
}
