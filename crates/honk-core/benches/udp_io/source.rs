//! Source-path workloads: the production VLESS XUDP source over loopback TCP.
//!
//! VLESS XUDP is the cheapest real source transport available without a QUIC
//! peer: Hy2/TUIC need a TLS/QUIC server (test-only, `control/tests/support.rs`).
//! One client carrier is shared by every destination, so a stuck carrier
//! write stalls all destinations (Mux.Cool head-of-line). A destination-
//! specific *send* block therefore cannot be expressed here; the closest
//! destination-specific condition is a destination whose replies never
//! return (`b_sink`). Per-target send blocking belongs to the future
//! `MultiTargetTransport` mock workload (same harness, new constructor).

use super::{Workload, bench_workload, runtime};
use criterion::Criterion;
use honk_core::control::udp_endpoint::bench_support::real_io::IoHarness;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const STATUS_KEEP: u8 = 2;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;

/// Accepts XUDP carriers and echoes every data frame back to its own target
/// address, except frames for the sink port. Frame layout mirrors
/// `source_tests.rs::run_wire_connection`.
async fn serve(socket: TcpStream, sink_port: Arc<AtomicU16>) -> io::Result<()> {
    socket.set_nodelay(true)?;
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut request = [0u8; 18];
    reader.read_exact(&mut request).await?;
    let mut addon_and_command = vec![0; usize::from(request[17]) + 1];
    reader.read_exact(&mut addon_and_command).await?;
    if addon_and_command.last() != Some(&3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a VLESS Mux carrier",
        ));
    }
    writer.write_all(&[0, 0]).await?;
    let mut metadata = [0u8; 64];
    let mut payload = [0u8; 2048];
    let mut reply = Vec::with_capacity(2 + 12 + 2 + 2048);
    loop {
        let metadata_len = usize::from(reader.read_u16().await?);
        let metadata = metadata
            .get_mut(..metadata_len)
            .filter(|m| m.len() >= 12)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad Cool metadata"))?;
        reader.read_exact(metadata).await?;
        if metadata[3] & OPTION_DATA == 0 {
            continue;
        }
        let len = usize::from(reader.read_u16().await?);
        reader.read_exact(&mut payload[..len]).await?;
        let port = u16::from_be_bytes([metadata[5], metadata[6]]);
        if metadata[4] != NETWORK_UDP
            || metadata[7] != ATYP_IPV4
            || port == sink_port.load(Ordering::Relaxed)
        {
            continue;
        }
        reply.clear();
        reply.extend_from_slice(&12u16.to_be_bytes());
        reply.extend_from_slice(&[0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        reply.extend_from_slice(&metadata[5..7]);
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&metadata[8..12]);
        reply.extend_from_slice(&(len as u16).to_be_bytes());
        reply.extend_from_slice(&payload[..len]);
        writer.write_all(&reply).await?;
    }
}

async fn start_peer(sink_port: Arc<AtomicU16>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("peer bind");
    let address = listener.local_addr().expect("peer address");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(socket, Arc::clone(&sink_port)));
        }
    });
    address
}

fn vless(
    name: &'static str,
    destinations: usize,
    measured: Vec<usize>,
    background: Option<usize>,
) -> Workload {
    let rt = runtime();
    let harness = rt.block_on(async {
        let sink_port = Arc::new(AtomicU16::new(0));
        let server = start_peer(Arc::clone(&sink_port)).await;
        let mut harness = IoHarness::new(destinations).await.expect("harness");
        if let Some(b) = background {
            // Sink a destination only after its first datagram is echoed.
            harness
                .install_vless_xudp_source(b, server)
                .await
                .expect("install background source");
            sink_port.store(harness.target(b).port(), Ordering::Relaxed);
        }
        for destination in (0..destinations).filter(|d| Some(*d) != background) {
            harness
                .install_vless_xudp_source(destination, server)
                .await
                .expect("install source");
        }
        harness
    });
    Workload {
        name,
        harness,
        rt,
        measured,
        background,
        gate: None,
    }
}

pub(super) fn bench(c: &mut Criterion) {
    bench_workload(c, vless("source_vless_single", 1, vec![0], None));
    bench_workload(c, vless("source_vless_two_dest", 2, vec![0, 1], None));
    bench_workload(
        c,
        vless("source_vless_two_dest_b_sink", 2, vec![0], Some(1)),
    );
}
