use super::*;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::event::{DaeEvent, DaeEventType};

/// Format a `DaeEvent` IP field — four u32 chunks of a 16-byte address in
/// network order, IPv4-mapped for v4 flows — as an `IpAddr` for logging.
pub fn event_ip(chunks: &[u32; 4]) -> std::net::IpAddr {
    let mut bytes = [0u8; 16];
    for (i, chunk) in chunks.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk.to_ne_bytes());
    }
    let v6 = std::net::Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    }
}

/// Maximum eBPF datapath events logged per second; excess events within the
/// window are counted and reported in aggregate when the window rolls over,
/// so a conntrack overflow burst cannot storm the log.
pub const EVENT_LOG_MAX_PER_SEC: u32 = 32;

fn dispatch_expiry_event(
    event: &DaeEvent,
    expiry_hints: &tokio::sync::mpsc::Sender<FlowExpiryHint>,
) -> bool {
    if event.type_ != DaeEventType::FlowExpired as u32 {
        return false;
    }
    if matches!(event.l4proto, 6 | 17)
        && event.incarnation != 0
        && event.incarnation <= honk_ebpf_common::conn::FLOW_INCARNATION_MAX
    {
        let hint = FlowExpiryHint {
            key: TuplesKey {
                src_ip: In6Addr {
                    u6_addr32: event.sip,
                },
                dst_ip: In6Addr {
                    u6_addr32: event.dip,
                },
                src_port: event.sport,
                dst_port: event.dport,
                l4proto: event.l4proto,
                padding: [0; 3],
            },
            incarnation: event.incarnation,
        };
        // Advisory only: the ordinary janitor backs up a full hint queue.
        let _ = expiry_hints.try_send(hint);
    }
    true
}

/// Drain functional expiry hints before rate-limiting diagnostic events.
pub async fn consume_dae_events(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    expiry_hints: tokio::sync::mpsc::Sender<FlowExpiryHint>,
) {
    let mut window = std::time::Instant::now();
    let mut emitted: u32 = 0;
    let mut suppressed: u64 = 0;
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                debug!("DaeEvent ringbuf AsyncFd wait failed: {}", e);
                break;
            }
        };
        {
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < core::mem::size_of::<DaeEvent>() {
                    continue;
                }
                let ev: DaeEvent =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DaeEvent) };
                if dispatch_expiry_event(&ev, &expiry_hints) {
                    continue;
                }
                if window.elapsed() >= std::time::Duration::from_secs(1) {
                    if suppressed > 0 {
                        warn!(
                            "eBPF datapath events suppressed: {} in the last second",
                            suppressed
                        );
                    }
                    window = std::time::Instant::now();
                    emitted = 0;
                    suppressed = 0;
                }
                if emitted >= EVENT_LOG_MAX_PER_SEC {
                    suppressed += 1;
                    continue;
                }
                emitted += 1;
                let pname_end = ev
                    .pname
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(ev.pname.len());
                let pname = String::from_utf8_lossy(&ev.pname[..pname_end]);
                let sip = event_ip(&ev.sip);
                let dip = event_ip(&ev.dip);
                let is_overflow = ev.type_ == DaeEventType::UdpConnOverflow as u32
                    || ev.type_ == DaeEventType::TcpConnOverflow as u32;
                let is_token_exhaustion =
                    ev.type_ == DaeEventType::UdpDecisionTokenExhausted as u32;
                let kind = match ev.type_ {
                    t if t == DaeEventType::UdpConnOverflow as u32 => "udp_conn_overflow",
                    t if t == DaeEventType::TcpConnOverflow as u32 => "tcp_conn_overflow",
                    t if t == DaeEventType::Blocked as u32 => "blocked",
                    t if t == DaeEventType::UdpDecisionTokenExhausted as u32 => {
                        "udp_decision_token_exhausted"
                    }
                    _ => "unknown",
                };
                if is_overflow {
                    debug!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF conntrack overflow");
                } else if is_token_exhaustion {
                    warn!(target: "honk-ebpf", event = kind, "UDP decision token allocator exhausted");
                } else {
                    debug!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF datapath event");
                }
            }
        }
        guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_dispatch_preserves_tuple_and_drops_only_advisory_overflow() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut event: DaeEvent = unsafe { core::mem::zeroed() };
        event.type_ = DaeEventType::FlowExpired as u32;
        event.l4proto = 6;
        event.incarnation = 42;
        event.sip = unsafe { In6Addr::from_ipv4_bytes([192, 0, 2, 1]).u6_addr32 };
        event.dip = unsafe { In6Addr::from_ipv4_bytes([198, 51, 100, 2]).u6_addr32 };
        event.sport = 49152;
        event.dport = 443;

        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = 43;
        assert!(dispatch_expiry_event(&event, &tx));
        let hint = rx.try_recv().unwrap();
        assert_eq!(hint.incarnation, 42);
        assert_eq!(unsafe { hint.key.src_ip.u6_addr32 }, event.sip);
        assert_eq!(unsafe { hint.key.dst_ip.u6_addr32 }, event.dip);
        assert_eq!(hint.key.src_port, 49152);
        assert_eq!(hint.key.dst_port, 443);
        assert_eq!(hint.key.l4proto, 6);
        assert_eq!(hint.key.padding, [0; 3]);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        event.l4proto = 17;
        assert!(dispatch_expiry_event(&event, &tx));
        assert_eq!(rx.try_recv().unwrap().key.l4proto, 17);
        event.incarnation = 0;
        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = honk_ebpf_common::conn::FLOW_INCARNATION_MAX + 1;
        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = 44;
        event.l4proto = 1;
        assert!(dispatch_expiry_event(&event, &tx));
        event.type_ = DaeEventType::Blocked as u32;
        assert!(!dispatch_expiry_event(&event, &tx));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        drop(tx);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
