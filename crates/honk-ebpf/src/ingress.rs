//! TC ingress program entry points and helpers.
//!
//! `lan_ingress` intercepts LAN traffic, makes a routing decision, and
//! redirects proxy-bound flows into the isolated `daens` namespace via the
//! `dae0` veth.  The `sk_lookup` BPF program in `daens` then assigns the
//! packet to the local transparent listener socket.  `dae0_ingress` rewrites
//! replies from that listener back onto the original LAN interface so the
//! three-way handshake can complete without involving host IP forwarding.

use core::{
    ffi::{c_long, c_void},
    mem, ptr,
};

use crate::{
    action::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT, Verdict, flatten},
    event::send_dae_event,
    log_shim::*,
    maps::LISTEN_SOCKET_MAP,
    transport::ParsedPacket,
};
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::{
        __sk_buff, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2,
    },
    helpers::{
        bpf_ktime_get_ns, bpf_redirect, bpf_redirect_peer, bpf_skb_load_bytes, bpf_skb_store_bytes,
    },
};
use honk_ebpf_common::{
    RedirectEntry, RedirectTuple, RoutingMeta, TPROXY_MARK,
    conn::ConnState,
    dae_ip::In6Addr,
    event::DaeEventType,
    redirect_need::{RoutingHandoffEntry, TuplesKey},
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use crate::{
    maps::{
        CONN_STATE_MAP, OUTBOUND_CONNECTIVITY_MAP, PARAM, PKT_SCRATCH_KEY, REDIRECT_TRACK,
        ROUTE_CTX_SCRATCH_MAP, ROUTING_HANDOFF_MAP, ROUTING_META_MAP,
    },
    route::{OUTBOUND_BLOCK, OUTBOUND_DIRECT, RouteCtx},
    sk,
    transport::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP, parse_packet},
};

const IPV6_BYTE_LENGTH: usize = 16;

// Internal codes for the load_redirect_tuple_* helpers — NOT TC verdicts.
// `LOAD_REDIRECT_TUPLE_FALLBACK` numerically collides with `TC_ACT_SHOT`;
// it is consumed only by `load_redirect_tuple`'s fast→slow fallback chain.
const LOAD_REDIRECT_TUPLE_FALLBACK: c_long = 2;
/// Packet is neither IPv4 nor IPv6 — nothing to look up.
const LOAD_REDIRECT_TUPLE_NOT_IP: c_long = 1;
/// `bpf_skb_load_bytes` failed during the slow parse.
const LOAD_REDIRECT_TUPLE_ERR: c_long = -1;
const REDIRECT_PULL_SIZE: u32 = 128;

/// skb->mark bit set on packets that already passed `lan_ingress`
/// classification and were allowed through (`TC_ACT_OK`).
///
/// Userspace attaches `lan_ingress` to both the bridge master and every
/// bridge slave (honk-core real.rs), so a forwarded packet would otherwise
/// run the full parse + conntrack + socket lookup twice.  The first pass
/// tags pass-through packets with this bit; the second pass sees it at the
/// entry check and returns `TC_ACT_OK` immediately.
///
/// The mark rides with the skb into the network stack and is visible to
/// netfilter (`iptables -m mark`) and other TC programs.  Bit 30 was chosen
/// because it collides with none of the marks in use here — `TPROXY_MARK`
/// is bit 27 and the dae socket mark is bit 8 — while staying clear of
/// bit 31, which some userland tools print as a sign bit.  Redirected
/// packets don't need the tag: their mark is overwritten with
/// `TPROXY_MARK` and they leave towards dae0 instead of reaching the
/// second attach point.
const CLASSIFIED_MARK: u32 = 0x4000_0000;

/// Handoff write modes for [`redirect_lan_packet_to_control_plane`].
///
/// `HANDOFF_WRITE_ALWAYS`: new TCP flow (pure-SYN path).  Userspace
///   consumes the entry once when the connection is accepted, so every new
///   flow must leave one behind.  `REDIRECT_TRACK` is written
///   unconditionally as well.
/// `HANDOFF_WRITE_SKIP`: established TCP on the cached-routing path.
///   Userspace never looks up handoffs for these packets, so writing one
///   would just sit in the map until the janitor sweeps it.
///   `REDIRECT_TRACK` is refreshed only when stale.
/// `HANDOFF_WRITE_REFRESH`: UDP, first packet and cached path alike.
///   Write when no entry exists or the existing one is older than
///   [`crate::contrack::REDIRECT_REFRESH_INTERVAL_NS`].  A new flow's first
///   packet always finds the entry absent (or long consumed) and therefore
///   rewrites it, so userspace still sees a handoff on endpoint-pool miss.
const HANDOFF_WRITE_ALWAYS: u8 = 0;
const HANDOFF_WRITE_SKIP: u8 = 1;
const HANDOFF_WRITE_REFRESH: u8 = 2;

#[inline(always)]
fn redirect_lan_packet_to_control_plane(
    ctx: &TcContext,
    _link_h_len: u32,
    pkt: &ParsedPacket,
    routing_meta_raw: u64,
    handoff_mode: u8,
) -> Verdict {
    let routing_meta = RoutingMeta {
        raw: routing_meta_raw,
    };
    let now = unsafe { bpf_ktime_get_ns() };

    // Account this LAN → outbound packet against the final outbound
    // (redirect path; the direct+must pass-through exits count separately).
    crate::stats::count_tx(ctx, unsafe { routing_meta.data.outbound });

    // Set mark and cb for later processing.  The cross-namespace redirect
    // path preserves skb->mark but not cb[], so encode the listener l4proto
    // in the low byte of the mark (TPROXY_MARK only uses bit 27).
    ctx.skb
        .set_mark(TPROXY_MARK | (pkt.listener_l4proto as u32));
    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
        (*ctx.skb.skb).cb[1] = pkt.listener_l4proto as u32;
    }

    // Handoff entry for userspace lookup, throttled by mode (see the
    // HANDOFF_WRITE_* constants): established TCP flows never write, UDP
    // flows write at most once per REDIRECT_REFRESH_INTERVAL_NS.
    let write_handoff = match handoff_mode {
        HANDOFF_WRITE_ALWAYS => true,
        HANDOFF_WRITE_REFRESH => match ROUTING_HANDOFF_MAP.get_ptr_mut(pkt.tuples.five) {
            Some(old) => {
                now.wrapping_sub(unsafe { (*old).last_seen_ns })
                    >= crate::contrack::REDIRECT_REFRESH_INTERVAL_NS
            }
            None => true,
        },
        _ => false,
    };
    if write_handoff {
        let mut handoff: RoutingHandoffEntry = unsafe { mem::zeroed() };
        handoff.last_seen_ns = now;
        unsafe {
            handoff.result.mark = routing_meta.data.mark;
            handoff.result.must = routing_meta.data.must;
            handoff.result.outbound = routing_meta.data.outbound;
            handoff.result.dscp = routing_meta.data.dscp;
        }
        handoff.result.mac.copy_from_slice(&pkt.ethh.src_addr);
        ROUTING_HANDOFF_MAP.insert(pkt.tuples.five, handoff, 0).ok();
    }

    // Store the original LAN framing so dae0_ingress can rewrite replies
    // back to the original client without involving host IP forwarding.
    // New flows write unconditionally; cached-flow packets only refresh the
    // entry once it is older than REDIRECT_REFRESH_INTERVAL_NS.
    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 };
    let redirect_tuple =
        RedirectTuple::from_tuples_ip(&pkt.tuples.five, protocol == ETH_P_IP.to_be());
    let write_track = if handoff_mode == HANDOFF_WRITE_ALWAYS {
        true
    } else {
        match REDIRECT_TRACK.get_ptr_mut(redirect_tuple) {
            Some(old) => {
                now.wrapping_sub(unsafe { (*old).last_seen_ns })
                    >= crate::contrack::REDIRECT_REFRESH_INTERVAL_NS
            }
            None => true,
        }
    };
    if write_track {
        let mut redirect_entry: RedirectEntry = unsafe { mem::zeroed() };
        redirect_entry.ifindex = unsafe { (*ctx.skb.skb).ifindex };
        redirect_entry.smac.copy_from_slice(&pkt.ethh.src_addr);
        redirect_entry.dmac.copy_from_slice(&pkt.ethh.dst_addr);
        redirect_entry.last_seen_ns = now;
        // Record the final outbound so dae0_ingress can attribute replies.
        redirect_entry.outbound = unsafe { routing_meta.data.outbound };
        REDIRECT_TRACK
            .insert(redirect_tuple, redirect_entry, 0)
            .ok();
    }

    // Redirect the packet to the host-side dae0 veth.  From there it crosses
    // into the isolated daens namespace via the veth peer (dae0peer), where
    // the sk_lookup program overrides socket selection and delivers it to the
    // local TPROXY listener while preserving the original destination.
    let param = PARAM.load();
    // bpf_redirect_peer() bypasses the CPU backlog for veth peer redirect.
    // Requires kernel >= 6.8 (CVE-2025-37959 fix). Userspace verifies the
    // kernel version before enabling this flag.
    if param.use_redirect_peer != 0 {
        Ok(unsafe { bpf_redirect_peer(param.dae0_ifindex, 0) } as c_long)
    } else {
        Ok(unsafe { bpf_redirect(param.dae0_ifindex, 0) } as c_long)
    }
}

/// Early-exit `TC_ACT_OK` after tagging the skb with `CLASSIFIED_MARK`, so the
/// second TC pass (bridge master + slave double-attach) short-circuits at
/// the `do_tproxy_lan_ingress` entry check instead of redoing the full
/// classification.
#[inline(always)]
fn pass_through_classified(ctx: &TcContext) -> Verdict {
    ctx.skb
        .set_mark(unsafe { (*ctx.skb.skb).mark } | CLASSIFIED_MARK);
    Err(TC_ACT_OK)
}

#[inline(always)]
fn load_redirect_tuple_fast(ctx: &TcContext) -> Result<RedirectTuple, c_long> {
    if ctx.pull_data(REDIRECT_PULL_SIZE).is_err() {
        return Err(LOAD_REDIRECT_TUPLE_FALLBACK);
    }

    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    if unsafe { data.add(mem::size_of::<EthHdr>()) } > data_end {
        return Err(LOAD_REDIRECT_TUPLE_FALLBACK);
    }

    let eth = data as *const EthHdr;
    let ether_type = unsafe { (*eth).ether_type };

    if ether_type == ETH_P_IP.to_be() {
        let iph_offset = ETH_HLEN as usize;
        if unsafe { data.add(iph_offset + mem::size_of::<Ipv4Hdr>()) } > data_end {
            return Err(LOAD_REDIRECT_TUPLE_FALLBACK);
        }
        let iph = unsafe { &*(data.add(iph_offset) as *const Ipv4Hdr) };

        let rt: RedirectTuple = RedirectTuple {
            src_ip: In6Addr::from_ipv4_bytes(iph.dst_addr),
            dst_ip: In6Addr::from_ipv4_bytes(iph.src_addr),
        };

        Ok(rt)
    } else if ether_type == ETH_P_IPV6.to_be() {
        let ipv6h_offset = ETH_HLEN as usize;
        if unsafe { data.add(ipv6h_offset + mem::size_of::<Ipv6Hdr>()) } > data_end {
            return Err(LOAD_REDIRECT_TUPLE_FALLBACK);
        }
        let ipv6h = unsafe { &*(data.add(ipv6h_offset) as *const Ipv6Hdr) };

        let mut rt: RedirectTuple = unsafe { mem::zeroed() };
        rt.src_ip = In6Addr::from_ipv6_addr(ipv6h.dst_addr());
        rt.dst_ip = In6Addr::from_ipv6_addr(ipv6h.src_addr());

        Ok(rt)
    } else {
        Err(LOAD_REDIRECT_TUPLE_NOT_IP)
    }
}

#[inline(always)]
fn load_redirect_tuple_slow(ctx: &TcContext) -> Result<RedirectTuple, c_long> {
    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 };

    match protocol {
        val if val == ETH_P_IP.to_be() => {
            let _rt: RedirectTuple = RedirectTuple {
                src_ip: In6Addr::zero(),
                dst_ip: In6Addr::zero(),
            };

            // daddr — use raw bpf_skb_load_bytes with fixed len=4
            let dst_offset = (ETH_HLEN as usize + mem::offset_of!(Ipv4Hdr, dst_addr)) as u32;
            let mut dst_buf: [u8; 4] = [0; 4];
            let ret = unsafe {
                bpf_skb_load_bytes(
                    ctx.skb.skb as *mut _,
                    dst_offset,
                    dst_buf.as_mut_ptr() as *mut _,
                    4,
                )
            };
            if ret != 0 {
                return Err(LOAD_REDIRECT_TUPLE_ERR);
            }

            let src_ip = In6Addr::from_ipv4_bytes(dst_buf);

            // saddr
            let src_offset = (ETH_HLEN as usize + mem::offset_of!(Ipv4Hdr, src_addr)) as u32;
            let mut src_buf: [u8; 4] = [0; 4];
            let ret = unsafe {
                bpf_skb_load_bytes(
                    ctx.skb.skb as *mut _,
                    src_offset,
                    src_buf.as_mut_ptr() as *mut _,
                    4,
                )
            };
            if ret != 0 {
                return Err(LOAD_REDIRECT_TUPLE_ERR);
            }

            let dst_ip = In6Addr::from_ipv4_bytes(src_buf);

            Ok(RedirectTuple { src_ip, dst_ip })
        }
        val if val == ETH_P_IPV6.to_be() => {
            let mut rt: RedirectTuple = unsafe { mem::zeroed() };

            let dst_offset = (ETH_HLEN as usize + mem::offset_of!(Ipv6Hdr, dst_addr)) as u32;
            let ret = unsafe {
                bpf_skb_load_bytes(
                    ctx.skb.skb as *mut _,
                    dst_offset,
                    rt.src_ip.u6_addr32.as_mut_ptr() as *mut _,
                    16,
                )
            };
            if ret != 0 {
                return Err(LOAD_REDIRECT_TUPLE_ERR);
            }

            let src_offset = (ETH_HLEN as usize + mem::offset_of!(Ipv6Hdr, src_addr)) as u32;
            let ret = unsafe {
                bpf_skb_load_bytes(
                    ctx.skb.skb as *mut _,
                    src_offset,
                    rt.dst_ip.u6_addr32.as_mut_ptr() as *mut _,
                    16,
                )
            };
            if ret != 0 {
                return Err(LOAD_REDIRECT_TUPLE_ERR);
            }

            Ok(rt)
        }
        _ => Err(LOAD_REDIRECT_TUPLE_NOT_IP),
    }
}

#[inline(always)]
fn load_redirect_tuple(ctx: &TcContext) -> Result<RedirectTuple, c_long> {
    match load_redirect_tuple_fast(ctx) {
        Err(LOAD_REDIRECT_TUPLE_FALLBACK) => load_redirect_tuple_slow(ctx),
        other => other,
    }
}

#[inline(always)]
fn wan_outbound_is_alive(ctx: &TcContext, outbound: u8, l4proto: u8, dport: u16) -> bool {
    if l4proto == IPPROTO_UDP && dport == 53 {
        return true;
    }

    let protocol = ctx.skb.protocol() as u16;
    let domain_idx = match (l4proto, dport) {
        (IPPROTO_UDP, 53) => 1,
        (IPPROTO_UDP, _) => 2,
        _ => 0,
    };

    let ip_idx: u64 = if protocol == ETH_P_IP.to_be() { 0 } else { 1 };
    let key: u32 = (outbound as u32) * 6 + (domain_idx as u32) * 2 + (ip_idx as u32);

    match OUTBOUND_CONNECTIVITY_MAP.get(key) {
        Some(alive_val) => *alive_val != 0,
        None => true,
    }
}

/// Check if a destination IP is likely a local address where a socket lookup
/// could find a matching listening socket (RFC 1918, loopback, ULA, link-local).
/// Returns false for clearly non-local addresses, allowing us to skip the
/// expensive bpf_sk_lookup_* calls.
#[inline(always)]
fn dst_is_likely_local(dst_ip: &In6Addr) -> bool {
    unsafe {
        if dst_ip.is_v4_mapped() || dst_ip.is_v4_compat() {
            let ip = u32::from_be(dst_ip.u6_addr32[3]);
            // 10.0.0.0/8
            if (ip & 0xFF000000) == 0x0A000000 {
                return true;
            }
            // 172.16.0.0/12
            if (ip & 0xFFF00000) == 0xAC100000 {
                return true;
            }
            // 192.168.0.0/16
            if (ip & 0xFFFF0000) == 0xC0A80000 {
                return true;
            }
            // 127.0.0.0/8 (loopback)
            if (ip & 0xFF000000) == 0x7F000000 {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if (ip & 0xFFFF0000) == 0xA9FE0000 {
                return true;
            }
            false
        } else {
            // IPv6
            let bytes = dst_ip.u6_addr8;
            // ULA: fd00::/8
            if bytes[0] == 0xfd {
                return true;
            }
            // Loopback: ::1
            let mut is_loopback = true;
            for i in 0..15 {
                if bytes[i] != 0 {
                    is_loopback = false;
                    break;
                }
            }
            if is_loopback && bytes[15] == 1 {
                return true;
            }
            // Link-local: fe80::/10
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
                return true;
            }
            false
        }
    }
}

// #[inline(never)]: shared by lan_ingress_l2/l3. 5-level call chain
// with 256B baseline stays under the 512B BPF stack limit.
#[inline(never)]
fn do_tproxy_lan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    // Userspace attaches lan_ingress to both the bridge master and every
    // bridge slave, so a forwarded packet can traverse this program twice.
    // The first pass tags pass-through packets with CLASSIFIED_MARK; pass
    // them straight through here to skip the duplicate parse + conntrack +
    // socket lookup.
    if unsafe { (*ctx.skb.skb).mark } & CLASSIFIED_MARK != 0 {
        return Err(TC_ACT_OK);
    }

    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        return pass_through_classified(ctx);
    }

    if pkt.l4proto == IPPROTO_TCP && !crate::contrack::is_new_tcp_connection(&pkt.tcph) {
        let tcp_state = crate::contrack::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            0u8,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
        );
        let tcp_state = match tcp_state {
            Some(state) => state,
            None => return pass_through_classified(ctx),
        };
        if (unsafe { tcp_state.meta.raw } >> 56) & 1 == 0 {
            return pass_through_classified(ctx);
        }

        let outbound = unsafe { tcp_state.meta.data.outbound };
        let mark = unsafe { tcp_state.meta.data.mark };

        let must = unsafe { tcp_state.meta.data.must };

        if outbound == OUTBOUND_DIRECT && must != 0 {
            crate::stats::count_tx(ctx, outbound);
            ctx.skb.set_mark(mark | CLASSIFIED_MARK);
            return Err(TC_ACT_OK);
        }
        if outbound == OUTBOUND_DIRECT {
            return redirect_lan_packet_to_control_plane(
                ctx,
                link_h_len,
                pkt,
                unsafe { tcp_state.meta.raw },
                HANDOFF_WRITE_SKIP,
            );
        }
        if outbound == OUTBOUND_BLOCK {
            // Redirect BLOCK to control plane so userspace can drop/log it.
            return redirect_lan_packet_to_control_plane(
                ctx,
                link_h_len,
                pkt,
                unsafe { tcp_state.meta.raw },
                HANDOFF_WRITE_SKIP,
            );
        }
        if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe { tcp_state.meta.raw },
            HANDOFF_WRITE_SKIP,
        );
    }

    // Per-flow log, gated by PARAM.padding2 bit 0 (userspace writes 0 → off).
    if PARAM.load().padding2 & 1 != 0 {
        info!(ctx, target: "honk", "lan new flow: l4proto={} sport={} dport={}", pkt.l4proto, pkt.tuples.five.src_port, pkt.tuples.five.dst_port);
    }
    let mut route_flag: [u32; 8] = [0; 8];
    let mut tcp_state: Option<&mut ConnState> = None;
    let mut udp_state: Option<&mut ConnState> = None;

    if pkt.l4proto == IPPROTO_TCP {
        tcp_state = crate::contrack::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            0u8,
            None,
            None,
            None,
            None,
            pkt.tuples.dscp,
            None,
            0,
        );
        route_flag[0] = 1; // L4ProtoType_TCP
    } else {
        // UDP
        if !crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five) {
            udp_state = crate::contrack::mark_udp_seen(
                &pkt.tuples.five,
                0u8,
                None,
                None,
                None,
                None,
                pkt.tuples.dscp,
                None,
                0,
            );
            if let Some(ref udp_s) = udp_state {
                if udp_s.is_wan_ingress_direction != 0 {
                    return pass_through_classified(ctx);
                }
                if (unsafe { udp_s.meta.raw } >> 56) & 1 != 0 {
                    let outbound = unsafe { udp_s.meta.data.outbound };
                    let mark = unsafe { udp_s.meta.data.mark };

                    let must = unsafe { udp_s.meta.data.must };

                    if outbound == OUTBOUND_DIRECT && must != 0 {
                        crate::stats::count_tx(ctx, outbound);
                        ctx.skb.set_mark(mark | CLASSIFIED_MARK);
                        return Err(TC_ACT_OK);
                    }
                    if outbound == OUTBOUND_DIRECT {
                        if !wan_outbound_is_alive(
                            ctx,
                            outbound,
                            pkt.l4proto,
                            pkt.tuples.five.dst_port,
                        ) {
                            return Err(TC_ACT_SHOT);
                        }
                        return redirect_lan_packet_to_control_plane(
                            ctx,
                            link_h_len,
                            pkt,
                            unsafe {
                                crate::contrack::build_routing_meta(
                                    outbound,
                                    mark,
                                    0,
                                    pkt.tuples.dscp,
                                )
                                .raw
                            },
                            HANDOFF_WRITE_REFRESH,
                        );
                    }
                    if outbound == OUTBOUND_BLOCK {
                        // Redirect BLOCK to control plane.
                        if !wan_outbound_is_alive(
                            ctx,
                            outbound,
                            pkt.l4proto,
                            pkt.tuples.five.dst_port,
                        ) {
                            return Err(TC_ACT_SHOT);
                        }
                        return redirect_lan_packet_to_control_plane(
                            ctx,
                            link_h_len,
                            pkt,
                            unsafe {
                                crate::contrack::build_routing_meta(
                                    outbound,
                                    mark,
                                    0,
                                    pkt.tuples.dscp,
                                )
                                .raw
                            },
                            HANDOFF_WRITE_REFRESH,
                        );
                    }
                    if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port)
                    {
                        return Err(TC_ACT_SHOT);
                    }
                    return redirect_lan_packet_to_control_plane(
                        ctx,
                        link_h_len,
                        pkt,
                        unsafe { udp_s.meta.raw },
                        HANDOFF_WRITE_REFRESH,
                    );
                }
            }
        }
        route_flag[0] = 2; // L4ProtoType_UDP
    }

    // New-flow handoff policy from here on: a pure TCP SYN must always leave
    // a handoff for userspace to consume at accept time; UDP writes are
    // throttled to absent-or-stale (userspace only reads them on endpoint
    // pool miss, and the first packet always finds the entry absent).
    let handoff_mode = if pkt.l4proto == IPPROTO_TCP {
        HANDOFF_WRITE_ALWAYS
    } else {
        HANDOFF_WRITE_REFRESH
    };

    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 };
    route_flag[1] = if protocol == ETH_P_IP.to_be() { 4 } else { 6 };
    route_flag[6] = pkt.tuples.dscp as u32;

    let mac_be: [u32; 4] = [
        0,
        0,
        (((pkt.ethh.src_addr[0] as u32) << 8) | (pkt.ethh.src_addr[1] as u32)).to_be(),
        (((pkt.ethh.src_addr[2] as u32) << 24)
            | ((pkt.ethh.src_addr[3] as u32) << 16)
            | ((pkt.ethh.src_addr[4] as u32) << 8)
            | (pkt.ethh.src_addr[5] as u32))
            .to_be(),
    ];

    // Socket lookup before routing (NAT loopback detection); only for
    // likely-local destinations (RFC1918, loopback, ULA, link-local).
    if dst_is_likely_local(&pkt.tuples.five.dst_ip)
        && (pkt.l4proto == IPPROTO_TCP || pkt.l4proto == IPPROTO_UDP)
    {
        let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
        let tuple_size: u32;

        if pkt.ethh.ether_type == ETH_P_IP.to_be() {
            unsafe {
                tuple.__bindgen_anon_1.ipv4.daddr = pkt.tuples.five.dst_ip.u6_addr32[3];
                tuple.__bindgen_anon_1.ipv4.saddr = pkt.tuples.five.src_ip.u6_addr32[3];
                tuple.__bindgen_anon_1.ipv4.dport = pkt.tuples.five.dst_port.to_be();
                tuple.__bindgen_anon_1.ipv4.sport = pkt.tuples.five.src_port.to_be();
            }
            tuple_size = mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32;
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    pkt.tuples.five.dst_ip.u6_addr32.as_ptr(),
                    tuple.__bindgen_anon_1.ipv6.daddr.as_mut_ptr(),
                    4,
                );
                core::ptr::copy_nonoverlapping(
                    pkt.tuples.five.src_ip.u6_addr32.as_ptr(),
                    tuple.__bindgen_anon_1.ipv6.saddr.as_mut_ptr(),
                    4,
                );
                tuple.__bindgen_anon_1.ipv6.dport = pkt.tuples.five.dst_port.to_be();
                tuple.__bindgen_anon_1.ipv6.sport = pkt.tuples.five.src_port.to_be();
            }
            tuple_size = mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2>() as u32;
        }

        if pkt.l4proto == IPPROTO_TCP {
            // Skip socket lookup for SYN packets
            if !(pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0) {
                let param = PARAM.load();
                if let Some(probe) =
                    sk::probe_tcp_socket(ctx, &mut tuple, tuple_size, param.dae_netns_id as u64)
                {
                    // A local (non-dae) LISTEN socket owns this destination:
                    // NAT loopback — leave it to the kernel.
                    // BPF_TCP_LISTEN = 10
                    if !probe.is_dae_socket && probe.state == 10 {
                        return pass_through_classified(ctx);
                    }
                }
            }
        } else {
            let param = PARAM.load();
            if let Some(probe) =
                sk::probe_udp_socket(ctx, &mut tuple, tuple_size, param.dae_netns_id as u64)
            {
                if !probe.is_dae_socket {
                    return pass_through_classified(ctx);
                }
            }
        }
    }

    // DNS fast path: skip the expensive route_loop + LPM/domain lookups.
    if pkt.tuples.five.dst_port == 53 {
        // Update conn state for TCP DNS (UDP DNS is short-lived, skipped anyway)
        if pkt.l4proto == IPPROTO_TCP {
            if let Some(ref mut state) = tcp_state {
                state.mac.copy_from_slice(&pkt.ethh.src_addr);
                let meta =
                    crate::contrack::build_routing_meta(OUTBOUND_DIRECT, 0, 0, pkt.tuples.dscp);
                crate::contrack::publish_routing_meta(&mut state.meta, meta);
            }
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe {
                crate::contrack::build_routing_meta(OUTBOUND_DIRECT, 0, 0, pkt.tuples.dscp).raw
            },
            handoff_mode,
        );
    }

    let route_ctx_ptr = ROUTE_CTX_SCRATCH_MAP.get_ptr_mut(0);
    if route_ctx_ptr.is_none() {
        return Err(TC_ACT_SHOT);
    }
    let route_ctx = unsafe { &mut *route_ctx_ptr.unwrap() };

    unsafe {
        core::ptr::write_bytes(
            route_ctx as *mut RouteCtx as *mut u8,
            0,
            mem::size_of::<RouteCtx>(),
        );
    }
    route_ctx.is_wan = 0;
    route_ctx.l4proto_type = route_flag[0] as u8;
    route_ctx.ipversion_type = route_flag[1] as u8;
    route_ctx.dscp_cache = route_flag[6] as u8;
    route_ctx.pname_cache = [route_flag[2], route_flag[3], route_flag[4], route_flag[5]];
    route_ctx.mac.copy_from_slice(&mac_be);

    if pkt.l4proto == IPPROTO_TCP {
        route_ctx.h_dport = u16::from_be_bytes(pkt.tcph.dest);
        route_ctx.h_sport = u16::from_be_bytes(pkt.tcph.source);
    } else {
        route_ctx.h_dport = u16::from_be_bytes(pkt.udph.dst);
        route_ctx.h_sport = u16::from_be_bytes(pkt.udph.src);
    }

    if route_ctx.h_dport == 53 && (route_flag[0] == 2 || route_flag[0] == 1) {
        route_ctx.route_state |= 1 << 3; // ROUTE_STATE_DNS_QUERY
    }

    // Copy the raw network-order bytes into the LPM key data. Using u6_addr32
    // chunks would swap bytes on little-endian BPF hosts, breaking lookups
    // against the network-order keys pushed by userspace.
    route_ctx.lpm_key_saddr.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    route_ctx.lpm_key_daddr.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    route_ctx.lpm_key_mac.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            pkt.tuples.five.src_ip.as_bytes().as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_saddr.data).cast::<u8>(),
            IPV6_BYTE_LENGTH,
        );
        core::ptr::copy_nonoverlapping(
            pkt.tuples.five.dst_ip.as_bytes().as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_daddr.data).cast::<u8>(),
            IPV6_BYTE_LENGTH,
        );
        core::ptr::copy_nonoverlapping(
            mac_be.as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_mac.data).cast(),
            4,
        );
    }

    let zero_key: u32 = 0;
    let max_match_set_len: u32 = 32 * 32;
    let active_rules_len = if let Some(len_ptr) = ROUTING_META_MAP.get(zero_key) {
        let raw = *len_ptr;
        if raw <= max_match_set_len {
            raw
        } else {
            max_match_set_len
        }
    } else {
        max_match_set_len
    };

    // Cache this flow's (l4proto × ipversion) group bitmap so the route
    // loop can skip MatchSets that cannot match it.
    route_ctx.load_group_bitmap();

    let loop_ret = route_ctx.route_loop(active_rules_len);
    if loop_ret < 0 {
        error!(ctx, target: "honk", "shot routing: {}", loop_ret);
        return Err(TC_ACT_SHOT);
    }

    let s64_ret = route_ctx.result;
    if s64_ret < 0 {
        error!(ctx, target: "honk", "lan_ingress route fail: {}", s64_ret);
        return Err(TC_ACT_SHOT);
    }

    let outbound = s64_ret as u8;
    let mark = (s64_ret >> 8) as u32;
    let must = ((s64_ret >> 40) & 1) as u8;

    if pkt.l4proto == IPPROTO_UDP && crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five) {
        // Skip cache for short-lived DNS
    } else if pkt.l4proto == IPPROTO_TCP {
        if let Some(ref mut state) = tcp_state {
            state.mac.copy_from_slice(&pkt.ethh.src_addr);
            let meta = crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp);
            crate::contrack::publish_routing_meta(&mut state.meta, meta);
        }
    } else if pkt.l4proto == IPPROTO_UDP {
        if let Some(ref mut state) = udp_state {
            state.mac.copy_from_slice(&pkt.ethh.src_addr);
            let meta = crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp);
            crate::contrack::publish_routing_meta(&mut state.meta, meta);
        }
    }

    // Fail-closed for TCP when the conn state map is full.
    if pkt.l4proto == IPPROTO_TCP && tcp_state.is_none() {
        if outbound == OUTBOUND_DIRECT && must != 0 && mark == 0 {
            ctx.skb.set_mark(mark | CLASSIFIED_MARK);
            return Err(TC_ACT_OK);
        }
        if outbound == OUTBOUND_DIRECT && must != 0 {}
        return Err(TC_ACT_SHOT);
    }

    if outbound == OUTBOUND_DIRECT && must != 0 {
        if PARAM.load().padding2 & 1 != 0 {
            info!(ctx, target: "honk", "direct(must) path");
        }
        crate::stats::count_tx(ctx, outbound);
        ctx.skb.set_mark(mark | CLASSIFIED_MARK);
        return Err(TC_ACT_OK);
    }
    if outbound == OUTBOUND_DIRECT {
        // No must → domain-based or uncertain routing.
        // Redirect to control plane for SNI sniffing and final routing.
        if PARAM.load().padding2 & 1 != 0 {
            info!(ctx, target: "honk", "direct(no must) → control plane");
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe {
                crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp).raw
            },
            handoff_mode,
        );
    }
    if outbound == OUTBOUND_BLOCK {
        // Redirect BLOCK to control plane.
        if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe { crate::contrack::build_routing_meta(outbound, mark, 0, pkt.tuples.dscp).raw },
            handoff_mode,
        );
    }

    if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }

    redirect_lan_packet_to_control_plane(
        ctx,
        link_h_len,
        pkt,
        unsafe { crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp).raw },
        handoff_mode,
    )
}

// #[inline(never)]: shared by wan_ingress_l2/l3. Shallow call chain
// (only parse_packet + conn state update).
#[inline(never)]
fn do_tproxy_wan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        if ret < 0 {
            error!(ctx, target: "honk", "parse_transport error: {}, dropping", ret);
            return Err(TC_ACT_SHOT);
        }
        return Err(TC_ACT_OK);
    }

    if pkt.l4proto == IPPROTO_TCP {
        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        let _ = crate::contrack::mark_tcp_seen(
            &reversed_key,
            &pkt.tcph,
            1u8,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
        );
    } else if pkt.l4proto == IPPROTO_UDP {
        let src_port = u16::from_be_bytes(pkt.udph.src);
        let dst_port = u16::from_be_bytes(pkt.udph.dst);
        if src_port == 53 || dst_port == 53 {
            return Err(TC_ACT_PIPE);
        }

        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        let _ =
            crate::contrack::mark_udp_seen(&reversed_key, 1u8, None, None, None, None, 0, None, 0);
    }

    Ok(TC_ACT_PIPE)
}

// #[inline(never)]: standalone program, no deep call chain.
/// Recover the listener protocol when veth delivery has cleared both
/// `skb->cb` and `skb->mark`.
///
/// The host-side ingress/egress programs record every redirected flow in
/// `CONN_STATE_MAP` before sending it to dae0.  This gives the dedicated
/// dae0peer ingress hook a durable, per-flow proof that the packet belongs to
/// honk, without accepting unrelated traffic injected into the namespace.
#[inline(always)]
fn recover_dae0peer_listener_l4proto(ctx: &TcContext) -> Option<u8> {
    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return None,
    };

    if parse_packet(ctx, ETH_HLEN, pkt) != 0 {
        return None;
    }

    let state = CONN_STATE_MAP.get_ptr_mut(pkt.tuples.five)?;
    let has_routing = ((unsafe { (*state).meta.raw } >> 56) & 1) != 0;
    has_routing.then_some(pkt.listener_l4proto)
}

// #[inline(never)]: standalone program, no deep call chain.
#[inline(never)]
fn do_tproxy_dae0peer_ingress(ctx: &TcContext) -> Verdict {
    // Only packets redirected from wan_egress or lan_ingress carry the
    // TPROXY marker. `skb->cb` is scratch storage and can be cleared when a
    // packet crosses the dae0 veth pair, so the redirect path mirrors the
    // marker and listener L4 protocol in skb->mark as a durable fallback.
    // Other traffic (e.g. replies to locally-generated proxy outbound
    // connections) must be dropped here rather than accidentally assigned to
    // the transparent listener.
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    let packet_mark = unsafe { (*ctx.skb.skb).mark };
    let mark_is_tproxy = (packet_mark & TPROXY_MARK) == TPROXY_MARK;

    // listener_l4proto is stored in cb[1] only when the control-plane handoff
    // needs an explicit listener assignment (UDP or TCP SYN, including first
    // fragments that still expose those headers). If cb[] was cleared by the
    // veth handoff, recover it from the low byte of skb->mark. Established TCP
    // has a zero protocol marker and can return to the stack without
    // bpf_sk_assign; the kernel will find the child socket via normal socket
    // lookup.
    let listener_l4proto = if cb0 == TPROXY_MARK || mark_is_tproxy {
        let listener_l4proto = (unsafe { (*ctx.skb.skb).cb[1] }) as u8;
        if listener_l4proto != 0 {
            listener_l4proto
        } else {
            packet_mark as u8
        }
    } else {
        match recover_dae0peer_listener_l4proto(ctx) {
            Some(listener_l4proto) => listener_l4proto,
            None => return Err(TC_ACT_SHOT),
        }
    };
    ctx.set_mark(TPROXY_MARK);
    // Force the packet type to HOST so the IP stack accepts it and returns
    // it to the stack, letting the netfilter PREROUTING TPROXY rule (or the
    // attached sk_lookup BPF program) deliver it to the transparent listener
    // socket.  Established TCP (cb[1] == 0) intentionally skips bpf_sk_assign:
    // assigning here would bypass PREROUTING and prevent the kernel from
    // creating proper child sockets for intercepted TCP flows.
    let _ = ctx.change_type(0);
    if listener_l4proto != 0 {
        if let Err(errno) = assign_listener(ctx, listener_l4proto) {
            // Do not silently turn a broken listener handoff into a timeout.
            // `DaeEvent` has no dedicated errno field; for this event type its
            // `pid` field carries the positive errno instead.
            let _ = send_dae_event(
                DaeEventType::TproxyAssignFailure as u32,
                errno.wrapping_neg() as u32,
                None,
                0,
                listener_l4proto,
                None,
                None,
                0,
                0,
            );
        }
    }

    Ok(TC_ACT_OK)
}

/// SockMap keys for `LISTEN_SOCKET_MAP`, matching the userspace
/// `publish_listener_sockets` mapping: 0 = TCP IPv4, 1 = UDP IPv4,
/// 2 = TCP IPv6, 3 = UDP IPv6.
const KEY_TCP4: u32 = 0;
const KEY_UDP4: u32 = 1;
const KEY_TCP6: u32 = 2;
const KEY_UDP6: u32 = 3;

/// Assign the TPROXY listener socket to the current skb so the kernel delivers
/// the packet to the transparent proxy listener instead of performing a normal
/// route lookup.
///
/// Ported from Go dae's `assign_listener` in `control/kern/tproxy.c`.  Uses
/// `bpf_sk_assign` via a SOCKMAP lookup — the same proven pattern employed by
/// the `tproxy_sk_lookup` program in `sk_lookup.rs`, shared via
/// [`sk::sk_assign_by_index`].
#[inline(always)]
fn assign_listener(ctx: &TcContext, listener_l4proto: u8) -> Result<(), c_long> {
    // SockMap keys differentiate IPv4 vs IPv6 to match the per-family
    // listeners published by userspace.
    let is_v6 = unsafe { (*ctx.skb.skb).protocol as u16 } == ETH_P_IPV6.to_be();
    let key = if listener_l4proto == IPPROTO_TCP as u8 {
        if is_v6 { KEY_TCP6 } else { KEY_TCP4 }
    } else {
        if is_v6 { KEY_UDP6 } else { KEY_UDP4 }
    };

    let map_ptr = ptr::from_ref(&LISTEN_SOCKET_MAP).cast::<c_void>();
    sk::sk_assign_by_index(ctx, map_ptr, &key, 0)
}

// #[inline(never)]: standalone program, no deep call chain.
#[inline(never)]
fn do_tproxy_dae0_ingress(ctx: &TcContext) -> Verdict {
    let redirect_tuple = match load_redirect_tuple(ctx) {
        Ok(rt) => rt,
        Err(_) => return Err(TC_ACT_OK),
    };

    let entry_ptr = REDIRECT_TRACK.get_ptr_mut(redirect_tuple);
    if entry_ptr.is_none() {
        return Err(TC_ACT_OK);
    }
    let entry = unsafe { &mut *entry_ptr.unwrap() };

    entry.last_seen_ns = unsafe { bpf_ktime_get_ns() };

    // Account this reply (outbound → LAN) against the outbound recorded
    // when the flow was redirected to the control plane.
    crate::stats::count_rx(ctx, entry.outbound);

    // load_redirect_tuple reverses the packet tuple, so any successful
    // lookup here is a reply (proxy -> LAN).  Rewrite the Ethernet header
    // back to the original LAN framing and redirect to the original
    // interface so the reply reaches the original client.
    //
    // Host-originated flows (from_wan != 0, e.g. gateway's own traffic out a
    // PPPoE WAN) have no LAN framing to restore: inject the reply into the
    // WAN interface's RX path (BPF_F_INGRESS) as PACKET_HOST so the local
    // stack accepts it, mirroring Go dae's tproxy_dae0_ingress.
    let dmac = entry.smac;
    let smac = entry.dmac;
    let from_wan = entry.from_wan;
    unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb,
            mem::offset_of!(EthHdr, src_addr) as u32,
            smac.as_ptr() as *const _,
            6,
            0,
        );
        bpf_skb_store_bytes(
            ctx.skb.skb,
            mem::offset_of!(EthHdr, dst_addr) as u32,
            dmac.as_ptr() as *const _,
            6,
            0,
        );
    }

    let pkt_type: u32 = if from_wan != 0 { 0 } else { 1 }; // PACKET_HOST : PACKET_OTHERHOST
    let flags: u64 = if from_wan != 0 { 1 } else { 0 }; // BPF_F_INGRESS
    let _ = ctx.skb.change_type(pkt_type);
    Ok(unsafe { bpf_redirect(entry.ifindex, flags) } as c_long)
}

// TC entry points use raw __sk_buff pointer to avoid verifier
// "Arg#0 type STRUCT not supported" error on kernel >= 7.0.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_ingress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_ingress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_dae0peer_ingress(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_dae0_ingress(&TcContext::new(ctx)))
}
