//! Canonical stable-element publication and refresh for tuple auxiliary maps.

#![allow(clippy::too_many_arguments)]

use crate::{
    maps::{PARAM, UDP_DECISION_SCRATCH_MAP},
    transport::ETH_HLEN,
};
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::BPF_NOEXIST,
    helpers::{
        bpf_ktime_get_ns, bpf_skb_change_head, bpf_skb_store_bytes, bpf_spin_lock, bpf_spin_unlock,
    },
};
use core::mem;
use honk_ebpf_common::{
    FlowMapValue, RedirectEntry, RedirectTuple, RoutingHandoffEntry, Tuples, TuplesKey,
    conn::BpfStatsKey,
};
use network_types::eth::EthHdr;

use crate::{
    contrack::{AUXILIARY_MAP_REFRESH_INTERVAL_NS, auxiliary_expired},
    flow::{
        AuxiliaryIdentity, copy_payload, handoff_identity, redirect_identity, redirect_snapshot,
    },
    maps::{
        CLIENT_REPLY_TRACK, REDIRECT_TRACK, ROUTING_HANDOFF_MAP, TCP_PUBLISHING,
        UdpDecisionScratch, increment_bpf_stat, tuple_retiring,
    },
};

pub const IDENTITY_MISMATCH: i32 = -2;

#[inline(always)]
fn stateless_publication(key: &TuplesKey, token: u32, incarnation: u64) -> bool {
    token == 0 && incarnation == 0 && crate::contrack::is_short_lived_udp_traffic(key)
}

// Project through existing scratch to avoid another key/value pair on the TC stack.
#[inline(always)]
fn publish_client_reply(key: &TuplesKey, scratch: &mut UdpDecisionScratch) {
    if key.l4proto != crate::transport::IPPROTO_UDP
        || key.dst_port == 53
        || scratch.redirect.from_wan != 0
    {
        return;
    }
    let token = scratch.redirect.decision_token;
    let incarnation = scratch.redirect.incarnation;
    scratch.redirect_key.dst_ip.u6_addr64 = [0, 0];
    scratch.redirect_key.dst_port = 0;
    scratch.redirect.decision_token = 0;
    scratch.redirect.incarnation = 0;
    let _ = CLIENT_REPLY_TRACK.insert(&scratch.redirect_key, &scratch.redirect, 0);
    scratch.redirect_key = RedirectTuple::from_tuples(key);
    scratch.redirect.decision_token = token;
    scratch.redirect.incarnation = incarnation;
}

const _: () = {
    assert!(
        core::mem::offset_of!(UdpDecisionScratch, redirect)
            == core::mem::offset_of!(UdpDecisionScratch, redirect_header) + 8
    );
    assert!(
        core::mem::offset_of!(UdpDecisionScratch, handoff)
            == core::mem::offset_of!(UdpDecisionScratch, handoff_header) + 8
    );
    assert!(core::mem::offset_of!(FlowMapValue<RedirectEntry>, value) == 8);
    assert!(core::mem::offset_of!(FlowMapValue<RoutingHandoffEntry>, value) == 8);
};

#[inline(always)]
fn touch_redirect(
    key: &TuplesKey,
    redirect_key: &RedirectTuple,
    snapshot: &AuxiliaryIdentity,
    now: u64,
) -> Result<(), i32> {
    if auxiliary_expired(
        key,
        snapshot.incarnation,
        now.saturating_sub(snapshot.last_seen_ns),
        false,
    ) {
        return Err(IDENTITY_MISMATCH);
    }
    if now.saturating_sub(snapshot.last_seen_ns) < AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        return Ok(());
    }
    let scratch = if key.l4proto == crate::transport::IPPROTO_UDP && key.dst_port != 53 {
        let mut zero = 0u32;
        unsafe { core::ptr::write_volatile(&mut zero, 0) };
        UDP_DECISION_SCRATCH_MAP.get_ptr_mut(unsafe { core::ptr::read_volatile(&zero) })
    } else {
        None
    };
    if let Some(scratch) = scratch {
        unsafe { (*scratch).redirect_key = *redirect_key };
    }
    let ptr = REDIRECT_TRACK
        .get_ptr_mut(redirect_key)
        .ok_or(IDENTITY_MISMATCH)?;
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.incarnation == snapshot.incarnation
        && current.decision_token == snapshot.decision_token;
    let refreshed =
        owned && now.saturating_sub(current.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS;
    let renew_client = refreshed && current.from_wan == 0;
    if refreshed {
        current.last_seen_ns = now;
        if renew_client && let Some(scratch) = scratch {
            unsafe { copy_payload(&raw mut (*scratch).redirect, current) };
        }
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    if renew_client && let Some(scratch) = scratch {
        publish_client_reply(key, unsafe { &mut *scratch });
    }
    if owned {
        Ok(())
    } else {
        Err(IDENTITY_MISMATCH)
    }
}

/// A cached hit refreshes only the captured owner; a miss needs publication.
#[inline(always)]
pub fn refresh_redirect(
    key: &TuplesKey,
    redirect_key: &RedirectTuple,
    token: u32,
    incarnation: u64,
    now: u64,
) -> Result<bool, i32> {
    if tuple_retiring(key) {
        return Err(IDENTITY_MISMATCH);
    }
    if stateless_publication(key, token, incarnation) {
        return Ok(false);
    }
    let Some(snapshot) = redirect_identity(redirect_key) else {
        return Ok(false);
    };
    if snapshot.decision_token != token || snapshot.incarnation != incarnation {
        return Err(IDENTITY_MISMATCH);
    }
    touch_redirect(key, redirect_key, &snapshot, now)?;
    Ok(true)
}

#[inline(always)]
pub fn reverse_redirect(
    key: &TuplesKey,
    redirect_key: &RedirectTuple,
    now: u64,
) -> Result<Option<RedirectEntry>, i32> {
    if tuple_retiring(key) {
        return Err(IDENTITY_MISMATCH);
    }
    let Some(snapshot) = redirect_snapshot(redirect_key) else {
        return Ok(None);
    };
    let identity = AuxiliaryIdentity {
        incarnation: snapshot.incarnation,
        last_seen_ns: snapshot.last_seen_ns,
        decision_token: snapshot.decision_token,
    };
    touch_redirect(key, redirect_key, &identity, now)?;
    Ok(Some(snapshot))
}

#[inline(always)]
pub fn refresh_handoff(
    key: &TuplesKey,
    token: u32,
    incarnation: u64,
    now: u64,
) -> Result<bool, i32> {
    if tuple_retiring(key) {
        return Err(IDENTITY_MISMATCH);
    }
    if stateless_publication(key, token, incarnation) {
        return Ok(false);
    }
    let Some(snapshot) = handoff_identity(key) else {
        return Ok(false);
    };
    if snapshot.decision_token != token
        || snapshot.incarnation != incarnation
        || auxiliary_expired(
            key,
            snapshot.incarnation,
            now.saturating_sub(snapshot.last_seen_ns),
            true,
        )
    {
        return Err(IDENTITY_MISMATCH);
    }
    if now.saturating_sub(snapshot.last_seen_ns) < AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        return Ok(true);
    }
    let ptr = ROUTING_HANDOFF_MAP
        .get_ptr_mut(key)
        .ok_or(IDENTITY_MISMATCH)?;
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.incarnation == snapshot.incarnation
        && current.result.decision_token == snapshot.decision_token;
    if owned && now.saturating_sub(current.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        current.last_seen_ns = now;
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    if owned {
        Ok(true)
    } else {
        Err(IDENTITY_MISMATCH)
    }
}

#[inline(always)]
fn syn_publisher(key: &TuplesKey, incarnation: u64) -> bool {
    key.l4proto == crate::transport::IPPROTO_TCP
        && incarnation != 0
        && TCP_PUBLISHING
            .get_ptr(key)
            .is_some_and(|owner| unsafe { *owner } == incarnation)
}

/// Fresh SYN and stateless per-packet authority publish payloads without replacing elements.
#[inline(always)]
pub fn publish_redirect(
    key: &TuplesKey,
    scratch: &mut UdpDecisionScratch,
    replace: bool,
) -> Result<(), i32> {
    if tuple_retiring(key) {
        return Err(IDENTITY_MISMATCH);
    }
    if stateless_publication(
        key,
        scratch.redirect.decision_token,
        scratch.redirect.incarnation,
    ) && let Some(ptr) = REDIRECT_TRACK.get_ptr_mut(&scratch.redirect_key)
    {
        unsafe { bpf_spin_lock(&mut (*ptr).lock) };
        let current = unsafe { &mut (*ptr).value };
        let owned = current.incarnation == 0 && current.decision_token == 0;
        let mut refreshed = false;
        if owned {
            refreshed = scratch
                .redirect
                .last_seen_ns
                .saturating_sub(current.last_seen_ns)
                >= AUXILIARY_MAP_REFRESH_INTERVAL_NS;
            if !refreshed {
                scratch.redirect.last_seen_ns = current.last_seen_ns;
            }
            unsafe { copy_payload(current, &scratch.redirect) };
        }
        unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
        if !owned {
            return Err(IDENTITY_MISMATCH);
        }
        if refreshed {
            publish_client_reply(key, scratch);
        }
        return Ok(());
    }
    if replace {
        let publisher = syn_publisher(key, scratch.redirect.incarnation);
        if !publisher {
            return Err(IDENTITY_MISMATCH);
        }
        if let Some(snapshot) = redirect_identity(&scratch.redirect_key) {
            let ptr = REDIRECT_TRACK
                .get_ptr_mut(&scratch.redirect_key)
                .ok_or(IDENTITY_MISMATCH)?;
            unsafe { bpf_spin_lock(&mut (*ptr).lock) };
            let current = unsafe { &mut (*ptr).value };
            let owned = publisher
                && current.incarnation == snapshot.incarnation
                && current.decision_token == snapshot.decision_token;
            if owned {
                unsafe { copy_payload(current, &scratch.redirect) };
            }
            unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
            return if owned {
                Ok(())
            } else {
                Err(IDENTITY_MISMATCH)
            };
        }
    }
    scratch.redirect_header = 0;
    // Opaque zero headers keep nested spin-lock types out of scratch-map BTF.
    let input = unsafe {
        &*core::ptr::from_ref(&scratch.redirect_header).cast::<FlowMapValue<RedirectEntry>>()
    };
    REDIRECT_TRACK
        .insert(&scratch.redirect_key, input, BPF_NOEXIST as u64)
        .map_err(|_| {
            increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
            -1
        })?;
    publish_client_reply(key, scratch);
    Ok(())
}

#[inline(always)]
pub fn publish_handoff(
    key: &TuplesKey,
    scratch: &mut UdpDecisionScratch,
    replace: bool,
) -> Result<(), i32> {
    if tuple_retiring(key) {
        return Err(IDENTITY_MISMATCH);
    }
    if stateless_publication(
        key,
        scratch.handoff.result.decision_token,
        scratch.handoff.incarnation,
    ) && let Some(ptr) = ROUTING_HANDOFF_MAP.get_ptr_mut(key)
    {
        unsafe { bpf_spin_lock(&mut (*ptr).lock) };
        let current = unsafe { &mut (*ptr).value };
        let owned = current.incarnation == 0 && current.result.decision_token == 0;
        if owned {
            unsafe { copy_payload(current, &scratch.handoff) };
        }
        unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
        return if owned {
            Ok(())
        } else {
            Err(IDENTITY_MISMATCH)
        };
    }
    if replace {
        let publisher = syn_publisher(key, scratch.handoff.incarnation);
        if !publisher {
            return Err(IDENTITY_MISMATCH);
        }
        if let Some(snapshot) = handoff_identity(key) {
            let ptr = ROUTING_HANDOFF_MAP
                .get_ptr_mut(key)
                .ok_or(IDENTITY_MISMATCH)?;
            unsafe { bpf_spin_lock(&mut (*ptr).lock) };
            let current = unsafe { &mut (*ptr).value };
            let owned = publisher
                && current.incarnation == snapshot.incarnation
                && current.result.decision_token == snapshot.decision_token;
            if owned {
                unsafe { copy_payload(current, &scratch.handoff) };
            }
            unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
            return if owned {
                Ok(())
            } else {
                Err(IDENTITY_MISMATCH)
            };
        }
    }
    scratch.handoff_header = 0;
    let input = unsafe {
        &*core::ptr::from_ref(&scratch.handoff_header).cast::<FlowMapValue<RoutingHandoffEntry>>()
    };
    ROUTING_HANDOFF_MAP
        .insert(key, input, BPF_NOEXIST as u64)
        .map_err(|_| {
            increment_bpf_stat(BpfStatsKey::RoutingHandoffInsertFailure);
            -1
        })
}

/// Prepare a packet for redirection to the control plane.
///
/// Stores the original source/dest MAC in `REDIRECT_TRACK` so the dae0 ingress
/// handler can reverse the tuple later.  For L3-only packets (no Ethernet header)
/// a new Ethernet header is prepended.  `outbound` is recorded in the entry so
/// `dae0_ingress` can attribute reply traffic in `OUTBOUND_STATS`.
///
/// Ordinary owners refresh lazily; SYN and stateless payloads are published
/// in place under the native value lock.
///
/// Returns 0 on success, non-zero on failure.
#[inline(always)]
pub fn prep_redirect_to_control_plane(
    ctx: &TcContext,
    link_h_len: u32,
    tuples: &Tuples,
    ethh: &EthHdr,
    from_wan: u8,
    refresh_if_stale: bool,
    outbound: u8,
    decision_token: u32,
    incarnation: u64,
) -> i32 {
    let param = PARAM.load();

    // bpf_redirect_peer is NOT supported in egress direction;
    // only use for ingress (from_wan == 0).
    let use_redirect_peer = param.use_redirect_peer != 0 && from_wan == 0;

    if !use_redirect_peer {
        if link_h_len == 0 {
            let l3proto = ctx.skb.protocol() as u16;
            let zero_mac: [u8; 6] = [0; 6];
            let ret =
                unsafe { bpf_skb_change_head(ctx.skb.skb, mem::size_of::<EthHdr>() as u32, 0) };
            if ret != 0 {
                return ret as i32;
            }
            unsafe {
                bpf_skb_store_bytes(
                    ctx.skb.skb,
                    12, // offsetof(struct ethhdr, h_proto)
                    &l3proto as *const u16 as *const _,
                    mem::size_of::<u16>() as u32,
                    0,
                );
                bpf_skb_store_bytes(
                    ctx.skb.skb,
                    6, // offsetof(struct ethhdr, h_source)
                    zero_mac.as_ptr() as *const _,
                    6,
                    0,
                );
            }
        }

        unsafe {
            bpf_skb_store_bytes(
                ctx.skb.skb,
                0, // offsetof(struct ethhdr, h_dest)
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
        }
    }

    let redirect_tuple = RedirectTuple::from_tuples(&tuples.five);
    let now = unsafe { bpf_ktime_get_ns() };
    if refresh_if_stale {
        match crate::auxiliary::refresh_redirect(
            &tuples.five,
            &redirect_tuple,
            decision_token,
            incarnation,
            now,
        ) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(error) => return error,
        }
    }

    let mut zero = 0u32;
    unsafe { core::ptr::write_volatile(&mut zero, 0) };
    let Some(scratch) =
        UDP_DECISION_SCRATCH_MAP.get_ptr_mut(unsafe { core::ptr::read_volatile(&zero) })
    else {
        increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
        return -1;
    };
    let scratch = unsafe { &mut *scratch };
    scratch.redirect_key = redirect_tuple;
    let redirect_entry = &mut scratch.redirect;
    unsafe { core::ptr::write_bytes(redirect_entry, 0, 1) };

    redirect_entry.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    redirect_entry.from_wan = from_wan;
    redirect_entry.last_seen_ns = now;
    // Record the final outbound so dae0_ingress can attribute replies.
    redirect_entry.outbound = outbound;
    redirect_entry.decision_token = decision_token;
    redirect_entry.incarnation = incarnation;

    if link_h_len == ETH_HLEN {
        redirect_entry.smac.copy_from_slice(&ethh.src_addr);
        redirect_entry.dmac.copy_from_slice(&ethh.dst_addr);
    }
    // else: L3-only — MACs stay zero.

    match crate::auxiliary::publish_redirect(&tuples.five, scratch, !refresh_if_stale) {
        Ok(()) => 0,
        Err(error) => error,
    }
}
