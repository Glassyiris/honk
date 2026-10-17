//! Required running-kernel TCP request/child proof attachment and FD storage access.

use std::os::fd::BorrowedFd;

use anyhow::{Context, Result, anyhow, ensure};
use aya::{
    Btf, Ebpf,
    maps::SkStorage,
    programs::{FEntry, FExit, fentry::FEntryLink, fexit::FExitLink},
};
use honk_ebpf_common::{
    redirect_need::{TCP_BINDING_LISTENER, TcpSocketBinding},
    tcp_binding::TcpBindingOffsets,
};

use super::btf::Btf as OffsetBtf;

pub(super) struct TcpBindings {
    _entries: [FEntryLink; 2],
    _child: FExitLink,
    ipv6: Ipv6Bindings,
}

enum Ipv6Bindings {
    Pending(Btf),
    Attached { _links: [FEntryLink; 2] },
    Unavailable(anyhow::Error),
}

impl TcpBindings {
    pub(super) fn attach_ipv6(&mut self, bpf: &mut Ebpf) -> Result<()> {
        let btf = match &self.ipv6 {
            Ipv6Bindings::Attached { .. } => return Ok(()),
            Ipv6Bindings::Pending(btf) => btf,
            Ipv6Bindings::Unavailable(error) => anyhow::bail!(
                "IPv6 TCP listener requires tcp_v6_route_req and tcp_v6_reqsk_destructor proof: {error:#}; use a kernel with built-in IPv6 (CONFIG_IPV6=y), or boot without an IPv6 stack (ipv6.disable=1); modular IPv6 proof is unsupported"
            ),
        };
        let links = [
            attach_entry(bpf, btf, "honk_tcp_v6_route_req", "tcp_v6_route_req")?,
            attach_entry(
                bpf,
                btf,
                "honk_tcp_v6_reqsk_destructor",
                "tcp_v6_reqsk_destructor",
            )?,
        ];
        self.ipv6 = Ipv6Bindings::Attached { _links: links };
        Ok(())
    }
}

/// An exact native lifetime pin; clones only the backend's shared map handle.
pub struct TcpKernelPin {
    map: std::sync::Arc<aya::maps::MapData>,
    incarnation: Option<u64>,
    errors: crate::ebpf::TcpPinErrorSink,
}

impl TcpKernelPin {
    pub(super) fn retain(
        map: &std::sync::Arc<aya::maps::MapData>,
        incarnation: u64,
        errors: crate::ebpf::TcpPinErrorSink,
    ) -> Result<Self> {
        ensure!(
            incarnation != 0 && incarnation <= honk_ebpf_common::conn::FLOW_INCARNATION_MAX,
            "invalid TCP lifetime identity"
        );
        super::syscall::insert_tcp_live_pin(map, incarnation)?;
        Ok(Self {
            map: std::sync::Arc::clone(map),
            incarnation: Some(incarnation),
            errors,
        })
    }

    fn release_once(&mut self) -> Result<()> {
        if let Some(incarnation) = self.incarnation.take() {
            super::syscall::remove_tcp_live_pin(&self.map, incarnation)?;
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<()> {
        self.release_once()
    }
}

impl Drop for TcpKernelPin {
    fn drop(&mut self) {
        if let Err(error) = self.release_once() {
            let sink = self.errors.lock();
            match sink.as_ref() {
                Some(sender) => {
                    if let Err(error) = sender.send(error) {
                        tracing::error!(error = %error.0, "TCP pin release error channel closed");
                    }
                }
                None => tracing::error!(%error, "TCP pin release error channel unavailable"),
            }
        }
    }
}

pub(super) fn take_live_pins(bpf: &mut Ebpf) -> Result<std::sync::Arc<aya::maps::MapData>> {
    match bpf.take_map("TCP_LIVE_PINS") {
        Some(aya::maps::Map::HashMap(map)) => Ok(std::sync::Arc::new(map)),
        _ => anyhow::bail!("TCP_LIVE_PINS unavailable or has an incompatible map type"),
    }
}

fn validate_signature(
    btf: &OffsetBtf<'_>,
    name: &str,
    args: &[&str],
    result: Option<&str>,
) -> Result<()> {
    let prototype = btf
        .function_proto(name)
        .ok_or_else(|| anyhow!("required TCP proof function {name} missing"))?;
    ensure!(
        btf.u32_at(prototype + 4).map(|info| info & 0xffff) == Some(args.len() as u32),
        "unsupported TCP proof argument count for {name}"
    );
    for (index, expected) in args.iter().enumerate() {
        let id = btf
            .u32_at(prototype + 16 + index * 8)
            .ok_or_else(|| anyhow!("truncated TCP proof prototype {name}"))?;
        let valid = if *expected == "u32" {
            btf.unsigned_integer_width(id, 4)
        } else {
            btf.pointer_to(id, expected)
        };
        ensure!(
            valid,
            "unsupported TCP proof argument {index} for {name}: expected {expected}"
        );
    }
    let result_id = btf
        .u32_at(prototype + 8)
        .ok_or_else(|| anyhow!("missing return type for {name}"))?;
    ensure!(
        match result {
            Some(expected) => btf.pointer_to(result_id, expected),
            None => result_id == 0,
        },
        "unsupported TCP proof return type for {name}"
    );
    Ok(())
}

pub(super) fn offsets(data: &[u8]) -> Result<TcpBindingOffsets> {
    let btf = OffsetBtf::parse(data).ok_or_else(|| anyhow!("invalid running-kernel BTF"))?;
    // Both 6.12 and current kernels pass tw_isn, not a pointer or a boolean.
    validate_signature(
        &btf,
        "tcp_v4_route_req",
        &["sock", "sk_buff", "flowi", "request_sock", "u32"],
        Some("dst_entry"),
    )?;
    validate_signature(
        &btf,
        "tcp_create_openreq_child",
        &["sock", "request_sock", "sk_buff"],
        Some("sock"),
    )?;
    validate_signature(&btf, "tcp_v4_reqsk_destructor", &["request_sock"], None)?;
    let member = |structure, field, width| {
        btf.sized_member_offset(structure, field, width)
            .ok_or_else(|| {
                anyhow!("unsupported running-kernel TCP proof field {structure}.{field}")
            })
    };
    let common = btf
        .member_offset("sock", "__sk_common")
        .ok_or_else(|| anyhow!("sock.__sk_common missing"))?;
    let request_common = btf
        .member_offset("request_sock", "__req_common")
        .ok_or_else(|| anyhow!("request_sock.__req_common missing"))?;
    ensure!(
        common == 0
            && request_common == 0
            && btf.member_offset("tcp_request_sock", "req") == Some(0)
            && btf.member_offset("inet_request_sock", "req") == Some(0),
        "unsupported socket common-prefix layout"
    );
    let socket_cookie = member("sock_common", "skc_cookie", 8)?;
    let request_rcv_isn = member("tcp_request_sock", "rcv_isn", 4)?;
    let capacity = core::mem::size_of::<honk_ebpf_common::KernelRouteWitness>() as u32;
    ensure!(
        socket_cookie <= capacity - 8 && request_rcv_isn <= capacity - 4,
        "running-kernel TCP request fields exceed the {capacity}-byte prefix scratch"
    );
    Ok(TcpBindingOffsets {
        skb_head: member("sk_buff", "head", 8)?,
        skb_network_header: member("sk_buff", "network_header", 2)?,
        skb_transport_header: member("sk_buff", "transport_header", 2)?,
        skb_tail: member("sk_buff", "tail", 4)?,
        skb_mark: member("sk_buff", "mark", 4)?,
        skb_priority: member("sk_buff", "priority", 4)?,
        socket_cookie,
        request_rcv_isn,
    })
}

pub(super) fn ipv6_proof(data: &[u8]) -> Result<()> {
    let btf = OffsetBtf::parse(data).ok_or_else(|| anyhow!("invalid running-kernel BTF"))?;
    validate_signature(
        &btf,
        "tcp_v6_route_req",
        &["sock", "sk_buff", "flowi", "request_sock", "u32"],
        Some("dst_entry"),
    )?;
    validate_signature(&btf, "tcp_v6_reqsk_destructor", &["request_sock"], None)
}

fn attach_entry(bpf: &mut Ebpf, btf: &Btf, name: &str, target: &str) -> Result<FEntryLink> {
    let program: &mut FEntry = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("required TCP proof program {name} missing"))?
        .try_into()?;
    program
        .load(target, btf)
        .with_context(|| format!("loading required TCP proof {name}"))?;
    let link = program
        .attach()
        .with_context(|| format!("attaching required TCP proof {name}"))?;
    Ok(program.take_link(link)?)
}

pub(super) fn attach(bpf: &mut Ebpf, btf: Btf, ipv6: Result<()>) -> Result<TcpBindings> {
    let entries = [
        attach_entry(bpf, &btf, "honk_tcp_v4_route_req", "tcp_v4_route_req")?,
        attach_entry(
            bpf,
            &btf,
            "honk_tcp_v4_reqsk_destructor",
            "tcp_v4_reqsk_destructor",
        )?,
    ];
    let program: &mut FExit = bpf
        .program_mut("honk_tcp_create_openreq_child")
        .ok_or_else(|| anyhow!("required TCP child proof program missing"))?
        .try_into()?;
    program
        .load("tcp_create_openreq_child", &btf)
        .context("loading required TCP child proof")?;
    let link = program
        .attach()
        .context("attaching required TCP child proof")?;
    let child = program.take_link(link)?;
    Ok(TcpBindings {
        _entries: entries,
        _child: child,
        ipv6: match ipv6 {
            Ok(()) => Ipv6Bindings::Pending(btf),
            Err(error) => Ipv6Bindings::Unavailable(error),
        },
    })
}

pub(super) fn publish_listener(bpf: &mut Ebpf, fd: BorrowedFd<'_>) -> Result<()> {
    let mut storage = SkStorage::<_, TcpSocketBinding>::try_from(
        bpf.map_mut("TCP_SOCKET_BINDING")
            .ok_or_else(|| anyhow!("required TCP_SOCKET_BINDING missing"))?,
    )?;
    storage
        .insert(
            &fd,
            TcpSocketBinding {
                kind: TCP_BINDING_LISTENER,
                ..Default::default()
            },
            0,
        )
        .context("publishing listener socket ownership")?;
    Ok(())
}

pub(super) fn lookup(bpf: &Ebpf, fd: BorrowedFd<'_>) -> Result<TcpSocketBinding> {
    let storage = SkStorage::<_, TcpSocketBinding>::try_from(
        bpf.map("TCP_SOCKET_BINDING")
            .ok_or_else(|| anyhow!("required TCP_SOCKET_BINDING missing"))?,
    )?;
    storage
        .get(&fd, 0)
        .context("reading accepted socket ownership")
}

pub(super) fn adopt(
    backend: &super::RealEbpfBackend,
    fd: BorrowedFd<'_>,
    tuples: &honk_ebpf_common::TuplesKey,
    errors: crate::ebpf::TcpPinErrorSink,
) -> Result<crate::ebpf::TcpAdoption> {
    use crate::ebpf::EbpfBackend;
    ensure!(
        !backend.retirement_failed,
        "retirement ownership is unresolved"
    );
    let binding = lookup(backend.bpf()?, fd)?;
    let current = backend
        .conn_state_lookup(tuples)?
        .ok_or_else(|| anyhow!("accepted TCP flow has no conn-state: {tuples:?}"))?;
    ensure!(
        binding.kind == honk_ebpf_common::redirect_need::TCP_BINDING_CHILD
            && crate::ebpf::tuple_matches(&binding.tuples, tuples)
            && binding.handoff.incarnation != 0
            && binding.handoff.incarnation == current.incarnation,
        "accepted TCP child is unproven or superseded"
    );
    let handoff = backend
        .routing_handoff_lookup(tuples)?
        .ok_or_else(|| anyhow!("accepted TCP child has no current handoff"))?;
    let redirect = backend
        .redirect_track_lookup(&honk_ebpf_common::RedirectTuple::from_tuples(tuples))?
        .ok_or_else(|| anyhow!("accepted TCP child has no current redirect"))?;
    ensure!(
        handoff.incarnation == current.incarnation && redirect.incarnation == current.incarnation,
        "accepted TCP child auxiliary ownership is superseded"
    );
    Ok(crate::ebpf::TcpAdoption {
        incarnation: current.incarnation,
        handoff: Some(binding.handoff),
        pin: crate::ebpf::TcpPin::Kernel(TcpKernelPin::retain(
            &backend.tcp_live_pins,
            current.incarnation,
            errors,
        )?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(last_argument: u32, argument_count: u32) -> Vec<u8> {
        let strings =
            b"\0sock\0sk_buff\0flowi\0request_sock\0dst_entry\0unsigned int\0tcp_v4_route_req\0";
        let mut types = Vec::new();
        let mut word = |value: u32| types.extend_from_slice(&value.to_le_bytes());
        // Five empty structs (IDs 1..5), their pointers (IDs 6..10), u32 (11), prototype (12), function (13).
        for name in [1, 6, 14, 20, 33] {
            word(name);
            word(4 << 24);
            word(8);
        }
        for target in 1..=5 {
            word(0);
            word(2 << 24);
            word(target);
        }
        word(43);
        word(1 << 24);
        word(4);
        word(32);
        word(0);
        word((13 << 24) | argument_count);
        word(10);
        for id in [6, 7, 8, 9, last_argument]
            .into_iter()
            .take(argument_count as usize)
        {
            word(0);
            word(id);
        }
        word(56);
        word(12 << 24);
        word(12);
        let mut data = Vec::new();
        data.extend_from_slice(&[0x9f, 0xeb, 1, 0]);
        for value in [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(&types);
        data.extend_from_slice(strings);
        data
    }

    #[test]
    fn route_signature_rejects_pointer_tw_isn_and_shifted_request() {
        let arguments = ["sock", "sk_buff", "flowi", "request_sock", "u32"];
        let correct = fixture(11, 5);
        assert!(
            validate_signature(
                &OffsetBtf::parse(&correct).unwrap(),
                "tcp_v4_route_req",
                &arguments,
                Some("dst_entry")
            )
            .is_ok()
        );
        let pointer = fixture(9, 5);
        assert!(
            validate_signature(
                &OffsetBtf::parse(&pointer).unwrap(),
                "tcp_v4_route_req",
                &arguments,
                Some("dst_entry")
            )
            .is_err()
        );
        let mut signed = fixture(11, 5);
        let encoding = 24 + (5 + 5) * 12 + 12;
        signed[encoding..encoding + 4].copy_from_slice(&((1u32 << 24) | 32).to_le_bytes());
        assert!(
            validate_signature(
                &OffsetBtf::parse(&signed).unwrap(),
                "tcp_v4_route_req",
                &arguments,
                Some("dst_entry")
            )
            .is_err()
        );
        let missing = fixture(11, 4);
        assert!(
            validate_signature(
                &OffsetBtf::parse(&missing).unwrap(),
                "tcp_v4_route_req",
                &arguments,
                Some("dst_entry")
            )
            .is_err()
        );
        assert!(
            validate_signature(
                &OffsetBtf::parse(&correct).unwrap(),
                "tcp_v4_route_req",
                &["sock", "sk_buff", "request_sock", "flowi", "u32"],
                Some("dst_entry")
            )
            .is_err()
        );
        assert!(
            validate_signature(
                &OffsetBtf::parse(&correct).unwrap(),
                "tcp_v4_route_req",
                &arguments,
                Some("sock")
            )
            .is_err()
        );
        assert!(
            validate_signature(
                &OffsetBtf::parse(&correct).unwrap(),
                "missing_function",
                &arguments,
                Some("dst_entry")
            )
            .is_err()
        );
    }
}
