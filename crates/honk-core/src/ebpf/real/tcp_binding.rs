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

pub(super) struct PreparedBinding {
    pub offsets: TcpBindingOffsets,
    btf: Btf,
}

pub(super) struct TcpBindings {
    _entries: Vec<FEntryLink>,
    _child: FExitLink,
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

fn offsets(data: &[u8]) -> Result<TcpBindingOffsets> {
    let btf = OffsetBtf::parse(data).ok_or_else(|| anyhow!("invalid running-kernel BTF"))?;
    for name in ["tcp_v4_route_req", "tcp_v6_route_req"] {
        // Both 6.12 and current kernels pass tw_isn, not a pointer or a boolean.
        validate_signature(
            &btf,
            name,
            &["sock", "sk_buff", "flowi", "request_sock", "u32"],
            Some("dst_entry"),
        )?;
    }
    validate_signature(
        &btf,
        "tcp_create_openreq_child",
        &["sock", "request_sock", "sk_buff"],
        Some("sock"),
    )?;
    for name in ["tcp_v4_reqsk_destructor", "tcp_v6_reqsk_destructor"] {
        validate_signature(&btf, name, &["request_sock"], None)?;
    }
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
        common == 0 && request_common == 0,
        "unsupported socket common-prefix layout"
    );
    let socket_cookie = member("sock_common", "skc_cookie", 8)?;
    Ok(TcpBindingOffsets {
        skb_head: member("sk_buff", "head", 8)?,
        skb_network_header: member("sk_buff", "network_header", 2)?,
        skb_transport_header: member("sk_buff", "transport_header", 2)?,
        skb_tail: member("sk_buff", "tail", 4)?,
        skb_mark: member("sk_buff", "mark", 4)?,
        skb_priority: member("sk_buff", "priority", 4)?,
        socket_cookie,
    })
}

pub(super) fn prepare() -> Result<PreparedBinding> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .context("reading required running-kernel TCP proof BTF")?;
    Ok(PreparedBinding {
        offsets: offsets(&data)?,
        btf: Btf::parse(&data, Default::default())
            .context("parsing required TCP proof attachment BTF")?,
    })
}

impl PreparedBinding {
    pub(super) fn attach(self, bpf: &mut Ebpf) -> Result<TcpBindings> {
        let mut entries = Vec::with_capacity(4);
        for (name, target) in [
            ("honk_tcp_v4_route_req", "tcp_v4_route_req"),
            ("honk_tcp_v6_route_req", "tcp_v6_route_req"),
            ("honk_tcp_v4_reqsk_destructor", "tcp_v4_reqsk_destructor"),
            ("honk_tcp_v6_reqsk_destructor", "tcp_v6_reqsk_destructor"),
        ] {
            let program: &mut FEntry = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("required TCP proof program {name} missing"))?
                .try_into()?;
            program
                .load(target, &self.btf)
                .with_context(|| format!("loading required TCP proof {name}"))?;
            let link = program
                .attach()
                .with_context(|| format!("attaching required TCP proof {name}"))?;
            entries.push(program.take_link(link)?);
        }
        let program: &mut FExit = bpf
            .program_mut("honk_tcp_create_openreq_child")
            .ok_or_else(|| anyhow!("required TCP child proof program missing"))?
            .try_into()?;
        program
            .load("tcp_create_openreq_child", &self.btf)
            .context("loading required TCP child proof")?;
        let link = program
            .attach()
            .context("attaching required TCP child proof")?;
        let child = program.take_link(link)?;
        Ok(TcpBindings {
            _entries: entries,
            _child: child,
        })
    }
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
