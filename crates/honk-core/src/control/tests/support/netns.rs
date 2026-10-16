use super::super::{fresh_test_netns, wait_for_test_address};
use super::udp_test_config;
use aya::maps::{Map, MapData};
use honk_config::node::Group;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use std::mem::size_of;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;

/// Enters private net/mount namespaces and wires the LAN and WAN veth edges.
pub(in crate::control::tests) fn build_lab(
    lan_ip: IpAddr,
    wan_ip: IpAddr,
) -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let expected_kernel = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
    anyhow::ensure!(
        std::env::var_os("HONK_CI_VM_LANE").is_some()
            && !expected_kernel.is_empty()
            && std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim() == expected_kernel,
        "root-cgroup datapath fixtures require the disposable kernel VM gate"
    );
    unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )?;
    // Mount isolation does not isolate root-cgroup BPF attachments. Only the
    // disposable VM above may remount its hierarchy for real identity capture.
    for line in std::fs::read_to_string("/proc/thread-self/mounts")?.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (_, target, filesystem) = (fields.next(), fields.next(), fields.next());
        if filesystem == Some("cgroup2") {
            umount2(target.expect("cgroup mount target"), MntFlags::MNT_DETACH)?;
        }
    }
    anyhow::ensure!(
        !std::fs::read_to_string("/proc/thread-self/mounts")?
            .lines()
            .any(|line| {
                matches!(
                    line.split_ascii_whitespace().nth(2),
                    Some("cgroup" | "cgroup2")
                )
            }),
        "isolated datapath fixture must not expose a host cgroup filesystem"
    );
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    // The backend reads interface MACs through sysfs; it must see this netns.
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some("bpf"),
        "/sys/fs/bpf",
        Some("bpf"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    let client_netns = fresh_test_netns();
    let server_netns = fresh_test_netns();
    let mut netlink = crate::netlink::NlSock::new()?;
    let (lo, _) = netlink.get_link("lo")?;
    netlink.set_link_up(lo, true)?;
    for (host, edge, namespace, ip) in [
        ("honk-lan0", "honk-c0", &client_netns, lan_ip),
        ("honk-wan0", "honk-s0", &server_netns, wan_ip),
    ] {
        netlink.add_veth_pair(host, edge)?;
        let (edge_index, _) = netlink.get_link(edge)?;
        netlink.set_link_netns_fd(edge_index, namespace)?;
        let (host_index, _) = netlink.get_link(host)?;
        netlink.set_link_up(host_index, true)?;
        add_address(&mut netlink, host_index, host, ip)?;
    }
    Ok((client_netns, server_netns))
}

/// Real-datapath config whose only route is the group holding `node`.
pub(in crate::control::tests) fn lab_config(node: &honk_config::node::Node) -> honk_config::Config {
    let group = Group {
        name: "fullcone".into(),
        nodes: vec![node.id],
        ..Default::default()
    };
    let mut config = udp_test_config("fullcone", vec![node.clone()], vec![group]);
    config.ensure_builtin_nodes();
    config.global.lan_interface = vec!["honk-lan0".into()];
    config.global.wan_interface = vec!["honk-wan0".into()];
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    config.global.store_subscribe = false;
    config.experimental.cache_file.enabled = Some(false);
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns.clear();
    config.dns.bind.clear();
    config
}

pub(in crate::control::tests) fn add_address(
    netlink: &mut crate::netlink::NlSock,
    index: u32,
    name: &str,
    ip: IpAddr,
) -> anyhow::Result<()> {
    match ip {
        IpAddr::V4(ip) => netlink.addr_op(true, index, libc::AF_INET as u8, &ip.octets(), 24)?,
        IpAddr::V6(ip) => {
            std::fs::write("/proc/sys/net/ipv6/conf/all/accept_dad", "0")?;
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0")?;
            netlink.addr_op(true, index, libc::AF_INET6 as u8, &ip.octets(), 64)?;
        }
    }
    wait_for_test_address(ip);
    Ok(())
}

pub(in crate::control::tests) fn pinned_map(root: &Path, name: &str) -> anyhow::Result<Map> {
    Ok(Map::from_map_data(MapData::from_pin(root.join(name))?)?)
}

/// Bucket-protected copies for external readers that cannot exclude native
/// request destruction or userspace tuple retirement. Never fall back to
/// GET_NEXT_KEY plus singleton LOOKUP_ELEM, even for immutable request values.
pub(in crate::control::tests) fn pinned_hash_snapshot<K: aya::Pod, V: aya::Pod>(
    root: &Path,
    name: &str,
    elem_flags: u64,
) -> anyhow::Result<Vec<(K, V)>> {
    const CHUNK: usize = 128;
    let data = MapData::from_pin(root.join(name))?;
    let info = data.info()?;
    anyhow::ensure!(
        info.map_type()? == aya::maps::MapType::Hash
            && info.key_size() as usize == size_of::<K>()
            && info.value_size() as usize == size_of::<V>(),
        "unexpected pinned hash layout for {name}"
    );
    // Hash cursors are opaque bucket positions; the kernel may write only four
    // bytes even when the map key is larger. Initialize every byte up front.
    let mut cursor = vec![0u8; size_of::<K>().max(4)];
    let mut previous = cursor.clone();
    let mut has_previous = false;
    let mut keys = vec![std::mem::MaybeUninit::<K>::uninit(); CHUNK];
    let mut values = vec![std::mem::MaybeUninit::<V>::uninit(); CHUNK];
    let mut snapshot = Vec::new();
    loop {
        let mut attr: aya_obj::generated::bpf_attr = unsafe { std::mem::zeroed() };
        attr.batch.map_fd = data.fd().as_fd().as_raw_fd() as u32;
        attr.batch.in_batch = if has_previous {
            previous.as_ptr() as u64
        } else {
            0
        };
        attr.batch.out_batch = cursor.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = CHUNK as u32;
        attr.batch.elem_flags = elem_flags;
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                aya_obj::generated::bpf_cmd::BPF_MAP_LOOKUP_BATCH as libc::c_long,
                &mut attr as *mut aya_obj::generated::bpf_attr,
                size_of::<aya_obj::generated::bpf_attr>(),
            )
        };
        let error = (result < 0).then(std::io::Error::last_os_error);
        let terminal = error
            .as_ref()
            .is_some_and(|error| error.raw_os_error() == Some(libc::ENOENT));
        if let Some(error) = error.filter(|_| !terminal) {
            return Err(anyhow::Error::new(error).context(format!(
                "safe pinned snapshot of {name} requires BPF_MAP_LOOKUP_BATCH (elem_flags={elem_flags})"
            )));
        }
        let count = unsafe { attr.batch.count } as usize;
        anyhow::ensure!(count <= CHUNK, "invalid batch count for {name}: {count}");
        for index in 0..count {
            // Success/ENOENT initializes exactly count elements; other errors,
            // including EFAULT, return above without touching output storage.
            snapshot.push(unsafe { (keys[index].assume_init(), values[index].assume_init()) });
        }
        if terminal {
            return Ok(snapshot);
        }
        anyhow::ensure!(count != 0, "empty nonterminal batch for {name}");
        previous.copy_from_slice(&cursor);
        has_previous = true;
    }
}
