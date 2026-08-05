use super::*;

impl RealEbpfBackend {
    pub async fn load(
        obj: &[u8],
        pin_root: &Path,
        tproxy_port: u16,
        tproxy_mark: u32,
        lan_ifname: Option<&str>,
        wan_ifname: &str,
        single_homed: bool,
    ) -> anyhow::Result<Self> {
        info!("Loading eBPF programs ({} bytes)", obj.len());
        let dae0_ifindex = std::fs::read_to_string("/sys/class/net/dae0/ifindex")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let dae0peer_ifindex = std::fs::read_to_string("/sys/class/net/dae0peer/ifindex")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let dae0peer_mac = std::fs::read_to_string("/sys/class/net/dae0peer/address")
            .ok()
            .map(|s| {
                let mut mac = [0u8; 6];
                for (i, b) in s.trim().split(':').enumerate().take(6) {
                    mac[i] = u8::from_str_radix(b, 16).unwrap_or(0);
                }
                mac
            })
            .unwrap_or([0u8; 6]);
        let ebpf_lan_ifname = lan_ifname
            .map(|name| Self::bridge_interface(name).unwrap_or_else(|| name.to_string()))
            .unwrap_or_default();
        // Determine the actual WAN interface (bond master if the configured
        // interface is a slave) so the eBPF datapath can identify locally-
        // generated packets that the bonding driver forwards onto the master.
        let ebpf_wan_ifname = if single_homed {
            ebpf_lan_ifname.clone()
        } else {
            Self::bridge_interface(wan_ifname).unwrap_or_else(|| wan_ifname.to_string())
        };
        let wan_ifindex = Self::iface_ifindex(&ebpf_wan_ifname);
        let local_ifname = if ebpf_lan_ifname.is_empty() {
            &ebpf_wan_ifname
        } else {
            &ebpf_lan_ifname
        };

        // Enable bpf_redirect_peer on kernels >= 6.8, and also on backported
        // LTS kernels that received the CVE-2024-37959 fix:
        //   5.15.164+, 6.1.99+, 6.6.40+
        // https://www.kernel.org/doc/Documentation/networking/netkit.rst
        let use_redirect_peer = match kernel_version() {
            Some((major, minor, patch)) => {
                let enabled = (major > 6 || (major == 6 && minor >= 8))   // >= 6.8
                    || (major == 5 && minor == 15 && patch >= 164)        // >= 5.15.164
                    || (major == 6 && minor == 1 && patch >= 99)          // >= 6.1.99
                    || (major == 6 && minor == 6 && patch >= 40); // >= 6.6.40
                if enabled {
                    info!(
                        "Kernel {}.{}.{} supports bpf_redirect_peer, enabling",
                        major, minor, patch
                    );
                    1u8
                } else {
                    info!(
                        "Kernel {}.{}.{} does not support bpf_redirect_peer, disabled",
                        major, minor, patch
                    );
                    0u8
                }
            }
            None => {
                warn!(
                    "Could not determine kernel version; bpf_redirect_peer disabled (safe default)"
                );
                0u8
            }
        };

        let dae_param = DaeParam {
            tproxy_port: tproxy_port.to_be() as u32,
            dae0_ifindex,
            wan_ifindex,
            dae0peer_mac,
            use_redirect_peer,
            dae_socket_mark: DAE_BYPASS_MARK,
            control_plane_pid: std::process::id(),
            local_ip: Self::iface_ipv4(local_ifname),
            ..Default::default()
        };
        debug!(
            "PARAM: port={} dae0_ifindex={} wan_ifindex={} (iface={})",
            tproxy_port, dae0_ifindex, wan_ifindex, ebpf_wan_ifname
        );
        // A stale pin must never hide the map owned by this generation.
        // The singleton lock guarantees the previous engine has exited.
        let _ = std::fs::remove_file(pin_root.join("LISTEN_SOCKET_MAP"));
        let mut bpf = EbpfLoader::new()
            .override_global("PARAM", &dae_param, true)
            .override_global("WAN_IFINDEX", &wan_ifindex, true)
            .override_global("DAE0PEER_IFINDEX", &dae0peer_ifindex, true)
            .load(obj)?;
        std::fs::create_dir_all(pin_root)?;
        for (name, map) in bpf.maps() {
            // aya exposes ELF internal sections (.rodata, .bss, etc.) as maps.
            // These cannot be pinned to bpffs; skip them to avoid noisy warnings.
            if name.starts_with('.') {
                debug!("skipping internal map '{}'", name);
                continue;
            }
            let pin_path = pin_root.join(name);
            if let Err(error) = std::fs::remove_file(&pin_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!("remove stale pin '{}': {}", name, error);
            }
            if let Err(e) = map.pin(&pin_path) {
                warn!("pin '{}': {}", name, e);
            } else {
                debug!("pinned '{}'", name);
            }
        }
        // Install a complete generation-0 fallback before any TC hook is
        // attached. New flows therefore punt to userspace until the first
        // compiled routing generation is published.
        {
            let generation = 0u32;
            let cold_start = MatchSet {
                match_type: MatchType::Fallback as u8,
                outbound: OutboundIndex::ControlPlaneRouting as u8,
                ..Default::default()
            };
            bpf_hash_insert(
                &mut bpf,
                "ROUTING_MAP",
                unsafe { as_bytes(&0u32) },
                unsafe { as_bytes(&cold_start) },
            )
            .map_err(|e| anyhow::anyhow!("cold-start ROUTING_MAP init: {}", e))?;

            let bitmap = [1u32, 0, 0, 0];
            for group in 0..ROUTING_GROUP_COUNT as u32 {
                for (word, value) in bitmap.iter().enumerate() {
                    let slot = routing_meta_bitmap_base(generation)
                        + group * ROUTING_GROUP_BITMAP_WORDS as u32
                        + word as u32;
                    bpf_hash_insert(
                        &mut bpf,
                        "ROUTING_META_MAP",
                        unsafe { as_bytes(&slot) },
                        unsafe { as_bytes(value) },
                    )
                    .map_err(|e| anyhow::anyhow!("cold-start ROUTING_META_MAP init: {}", e))?;
                }
            }
            let count = 1u32;
            let count_slot = routing_meta_count_slot(generation);
            bpf_hash_insert(
                &mut bpf,
                "ROUTING_META_MAP",
                unsafe { as_bytes(&count_slot) },
                unsafe { as_bytes(&count) },
            )
            .map_err(|e| anyhow::anyhow!("cold-start ROUTING_META_MAP init: {}", e))?;
            for group in 0..ROUTING_GROUP_COUNT as u32 {
                let index = routing_group_meta_index(generation, group);
                let meta = RoutingGroupMeta {
                    rule_count: count,
                    bitmap,
                };
                bpf_hash_insert(
                    &mut bpf,
                    "ROUTING_GROUP_META_MAP",
                    unsafe { as_bytes(&index) },
                    unsafe { as_bytes(&meta) },
                )
                .map_err(|e| anyhow::anyhow!("cold-start ROUTING_GROUP_META_MAP init: {}", e))?;
            }
            bpf_hash_insert(
                &mut bpf,
                "ROUTING_META_MAP",
                unsafe { as_bytes(&ROUTING_META_ACTIVE_GENERATION_SLOT) },
                unsafe { as_bytes(&generation) },
            )
            .map_err(|e| anyhow::anyhow!("cold-start routing selector init: {}", e))?;
        }
        // Attach cgroup programs to root cgroup2 for cookie→PID mapping.
        // This enables pname routing and control-plane traffic bypass (Go dae parity).
        // The links must stay owned by the backend: a dropped link fd detaches
        // the program, which once silently disabled COOKIE_PID_MAP (pname
        // routing) from the first microseconds of every run.
        let mut cgroup_sock_links = Vec::new();
        let mut cgroup_sock_addr_links = Vec::new();
        match detect_cgroup_path() {
            Ok(cgroup_path) => {
                let cgroup_file = std::fs::File::open(&cgroup_path)
                    .map_err(|e| anyhow::anyhow!("open cgroup {}: {}", cgroup_path, e))?;
                let cg_sock_names = ["tproxy_wan_cg_sock_create", "tproxy_wan_cg_sock_release"];
                for name in &cg_sock_names {
                    let p: &mut aya::programs::CgroupSock = bpf
                        .program_mut(name)
                        .and_then(|p| p.try_into().ok())
                        .ok_or_else(|| anyhow::anyhow!("{} program not found", name))?;
                    p.load()?;
                    let link_id =
                        p.attach(&cgroup_file, aya::programs::CgroupAttachMode::Single)?;
                    cgroup_sock_links.push(p.take_link(link_id)?);
                }
                let cg_addr_names = [
                    "tproxy_wan_cg_connect4",
                    "tproxy_wan_cg_connect6",
                    "tproxy_wan_cg_sendmsg4",
                    "tproxy_wan_cg_sendmsg6",
                ];
                for name in &cg_addr_names {
                    let p: &mut aya::programs::CgroupSockAddr = bpf
                        .program_mut(name)
                        .and_then(|p| p.try_into().ok())
                        .ok_or_else(|| anyhow::anyhow!("{} program not found", name))?;
                    p.load()?;
                    let link_id =
                        p.attach(&cgroup_file, aya::programs::CgroupAttachMode::Single)?;
                    cgroup_sock_addr_links.push(p.take_link(link_id)?);
                }
                info!("Attached 6 cgroup programs to {}", cgroup_path);
            }
            Err(e) => {
                warn!("cgroup2 not available; pname routing disabled: {}", e);
            }
        }
        // Initialize outbound connectivity map: all entries are alive by default.
        // This map is updated by health checks; until then we must not drop
        // proxy-bound traffic. Skipping entries here marks every outbound
        // dead, so an insert error aborts startup.
        for i in 0..honk_ebpf_common::MAX_OUTBOUNDS * 6 {
            bpf_hash_insert(
                &mut bpf,
                "OUTBOUND_CONNECTIVITY_MAP",
                unsafe { as_bytes(&i) },
                unsafe { as_bytes(&1u64) },
            )
            .map_err(|e| anyhow::anyhow!("OUTBOUND_CONNECTIVITY_MAP init: {}", e))?;
        }

        if ebpf_lan_ifname.is_empty() {
            info!("LAN interception disabled; attaching only configured WAN hooks");
        } else {
            info!(
                "Attaching eBPF TC programs to LAN interface: {} (configured: {})",
                ebpf_lan_ifname,
                lan_ifname.unwrap_or_default()
            );
            if let Err(e) = aya::programs::tc::qdisc_add_clsact(&ebpf_lan_ifname) {
                let msg = e.to_string();
                if !msg.contains("File exists") && !msg.contains("Exclusivity flag") {
                    warn!("failed to add clsact qdisc to {}: {}", ebpf_lan_ifname, e);
                }
            }
        }
        let (lan_ingress_prog, lan_egress_prog) = Self::lan_program_pair(&ebpf_lan_ifname);

        // Attach LAN programs and take ownership of the links so they stay alive
        // and can be explicitly detached on shutdown.
        let lan_ingress_link = if ebpf_lan_ifname.is_empty() {
            None
        } else {
            let id = Self::attach_tc(&mut bpf, lan_ingress_prog, &ebpf_lan_ifname)
                .map_err(|e| anyhow::anyhow!("attach {}: {}", lan_ingress_prog, e))?;
            let p: &mut aya::programs::SchedClassifier = bpf
                .program_mut(lan_ingress_prog)
                .ok_or_else(|| anyhow::anyhow!("{} program disappeared", lan_ingress_prog))?
                .try_into()?;
            Some(p.take_link(id)?)
        };
        // In a single-homed setup (LAN and WAN share the same physical
        // interface) attaching lan_egress to the host's only outbound interface
        // would drop the host's own traffic. Attach only ingress in that case.
        let lan_egress_link = if ebpf_lan_ifname.is_empty() {
            None
        } else if single_homed {
            info!("Single-homed interface detected; skipping lan_egress attach");
            None
        } else {
            let id = Self::attach_tc_at(
                &mut bpf,
                lan_egress_prog,
                &ebpf_lan_ifname,
                aya::programs::TcAttachType::Egress,
            )
            .map_err(|e| anyhow::anyhow!("attach {}: {}", lan_egress_prog, e))?;
            let p: &mut aya::programs::SchedClassifier = bpf
                .program_mut(lan_egress_prog)
                .ok_or_else(|| anyhow::anyhow!("{} program disappeared", lan_egress_prog))?
                .try_into()?;
            Some(p.take_link(id)?)
        };

        // Attach WAN egress program to intercept locally-generated traffic.
        // In single-homed setups the WAN and LAN share the same interface, so
        // we attach wan_egress there (lan_egress is skipped above to avoid
        // interfering with host traffic).
        let wan_egress_link = if ebpf_wan_ifname.is_empty() {
            warn!("WAN interface name is empty; skipping wan_egress attach");
            None
        } else {
            if let Err(e) = aya::programs::tc::qdisc_add_clsact(&ebpf_wan_ifname) {
                let msg = e.to_string();
                if !msg.contains("File exists") && !msg.contains("Exclusivity flag") {
                    warn!("failed to add clsact qdisc to {}: {}", ebpf_wan_ifname, e);
                }
            }
            // Choose the L2/L3 variant by interface type (Go dae mapLinkType
            // semantics): ARPHRD_ETHER interfaces (incl. bond masters) carry
            // fully-framed packets at TC egress — neigh_output runs
            // dev_hard_header before dev_queue_xmit, so the Ethernet header
            // is already present when the TC hook fires.  Only genuinely
            // headerless interfaces (PPP/tun/IPIP) get the L3 program.
            let wan_egress_prog = if Self::iface_is_ethernet(&ebpf_wan_ifname) {
                "wan_egress_l2"
            } else {
                "wan_egress_l3"
            };
            let id = Self::attach_tc_at(
                &mut bpf,
                wan_egress_prog,
                &ebpf_wan_ifname,
                aya::programs::TcAttachType::Egress,
            )
            .map_err(|e| anyhow::anyhow!("attach {}: {}", wan_egress_prog, e))?;
            let p: &mut aya::programs::SchedClassifier = bpf
                .program_mut(wan_egress_prog)
                .ok_or_else(|| anyhow::anyhow!("{} program disappeared", wan_egress_prog))?
                .try_into()?;
            info!(
                "attached '{}' to {} (Egress)",
                wan_egress_prog, ebpf_wan_ifname
            );
            Some(p.take_link(id)?)
        };

        // Attach the WAN ingress program so replies arriving from the WAN
        // refresh the reverse-direction conntrack state (the datapath's
        // is_wan_ingress_direction tracking for direct flows).  Unlike
        // wan_egress — which uses the L3 program because a bond master may
        // emit locally-generated egress skbs without an Ethernet header —
        // ingress packets always arrive from the wire fully framed, so the
        // L2/L3 choice follows the interface type (same judgment as
        // attach_wan_egress uses for secondary interfaces).
        //
        // Single-homed setups share one interface between LAN and WAN and
        // lan_ingress already owns that ingress hook, so wan_ingress is
        // skipped there (mirroring the lan_egress skip above).
        let wan_ingress_link = if single_homed {
            info!("Single-homed interface detected; skipping wan_ingress attach");
            None
        } else if ebpf_wan_ifname.is_empty() {
            // Already warned in the wan_egress block above.
            None
        } else {
            let wan_ingress_prog = if Self::iface_is_ethernet(&ebpf_wan_ifname) {
                "wan_ingress_l2"
            } else {
                "wan_ingress_l3"
            };
            let id = Self::attach_tc(&mut bpf, wan_ingress_prog, &ebpf_wan_ifname)
                .map_err(|e| anyhow::anyhow!("attach {}: {}", wan_ingress_prog, e))?;
            let p: &mut aya::programs::SchedClassifier = bpf
                .program_mut(wan_ingress_prog)
                .ok_or_else(|| anyhow::anyhow!("{} program disappeared", wan_ingress_prog))?
                .try_into()?;
            info!(
                "attached '{}' to {} (Ingress)",
                wan_ingress_prog, ebpf_wan_ifname
            );
            Some(p.take_link(id)?)
        };

        // For bridge masters, forwarded L2 traffic does not traverse the
        // master's TC hooks; it is switched directly between slave ports.
        // Attach the LAN programs to each bridge slave so container traffic
        // is intercepted.
        // Slave links go into `dynamic_links` (keyed by ifindex/direction):
        // without that the watcher's `dynamic_hooked` dedup never sees them
        // and retries the attach every tick, failing with AlreadyExists.
        let mut dynamic_links = Vec::new();
        let br_slaves = if ebpf_lan_ifname.is_empty() {
            Vec::new()
        } else {
            Self::bridge_slaves(&ebpf_lan_ifname)
        };
        if !br_slaves.is_empty() {
            info!(
                "Bridge master {} has slaves {:?}; attaching LAN programs to bridge slaves",
                ebpf_lan_ifname, br_slaves
            );
            let ingress_dir = aya::programs::TcAttachType::Ingress;
            let egress_dir = aya::programs::TcAttachType::Egress;
            for slave in &br_slaves {
                if let Err(e) = aya::programs::tc::qdisc_add_clsact(slave) {
                    let msg = e.to_string();
                    if !msg.contains("File exists") && !msg.contains("Exclusivity flag") {
                        warn!(
                            "failed to add clsact qdisc to bridge slave {}: {}",
                            slave, e
                        );
                    }
                }
                let slave_prog = if Self::iface_is_ethernet(slave) {
                    "lan_ingress_l2"
                } else {
                    "lan_ingress_l3"
                };
                let ingress_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut(slave_prog)
                        .ok_or_else(|| anyhow::anyhow!("{} program disappeared", slave_prog))?
                        .try_into()?;
                    let id = p.attach(slave, ingress_dir).map_err(|e| {
                        anyhow::anyhow!("attach {} to {}: {}", slave_prog, slave, e)
                    })?;
                    dynamic_links.push((Self::iface_ifindex(slave), false, p.take_link(id)?));
                    Ok(())
                })();
                // A slave we cannot attach silently leaves that traffic
                // outside the proxy — abort rather than run half-covered.
                ingress_result.map_err(|e| {
                    anyhow::anyhow!("attach {} to bridge slave {}: {}", slave_prog, slave, e)
                })?;
                info!(
                    "attached {} to bridge slave {} (Ingress)",
                    slave_prog, slave
                );

                let egress_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut("lan_egress_l2")
                        .ok_or_else(|| anyhow::anyhow!("lan_egress_l2 program disappeared"))?
                        .try_into()?;
                    let id = p
                        .attach(slave, egress_dir)
                        .map_err(|e| anyhow::anyhow!("attach lan_egress_l2 to {}: {}", slave, e))?;
                    dynamic_links.push((Self::iface_ifindex(slave), true, p.take_link(id)?));
                    Ok(())
                })();
                egress_result.map_err(|e| {
                    anyhow::anyhow!("attach lan_egress_l2 to bridge slave {}: {}", slave, e)
                })?;
                info!("attached lan_egress_l2 to bridge slave {} (Egress)", slave);
            }
        }

        // For bond masters, packets may be delivered on the slave interfaces
        // before they are aggregated onto the master. Attach lan_ingress to
        // each slave so we do not miss downstream traffic.  Like bridge
        // slaves above, the links go into `dynamic_links` so the watcher's
        // `dynamic_hooked` dedup sees them and does not stack a duplicate
        // hook on the first reconcile.
        let lan_slaves = if ebpf_lan_ifname.is_empty() {
            Vec::new()
        } else {
            Self::bond_slaves(&ebpf_lan_ifname)
        };
        if !lan_slaves.is_empty() {
            info!(
                "Bond master {} has slaves {:?}; attaching lan_ingress to slaves",
                ebpf_lan_ifname, lan_slaves
            );
            // The ingress program is already loaded for the master; reuse the
            // same loaded program object and attach it to each slave.
            let slave_dir = aya::programs::TcAttachType::Ingress;
            for slave in &lan_slaves {
                if let Err(e) = aya::programs::tc::qdisc_add_clsact(slave) {
                    warn!("failed to add clsact qdisc to slave {}: {}", slave, e);
                }
                let slave_prog = if Self::iface_is_ethernet(slave) {
                    "lan_ingress_l2"
                } else {
                    "lan_ingress_l3"
                };
                let attach_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut(slave_prog)
                        .ok_or_else(|| anyhow::anyhow!("{} program disappeared", slave_prog))?
                        .try_into()?;
                    let id = p.attach(slave, slave_dir).map_err(|e| {
                        anyhow::anyhow!("attach {} to {}: {}", slave_prog, slave, e)
                    })?;
                    dynamic_links.push((Self::iface_ifindex(slave), false, p.take_link(id)?));
                    Ok(())
                })();
                attach_result.map_err(|e| {
                    anyhow::anyhow!("attach lan_ingress to bond slave {}: {}", slave, e)
                })?;
                info!("attached lan_ingress to bond slave {}", slave);
            }
        }

        // Preserve the LAN-bond egress hooks used by single-homed setups, then
        // add WAN-bond slaves so WAN-only hosts cover the same physical path.
        let mut wan_egress_slaves = lan_slaves.clone();
        if !ebpf_wan_ifname.is_empty() {
            for slave in Self::bond_slaves(&ebpf_wan_ifname) {
                if !wan_egress_slaves.contains(&slave) {
                    wan_egress_slaves.push(slave);
                }
            }
        }
        if !wan_egress_slaves.is_empty() {
            info!(
                "Attaching wan_egress to bond slaves {:?}",
                wan_egress_slaves
            );
            let slave_dir = aya::programs::TcAttachType::Egress;
            for slave in &wan_egress_slaves {
                if let Err(e) = aya::programs::tc::qdisc_add_clsact(slave) {
                    warn!("failed to add clsact qdisc to slave {}: {}", slave, e);
                }
                // Bond slaves are ARPHRD_ETHER and see fully-framed skbs at
                // their TC egress hook (the bond driver has already built
                // the Ethernet header), so use the L2 program.
                let slave_prog = "wan_egress_l2";
                let attach_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut(slave_prog)
                        .ok_or_else(|| anyhow::anyhow!("{} program disappeared", slave_prog))?
                        .try_into()?;
                    let id = p.attach(slave, slave_dir).map_err(|e| {
                        anyhow::anyhow!("attach {} to {}: {}", slave_prog, slave, e)
                    })?;
                    dynamic_links.push((Self::iface_ifindex(slave), true, p.take_link(id)?));
                    Ok(())
                })();
                attach_result.map_err(|e| {
                    anyhow::anyhow!("attach wan_egress to bond slave {}: {}", slave, e)
                })?;
                info!("attached wan_egress to bond slave {}", slave);
            }
        }

        info!("eBPF loaded and attached");

        // aya-log must be initialized *after* programs are loaded, otherwise the
        // AYA_LOGS map fd taken by the logger is not valid during BPF_PROG_LOAD.
        //
        // Wait on the ringbuf fd with AsyncFd (official aya-log 0.3 pattern).
        // A fixed-interval flush was waking every 100ms even when empty and
        // could burn a full core under high eBPF log volume via spawn_blocking.
        let log_flush_handle = match aya_log::EbpfLogger::init(&mut bpf) {
            Ok(logger) => {
                debug!("eBPF logger initialized");
                match tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                {
                    Ok(async_logger) => Some(tokio::spawn(async move {
                        let mut async_logger = async_logger;
                        loop {
                            let mut guard = match async_logger.readable_mut().await {
                                Ok(g) => g,
                                Err(e) => {
                                    debug!("eBPF logger AsyncFd wait failed: {}", e);
                                    break;
                                }
                            };
                            // Non-blocking drain; returns immediately when empty.
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                    })),
                    Err(e) => {
                        warn!(
                            "eBPF logger AsyncFd setup failed (logs will not be drained): {}",
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                debug!(
                    "eBPF logger init failed (no log statements or aya-log mismatch): {}",
                    e
                );
                None
            }
        };

        // Spawn the DaeEvent consumer: conntrack overflow events produced by
        // the eBPF datapath arrive on EVENT_RINGBUF (contrack.rs).  Same
        // AsyncFd readiness pattern as the aya-log flush task above.  The map
        // is taken out of the Ebpf object so the task owns it outright; the
        // pinned copy under pin_root remains for external inspection.
        let event_flush_handle = match bpf.take_map("EVENT_RINGBUF") {
            Some(map) => match aya::maps::RingBuf::try_from(map) {
                Ok(ring_buf) => {
                    match tokio::io::unix::AsyncFd::with_interest(
                        ring_buf,
                        tokio::io::Interest::READABLE,
                    ) {
                        Ok(async_fd) => Some(tokio::spawn(consume_dae_events(async_fd))),
                        Err(e) => {
                            warn!(
                                "DaeEvent ringbuf AsyncFd setup failed (events will not be drained): {}",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "EVENT_RINGBUF open failed (events will not be drained): {}",
                        e
                    );
                    None
                }
            },
            None => {
                debug!("EVENT_RINGBUF not present in eBPF object");
                None
            }
        };

        Ok(Self {
            bpf: Some(bpf),
            pin_root: pin_root.to_path_buf(),
            tproxy_port,
            tproxy_mark,
            lan_ingress_link,
            lan_egress_link,
            wan_egress_link,
            wan_ingress_link,
            dynamic_links,
            cgroup_sock_links,
            cgroup_sock_addr_links,
            dae0_ingress_link: None,
            dae0peer_ingress_link: None,
            sk_lookup_link: None,
            listeners_published: false,
            log_flush_handle,
            event_flush_handle,
            cap_lookup_and_delete: BatchCapability::new(),
            cap_lookup_batch: BatchCapability::new(),
            cap_delete_batch: BatchCapability::new(),
            cap_update_batch: BatchCapability::new(),
        })
    }

    fn attach_tc_at(
        bpf: &mut Ebpf,
        prog: &str,
        iface: &str,
        dir: aya::programs::TcAttachType,
    ) -> anyhow::Result<aya::programs::tc::SchedClassifierLinkId> {
        let p: &mut aya::programs::SchedClassifier = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("prog '{}' not found", prog))?
            .try_into()?;
        // Re-attaching an interface (extra LAN/WAN, dynamic watcher) reuses
        // the program loaded for the primary interface; only the first
        // attach actually loads.
        match p.load() {
            Ok(()) => {}
            Err(aya::programs::ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(anyhow::anyhow!("load '{}': {}", prog, e)),
        }
        let id = p
            .attach(iface, dir)
            .map_err(|e| anyhow::anyhow!("attach '{}': {} (raw={:?})", prog, e, e))?;
        info!(
            "attached '{}' to {} ({:?}) link_id={:?}",
            prog, iface, dir, id
        );
        Ok(id)
    }

    pub fn attach_tc(
        bpf: &mut Ebpf,
        prog: &str,
        iface: &str,
    ) -> anyhow::Result<aya::programs::tc::SchedClassifierLinkId> {
        Self::attach_tc_at(bpf, prog, iface, aya::programs::TcAttachType::Ingress)
    }

    /// Determine whether an interface carries Ethernet frames (ARPHRD_ETHER).
    /// Non-Ethernet interfaces (e.g. loopback, tunnel) should use L3 TC programs.
    fn iface_is_ethernet(iface: &str) -> bool {
        std::fs::read_to_string(format!("/sys/class/net/{}/type", iface))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|t| t == 1) // ARPHRD_ETHER
            .unwrap_or(false)
    }

    /// Pick the ingress/egress program pair for a LAN interface.
    /// Bridge masters use L3; physical/veth Ethernet interfaces use L2;
    /// everything else falls back to L3.
    fn lan_program_pair(iface: &str) -> (&'static str, &'static str) {
        // NOTE: bridge masters are attached with L2 programs because the TC
        // ingress qdisc on a Linux bridge sees the full Ethernet frame.
        if Self::iface_is_ethernet(iface) {
            ("lan_ingress_l2", "lan_egress_l2")
        } else {
            ("lan_ingress_l3", "lan_egress_l3")
        }
    }

    /// Read the IPv4 address of an interface in big-endian u32, or 0
    /// (getifaddrs — no `ip` subprocess needed).
    fn iface_ipv4(iface: &str) -> u32 {
        // SAFETY: getifaddrs allocates a linked list freed by freeifaddrs;
        // all pointers are checked before dereference.
        unsafe {
            let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut head) != 0 {
                return 0;
            }
            let mut result = 0u32;
            let mut cur = head;
            while !cur.is_null() {
                let ifa = &*cur;
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                if name == iface
                    && !ifa.ifa_addr.is_null()
                    && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET
                {
                    result = (*(ifa.ifa_addr as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr;
                    break;
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(head);
            result
        }
    }

    /// Read the kernel ifindex for an interface, or 0 if it cannot be read.
    fn iface_ifindex(iface: &str) -> u32 {
        std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Return the bridge master of `iface` if it is a bridge slave.
    fn bridge_interface(iface: &str) -> Option<String> {
        let master_link = format!("/sys/class/net/{}/master", iface);
        std::fs::read_link(&master_link)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }

    /// Return the list of bond slaves for `iface` if it is a bond master.
    pub(crate) fn bond_slaves(iface: &str) -> Vec<String> {
        let path = format!("/sys/class/net/{}/bonding/slaves", iface);
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| {
                s.split_whitespace()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    /// Return the list of bridge slaves for `iface` if it is a bridge master.
    pub(crate) fn bridge_slaves(iface: &str) -> Vec<String> {
        let path = format!("/sys/class/net/{}/brif", iface);
        std::fs::read_dir(&path)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }
}

impl RealEbpfBackend {
    /// Attach one TC program and record the link under (ifindex, direction)
    /// so it joins the detach lifecycle and dedupes later retries.
    fn attach_tc_tracked(
        &mut self,
        prog: &str,
        iface: &str,
        dir: aya::programs::TcAttachType,
    ) -> anyhow::Result<()> {
        let ifindex = Self::iface_ifindex(iface);
        let id = Self::attach_tc_at(self.bpf_mut()?, prog, iface, dir)?;
        let p: &mut aya::programs::SchedClassifier = self
            .bpf_mut()?
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("{} program disappeared", prog))?
            .try_into()?;
        let link = p.take_link(id)?;
        let is_egress = matches!(dir, aya::programs::TcAttachType::Egress);
        self.dynamic_links.push((ifindex, is_egress, link));
        Ok(())
    }

    fn dynamic_hooked(&self, ifindex: u32, is_egress: bool) -> bool {
        self.dynamic_links
            .iter()
            .any(|(i, e, _)| *i == ifindex && *e == is_egress)
    }

    /// Attach LAN programs to an additional interface (beyond the primary).
    /// Directions already hooked on this ifindex are skipped, so a retry
    /// after a partial failure only fills the gap.
    pub fn attach_lan(
        &mut self,
        ifname: &str,
        single_homed: bool,
    ) -> anyhow::Result<crate::ebpf::DynamicHooks> {
        let ifname = Self::bridge_interface(ifname).unwrap_or_else(|| ifname.to_string());
        info!("Attaching LAN programs to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(&ifname);
        let ifindex = Self::iface_ifindex(&ifname);
        let (ingress_prog, egress_prog) = Self::lan_program_pair(&ifname);
        let mut hooks = crate::ebpf::DynamicHooks {
            ingress: self.dynamic_hooked(ifindex, false),
            egress: self.dynamic_hooked(ifindex, true),
        };
        if !hooks.ingress {
            self.attach_tc_tracked(ingress_prog, &ifname, aya::programs::TcAttachType::Ingress)?;
            hooks.ingress = true;
        }
        if !single_homed && !hooks.egress {
            self.attach_tc_tracked(egress_prog, &ifname, aya::programs::TcAttachType::Egress)?;
            hooks.egress = true;
        }
        Ok(hooks)
    }

    /// Attach WAN egress to an additional interface.
    pub fn attach_wan_egress(&mut self, ifname: &str) -> anyhow::Result<()> {
        info!("Attaching WAN egress to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(ifname);
        if self.dynamic_hooked(Self::iface_ifindex(ifname), true) {
            return Ok(());
        }
        let prog = if Self::iface_is_ethernet(ifname) {
            "wan_egress_l2"
        } else {
            "wan_egress_l3"
        };
        self.attach_tc_tracked(prog, ifname, aya::programs::TcAttachType::Egress)
    }

    /// Attach WAN ingress to an additional interface (reverse-direction
    /// conntrack updates for replies arriving from the WAN).  L2/L3 is
    /// chosen by interface type, same as `attach_wan_egress`.
    pub fn attach_wan_ingress(&mut self, ifname: &str) -> anyhow::Result<()> {
        info!("Attaching WAN ingress to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(ifname);
        if self.dynamic_hooked(Self::iface_ifindex(ifname), false) {
            return Ok(());
        }
        let prog = if Self::iface_is_ethernet(ifname) {
            "wan_ingress_l2"
        } else {
            "wan_ingress_l3"
        };
        self.attach_tc_tracked(prog, ifname, aya::programs::TcAttachType::Ingress)
    }

    /// Attach a bridge/bond slave of a configured LAN master, mirroring the
    /// program choices `load()` makes at startup: bridge slaves get the LAN
    /// pair, bond slaves lan_ingress + wan_egress (both L2 on the egress —
    /// bond/bridge slaves are ARPHRD_ETHER and see fully-framed skbs).
    pub fn attach_slave(
        &mut self,
        ifname: &str,
        role: crate::ebpf::IfaceRole,
    ) -> anyhow::Result<crate::ebpf::DynamicHooks> {
        info!(
            "Attaching slave programs to additional interface: {}",
            ifname
        );
        let _ = aya::programs::tc::qdisc_add_clsact(ifname);
        let ifindex = Self::iface_ifindex(ifname);
        let mut hooks = crate::ebpf::DynamicHooks {
            ingress: self.dynamic_hooked(ifindex, false),
            egress: self.dynamic_hooked(ifindex, true),
        };
        let ingress_prog = if Self::iface_is_ethernet(ifname) {
            "lan_ingress_l2"
        } else {
            "lan_ingress_l3"
        };
        if !hooks.ingress {
            self.attach_tc_tracked(ingress_prog, ifname, aya::programs::TcAttachType::Ingress)?;
            hooks.ingress = true;
        }
        let egress_prog = match role {
            crate::ebpf::IfaceRole::LanBridgeSlave => "lan_egress_l2",
            _ => "wan_egress_l2",
        };
        if !hooks.egress {
            self.attach_tc_tracked(egress_prog, ifname, aya::programs::TcAttachType::Egress)?;
            hooks.egress = true;
        }
        Ok(hooks)
    }
}
