use super::*;

impl RealEbpfBackend {
    pub async fn load(
        obj: &[u8],
        pin_root: &Path,
        tproxy_port: u16,
        tproxy_mark: u32,
        lan_ifname: &str,
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
        // Determine the actual WAN interface (bond master if the configured
        // interface is a slave) so the eBPF datapath can identify locally-
        // generated packets that the bonding driver forwards onto the master.
        let ebpf_wan_ifname = if single_homed {
            Self::bridge_interface(lan_ifname).unwrap_or_else(|| lan_ifname.to_string())
        } else {
            Self::bridge_interface(wan_ifname).unwrap_or_else(|| wan_ifname.to_string())
        };
        let wan_ifindex = Self::iface_ifindex(&ebpf_wan_ifname);

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
            local_ip: Self::iface_ipv4(lan_ifname),
            ..Default::default()
        };
        debug!(
            "PARAM: port={} dae0_ifindex={} wan_ifindex={} (iface={})",
            tproxy_port, dae0_ifindex, wan_ifindex, ebpf_wan_ifname
        );
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
            if let Err(e) = map.pin(&pin_path) {
                warn!("pin '{}': {}", name, e);
            } else {
                debug!("pinned '{}'", name);
            }
        }
        // Cold-start routing table: a single Fallback MatchSet pointing at the
        // control plane (outbound 0xFD), with the active rule count set to 1.
        // ROUTING_META_MAP[0] defaults to 0, and the eBPF route loop treats a
        // zero rule count as an error (route() returns negative → TC_ACT_SHOT),
        // so without this every new flow would be dropped between program
        // attach and the first routing push.  With it, such flows are punted
        // to userspace routing instead.  This runs before any TC attach below,
        // so there is no window where the datapath sees an empty table.
        {
            let cold_start = MatchSet {
                match_type: MatchType::Fallback as u8,
                outbound: OutboundIndex::ControlPlaneRouting as u8,
                ..Default::default()
            };
            if let Err(e) = bpf_hash_insert(
                &mut bpf,
                "ROUTING_MAP",
                unsafe { as_bytes(&0u32) },
                unsafe { as_bytes(&cold_start) },
            ) {
                warn!("cold-start ROUTING_MAP init failed (non-fatal): {}", e);
            }
            // The fallback belongs to every (l4proto × ipversion) group, so
            // bit 0 of each group bitmap is set.  Write all meta slots
            // explicitly — group bitmaps first, the rule count last — so a
            // reused pinned map cannot leak stale group bits and the count
            // stays the atomic switch.
            for g in 0..ROUTING_GROUP_COUNT as u32 {
                for w in 0..ROUTING_GROUP_BITMAP_WORDS as u32 {
                    let slot = 1 + g * ROUTING_GROUP_BITMAP_WORDS as u32 + w;
                    let word: u32 = if w == 0 { 1 } else { 0 };
                    if let Err(e) = bpf_hash_insert(
                        &mut bpf,
                        "ROUTING_META_MAP",
                        unsafe { as_bytes(&slot) },
                        unsafe { as_bytes(&word) },
                    ) {
                        warn!("cold-start ROUTING_META_MAP init failed (non-fatal): {}", e);
                    }
                }
            }
            if let Err(e) = bpf_hash_insert(
                &mut bpf,
                "ROUTING_META_MAP",
                unsafe { as_bytes(&0u32) },
                unsafe { as_bytes(&1u32) },
            ) {
                warn!("cold-start ROUTING_META_MAP init failed (non-fatal): {}", e);
            }
        }
        // Attach cgroup programs to root cgroup2 for cookie→PID mapping.
        // This enables pname routing and control-plane traffic bypass (Go dae parity).
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
                    let _link = p.take_link(link_id)?;
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
                    let _link = p.take_link(link_id)?;
                }
                info!("Attached 6 cgroup programs to {}", cgroup_path);
            }
            Err(e) => {
                warn!("cgroup2 not available; pname routing disabled: {}", e);
            }
        }
        // Initialize outbound connectivity map: all entries are alive by default.
        // This map is updated by health checks; until then we must not drop
        // proxy-bound traffic.
        for i in 0..honk_ebpf_common::MAX_OUTBOUNDS * 6 {
            let _ = bpf_hash_insert(
                &mut bpf,
                "OUTBOUND_CONNECTIVITY_MAP",
                unsafe { as_bytes(&i) },
                unsafe { as_bytes(&1u64) },
            );
        }

        // If the configured LAN interface is a bridge slave, attach the eBPF
        // programs to the bridge master instead.  This lets a single eBPF
        // attachment handle all containers on the bridge, rather than only the
        // one specific veth configured as lan_interface.
        let ebpf_lan_ifname =
            Self::bridge_interface(lan_ifname).unwrap_or_else(|| lan_ifname.to_string());
        info!(
            "Attaching eBPF TC programs to LAN interface: {} (configured: {})",
            ebpf_lan_ifname, lan_ifname
        );
        if let Err(e) = aya::programs::tc::qdisc_add_clsact(&ebpf_lan_ifname) {
            let msg = e.to_string();
            if !msg.contains("File exists") && !msg.contains("Exclusivity flag") {
                warn!("failed to add clsact qdisc to {}: {}", ebpf_lan_ifname, e);
            }
        }
        let (lan_ingress_prog, lan_egress_prog) = Self::lan_program_pair(&ebpf_lan_ifname);

        // Attach LAN programs and take ownership of the links so they stay alive
        // and can be explicitly detached on shutdown.
        let lan_ingress_link = {
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
        let lan_egress_link = if single_homed {
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
            // The bonding master may see locally-generated egress skbs as
            // L3-only (Ethernet header added later by the slave driver), so use
            // the L3 program for WAN egress.
            let wan_egress_prog = "wan_egress_l3";
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
        let mut bridge_slave_links = Vec::new();
        let br_slaves = Self::bridge_slaves(&ebpf_lan_ifname);
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
                    bridge_slave_links.push(p.take_link(id)?);
                    Ok(())
                })();
                match ingress_result {
                    Ok(()) => info!(
                        "attached {} to bridge slave {} (Ingress)",
                        slave_prog, slave
                    ),
                    Err(e) => warn!(
                        "failed to attach {} to bridge slave {}: {}",
                        slave_prog, slave, e
                    ),
                }

                let egress_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut("lan_egress_l2")
                        .ok_or_else(|| anyhow::anyhow!("lan_egress_l2 program disappeared"))?
                        .try_into()?;
                    let id = p
                        .attach(slave, egress_dir)
                        .map_err(|e| anyhow::anyhow!("attach lan_egress_l2 to {}: {}", slave, e))?;
                    bridge_slave_links.push(p.take_link(id)?);
                    Ok(())
                })();
                match egress_result {
                    Ok(()) => info!("attached lan_egress_l2 to bridge slave {} (Egress)", slave),
                    Err(e) => warn!(
                        "failed to attach lan_egress_l2 to bridge slave {}: {}",
                        slave, e
                    ),
                }
            }
        }

        // For bond masters, packets may be delivered on the slave interfaces
        // before they are aggregated onto the master. Attach lan_ingress to
        // each slave so we do not miss downstream traffic.
        let mut lan_slave_links = Vec::new();
        let slaves = Self::bond_slaves(&ebpf_lan_ifname);
        if !slaves.is_empty() {
            info!(
                "Bond master {} has slaves {:?}; attaching lan_ingress to slaves",
                ebpf_lan_ifname, slaves
            );
            // The ingress program is already loaded for the master; reuse the
            // same loaded program object and attach it to each slave.
            let slave_dir = aya::programs::TcAttachType::Ingress;
            for slave in &slaves {
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
                    lan_slave_links.push(p.take_link(id)?);
                    Ok(())
                })();
                match attach_result {
                    Ok(()) => info!("attached lan_ingress to bond slave {}", slave),
                    Err(e) => warn!("failed to attach lan_ingress to slave {}: {}", slave, e),
                }
            }
        }

        // For bond masters, outbound packets may leave via a slave without
        // traversing the master's egress qdisc. Attach wan_egress to each slave
        // so locally-generated traffic is intercepted regardless of the bond's
        // egress slave selection.
        let mut wan_slave_links = Vec::new();
        if !slaves.is_empty() {
            info!(
                "Bond master {} has slaves {:?}; attaching wan_egress to slaves",
                ebpf_wan_ifname, slaves
            );
            let slave_dir = aya::programs::TcAttachType::Egress;
            for slave in &slaves {
                if let Err(e) = aya::programs::tc::qdisc_add_clsact(slave) {
                    warn!("failed to add clsact qdisc to slave {}: {}", slave, e);
                }
                // Bond slaves may see locally-generated egress skbs as L3-only
                // (Ethernet header added by the driver after TC), so use the L3
                // program for slaves even though their type is ARPHRD_ETHER.
                let slave_prog = "wan_egress_l3";
                let attach_result: anyhow::Result<()> = (|| {
                    let p: &mut aya::programs::SchedClassifier = bpf
                        .program_mut(slave_prog)
                        .ok_or_else(|| anyhow::anyhow!("{} program disappeared", slave_prog))?
                        .try_into()?;
                    let id = p.attach(slave, slave_dir).map_err(|e| {
                        anyhow::anyhow!("attach {} to {}: {}", slave_prog, slave, e)
                    })?;
                    wan_slave_links.push(p.take_link(id)?);
                    Ok(())
                })();
                match attach_result {
                    Ok(()) => info!("attached wan_egress to bond slave {}", slave),
                    Err(e) => warn!("failed to attach wan_egress to slave {}: {}", slave, e),
                }
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
            lan_slave_links,
            wan_slave_links,
            bridge_slave_links,
            dae0_ingress_link: None,
            dae0peer_ingress_link: None,
            sk_lookup_link: None,
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
        p.load()
            .map_err(|e| anyhow::anyhow!("load '{}': {}", prog, e))?;
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

    /// Determine whether an interface is a Linux bridge master.
    /// Bridge devices have ARPHRD_ETHER but the TC datapath on a bridge master
    /// sees packets at L3 (Ethernet header already consumed by the bridge
    /// forwarding path), so they must use the L3 TC programs.
    #[allow(dead_code)]
    fn iface_is_bridge_master(iface: &str) -> bool {
        std::fs::metadata(format!("/sys/class/net/{}/bridge/bridge_id", iface)).is_ok()
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

    /// Read the IPv4 address of an interface in big-endian u32, or 0.
    fn iface_ipv4(iface: &str) -> u32 {
        let output = match std::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show", iface])
            .output()
        {
            Ok(o) => o,
            Err(_) => return 0,
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(inet_pos) = line.find("inet ") {
                let rest = &line[inet_pos + 5..];
                if let Some(slash_pos) = rest.find('/') {
                    let ip_str = &rest[..slash_pos];
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        return u32::from_be_bytes(ip.octets());
                    }
                }
            }
        }
        0
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
    fn bond_slaves(iface: &str) -> Vec<String> {
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
    fn bridge_slaves(iface: &str) -> Vec<String> {
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
    /// Attach LAN programs to an additional interface (beyond the primary).
    pub fn attach_lan(&mut self, ifname: &str, single_homed: bool) -> anyhow::Result<()> {
        let bpf = self.bpf_mut()?;
        let ifname = Self::bridge_interface(ifname).unwrap_or_else(|| ifname.to_string());
        info!("Attaching LAN programs to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(&ifname);
        let (ingress_prog, egress_prog) = Self::lan_program_pair(&ifname);
        Self::attach_tc_at(
            bpf,
            ingress_prog,
            &ifname,
            aya::programs::TcAttachType::Ingress,
        )
        .ok();
        if !single_homed {
            Self::attach_tc_at(
                bpf,
                egress_prog,
                &ifname,
                aya::programs::TcAttachType::Egress,
            )
            .ok();
        }
        Ok(())
    }

    /// Attach WAN egress to an additional interface.
    pub fn attach_wan_egress(&mut self, ifname: &str) -> anyhow::Result<()> {
        let bpf = self.bpf_mut()?;
        info!("Attaching WAN egress to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(ifname);
        let prog = if Self::iface_is_ethernet(ifname) {
            "wan_egress_l2"
        } else {
            "wan_egress_l3"
        };
        Self::attach_tc_at(bpf, prog, ifname, aya::programs::TcAttachType::Egress).ok();
        Ok(())
    }

    /// Attach WAN ingress to an additional interface (reverse-direction
    /// conntrack updates for replies arriving from the WAN).  L2/L3 is
    /// chosen by interface type, same as `attach_wan_egress`.
    pub fn attach_wan_ingress(&mut self, ifname: &str) -> anyhow::Result<()> {
        let bpf = self.bpf_mut()?;
        info!("Attaching WAN ingress to additional interface: {}", ifname);
        let _ = aya::programs::tc::qdisc_add_clsact(ifname);
        let prog = if Self::iface_is_ethernet(ifname) {
            "wan_ingress_l2"
        } else {
            "wan_ingress_l3"
        };
        Self::attach_tc(bpf, prog, ifname).ok();
        Ok(())
    }
}
