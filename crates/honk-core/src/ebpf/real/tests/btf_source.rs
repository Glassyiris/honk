use super::*;

#[test]
#[ignore = "requires disposable VM, root, cgroup v2, Linux 6.12+, and an eBPF build"]
fn kernel_btf_override_controls_startup() {
    const CHILD: &str = "HONK_TEST_KERNEL_BTF";
    let Ok(case) = std::env::var(CHILD) else {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.btf");
        let invalid = directory.path().join("invalid.btf");
        let missing = directory.path().join("missing.btf");
        let data = std::fs::read("/sys/kernel/btf/vmlinux").unwrap();
        std::fs::write(&valid, &data).unwrap();
        let oversized = directory.path().join("oversized-request.btf");
        let (structure, member_offset) = {
            let btf = btf::Btf::parse(&data).unwrap();
            let structure = btf.find_type(4, "tcp_request_sock").unwrap();
            let old_offset = btf.member_offset("tcp_request_sock", "rcv_isn").unwrap();
            let members = btf.u32_at(structure + 4).unwrap() & 0xffff;
            let positions: Vec<_> = (0..members as usize)
                .map(|index| structure + 12 + index * 12 + 8)
                .filter(|offset| btf.u32_at(*offset) == Some(old_offset * 8))
                .collect();
            assert_eq!(positions.len(), 1, "unique rcv_isn member offset");
            (structure, positions[0])
        };
        let capacity = core::mem::size_of::<honk_ebpf_common::KernelRouteWitness>() as u32;
        let mut oversized_data = data.clone();
        oversized_data[structure + 8..structure + 12]
            .copy_from_slice(&(capacity + 64).to_ne_bytes());
        oversized_data[member_offset..member_offset + 4]
            .copy_from_slice(&((capacity + 4) * 8).to_ne_bytes());
        std::fs::write(&oversized, oversized_data).unwrap();
        let v4_only = directory.path().join("v4-only.btf");
        let mut v4_data = data;
        for name in ["tcp_v6_route_req", "tcp_v6_reqsk_destructor"] {
            let at = v4_data
                .windows(name.len())
                .position(|value| value == name.as_bytes())
                .expect("built-in IPv6 BTF fixture");
            v4_data[at] = b'_';
        }
        std::fs::write(&v4_only, v4_data).unwrap();
        std::fs::write(&invalid, b"not kernel BTF").unwrap();
        for (case, path) in [
            ("partial-v6", valid.clone()),
            ("valid", valid),
            ("missing", missing),
            ("invalid", invalid),
            ("v4-only", v4_only),
            ("oversized-request", oversized),
        ] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "ebpf::real::tests::btf_source::kernel_btf_override_controls_startup",
                    "--nocapture",
                ])
                .env(CHILD, case)
                .env("HONK_VMLINUX_BTF", path)
                .status()
                .unwrap();
            assert!(status.success(), "kernel BTF override case {case} failed");
        }
        return;
    };
    let valid = matches!(case.as_str(), "valid" | "v4-only" | "partial-v6");

    let empty = tempfile::tempdir().unwrap();
    if matches!(case.as_str(), "valid" | "partial-v6") {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .unwrap();
        // A matching override must work even without the sysfs BTF mount.
        nix::mount::mount(
            Some(empty.path()),
            "/sys/kernel/btf",
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let pin_root =
                Path::new("/sys/fs/bpf").join(format!("honk-kernel-btf-{}", std::process::id()));
            assert!(!pin_root.exists());
            let before = held_bpf_link_count();
            let result = RealEbpfBackend::load(
                crate::DEFAULT_BPF_OBJECT,
                &pin_root,
                12345,
                Some("lo"),
                "lo",
                true,
            )
            .await;
            let mut backend = match result {
                Ok(backend) => backend,
                Err(error) => {
                    assert!(!valid, "matching BTF override rejected: {error:#}");
                    assert_eq!(held_bpf_link_count(), before);
                    assert!(!pin_root.exists());
                    return;
                }
            };
            if case == "valid" {
                let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                receiver
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let storage = aya::maps::SkStorage::<_, SocketIdentity>::try_from(
                    backend.bpf().unwrap().map("SOCKET_IDENTITY").unwrap(),
                )
                .unwrap();
                assert_eq!(storage.get(&receiver, 0).unwrap().pid, std::process::id());
                #[cfg(feature = "native-api")]
                {
                    let trace = backend.receive_trace().expect("override receive trace");
                    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    let mut registration = trace.register(receiver.as_raw_fd()).unwrap();
                    sender
                        .send_to(b"btf", receiver.local_addr().unwrap())
                        .unwrap();
                    assert!(registration.begin(receiver.as_raw_fd()));
                    let mut buffer = [0; 3];
                    assert_eq!(receiver.recv(&mut buffer).unwrap(), 3);
                    assert_eq!(&buffer, b"btf");
                    let packet = registration.finish(1).expect("traced UDP receive")[0];
                    assert_eq!(
                        packet.valid,
                        honk_ebpf_common::receive_trace::RECEIVE_TRACE_VALID
                    );
                    assert_eq!(packet.length, 3);
                }
                use honk_ebpf_common::redirect_need::{TCP_BINDING_LISTENER, TcpSocketBinding};
                let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
                backend
                    .publish_listener_sockets(tcp4.as_raw_fd(), Some(tcp6.as_raw_fd()), &[], &[])
                    .unwrap();
                backend.set_datapath_ready(true).unwrap();
                backend.set_datapath_ready(false).unwrap();
                let storage = aya::maps::SkStorage::<_, TcpSocketBinding>::try_from(
                    backend.bpf().unwrap().map("TCP_SOCKET_BINDING").unwrap(),
                )
                .unwrap();
                assert_eq!(storage.get(&tcp4, 0).unwrap().kind, TCP_BINDING_LISTENER);
                assert_eq!(storage.get(&tcp6, 0).unwrap().kind, TCP_BINDING_LISTENER);
                backend.clear_listener_sockets().unwrap();
            }
            if case == "v4-only" {
                use honk_ebpf_common::redirect_need::{TCP_BINDING_LISTENER, TcpSocketBinding};
                let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
                assert!(
                    backend
                        .publish_listener_sockets(
                            tcp4.as_raw_fd(),
                            Some(tcp6.as_raw_fd()),
                            &[],
                            &[]
                        )
                        .is_err()
                );
                assert!(backend.set_datapath_ready(true).is_err());
                let storage = aya::maps::SkStorage::<_, TcpSocketBinding>::try_from(
                    backend.bpf().unwrap().map("TCP_SOCKET_BINDING").unwrap(),
                )
                .unwrap();
                assert!(storage.get(&tcp4, 0).is_err());
                assert!(storage.get(&tcp6, 0).is_err());
                let mut sockets = AyaSockMap::try_from(
                    backend
                        .bpf_mut()
                        .unwrap()
                        .map_mut("LISTEN_SOCKET_MAP")
                        .unwrap(),
                )
                .unwrap();
                for slot in [0, 1] {
                    assert!(RealEbpfBackend::sockmap_slot_is_empty(
                        &sockets.clear_index(&slot).unwrap_err()
                    ));
                }
                backend
                    .publish_listener_sockets(tcp4.as_raw_fd(), None, &[], &[])
                    .unwrap();
                backend.set_datapath_ready(true).unwrap();
                backend.set_datapath_ready(false).unwrap();
                let storage = aya::maps::SkStorage::<_, TcpSocketBinding>::try_from(
                    backend.bpf().unwrap().map("TCP_SOCKET_BINDING").unwrap(),
                )
                .unwrap();
                assert_eq!(storage.get(&tcp4, 0).unwrap().kind, TCP_BINDING_LISTENER);
                assert!(storage.get(&tcp6, 0).is_err());
                for name in ["honk_tcp_v6_route_req", "honk_tcp_v6_reqsk_destructor"] {
                    assert!(backend.bpf().unwrap().program(name).unwrap().fd().is_err());
                }
                backend.clear_listener_sockets().unwrap();
            }
            if case == "partial-v6" {
                let mut destructor = None;
                let mut lookup = None;
                for (name, program) in backend.bpf_mut().unwrap().programs_mut() {
                    match name {
                        "honk_tcp_v6_reqsk_destructor" => destructor = Some(program),
                        "tproxy_sk_lookup" => lookup = Some(program),
                        _ => {}
                    }
                }
                std::mem::swap(destructor.unwrap(), lookup.unwrap());
                let links = held_bpf_link_count();
                let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
                assert!(
                    backend
                        .publish_listener_sockets(
                            tcp4.as_raw_fd(),
                            Some(tcp6.as_raw_fd()),
                            &[],
                            &[]
                        )
                        .is_err()
                );
                assert_eq!(held_bpf_link_count(), links);
                assert!(backend.set_datapath_ready(true).is_err());
                let storage = aya::maps::SkStorage::<
                    _,
                    honk_ebpf_common::redirect_need::TcpSocketBinding,
                >::try_from(
                    backend.bpf().unwrap().map("TCP_SOCKET_BINDING").unwrap()
                )
                .unwrap();
                assert!(storage.get(&tcp4, 0).is_err());
                assert!(storage.get(&tcp6, 0).is_err());
            }
            backend.detach_hooks().unwrap();
            backend.cleanup().await.unwrap();
            std::fs::remove_dir_all(pin_root).unwrap();
            assert!(valid, "invalid BTF override allowed startup");
            assert_eq!(held_bpf_link_count(), before);
        });
}
