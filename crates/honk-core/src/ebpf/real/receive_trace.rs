//! Bounded socket-cookie registrations, synchronously armed and drained by the receive owner.

use std::io;
use std::os::fd::{AsFd, RawFd};
use std::sync::Arc;

use aya::maps::{HashMap, Map, MapData};
use aya::programs::{FEntry, FExit, fentry::FEntryLink, fexit::FExitLink};
use aya::{Btf, Ebpf, EbpfLoader};
use honk_ebpf_common::receive_trace::{
    RECEIVE_TRACE_BATCH_SIZE, RECEIVE_TRACE_VALID, ReceiveTraceBatch, ReceiveTracePacket,
};
use parking_lot::Mutex;

use super::btf::Btf as OffsetBtf;
use super::process_name::{VMLINUX_BTF_ENV, VMLINUX_BTF_PATHS};

#[derive(Clone, Copy, Debug)]
pub(super) struct ReceiveTraceOffsets {
    cookie: u32,
    priority: u32,
    mark: u32,
}

impl ReceiveTraceOffsets {
    pub(super) fn configure<'a>(&'a self, loader: &mut EbpfLoader<'a>) {
        loader
            .override_global("RECEIVE_SOCK_COOKIE_OFFSET", &self.cookie, true)
            .override_global("RECEIVE_SKB_PRIORITY_OFFSET", &self.priority, true)
            .override_global("RECEIVE_SKB_MARK_OFFSET", &self.mark, true);
    }
}

pub(super) fn detect() -> Option<ReceiveTraceOffsets> {
    fn offsets(data: &[u8]) -> Option<ReceiveTraceOffsets> {
        let btf = OffsetBtf::parse(data)?;
        let common = btf.member_offset("sock", "__sk_common")?;
        let cookie =
            common.checked_add(btf.sized_member_offset("sock_common", "skc_cookie", 8)?)?;
        Some(ReceiveTraceOffsets {
            cookie,
            priority: btf.sized_member_offset("sk_buff", "priority", 4)?,
            mark: btf.sized_member_offset("sk_buff", "mark", 4)?,
        })
    }
    if let Some(path) = std::env::var_os(VMLINUX_BTF_ENV) {
        return offsets(&std::fs::read(path).ok()?);
    }
    VMLINUX_BTF_PATHS
        .iter()
        .find_map(|path| offsets(&std::fs::read(path).ok()?))
}

pub struct ReceiveTrace {
    map: Mutex<HashMap<MapData, u64, ReceiveTraceBatch>>,
    _entries: Vec<FEntryLink>,
    _exits: Vec<FExitLink>,
}

impl ReceiveTrace {
    #[cfg(test)]
    pub(crate) fn load_for_test() -> anyhow::Result<(Ebpf, Arc<Self>)> {
        let offsets =
            detect().ok_or_else(|| anyhow::anyhow!("receive trace BTF offsets unavailable"))?;
        let mut loader = EbpfLoader::new();
        offsets.configure(&mut loader);
        let mut bpf = loader.load(crate::DEFAULT_BPF_OBJECT)?;
        let trace = Self::attach(&mut bpf)?;
        Ok((bpf, trace))
    }

    pub(super) fn attach(bpf: &mut Ebpf) -> anyhow::Result<Arc<Self>> {
        let btf = Btf::from_sys_fs()?;
        let mut entries = Vec::with_capacity(2);
        let mut exits = Vec::with_capacity(3);
        for (name, target) in [
            ("honk_udp_receive_enter", "udp_recvmsg"),
            ("honk_udp6_receive_enter", "udpv6_recvmsg"),
        ] {
            let program: &mut FEntry = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing receive program {name}"))?
                .try_into()?;
            program.load(target, &btf)?;
            let link = program.attach()?;
            entries.push(program.take_link(link)?);
        }
        for (name, target) in [
            ("honk_udp_receive_exit", "udp_recvmsg"),
            ("honk_udp6_receive_exit", "udpv6_recvmsg"),
            ("honk_udp_receive_candidate", "__skb_recv_udp"),
        ] {
            let program: &mut FExit = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing receive program {name}"))?
                .try_into()?;
            program.load(target, &btf)?;
            let link = program.attach()?;
            exits.push(program.take_link(link)?);
        }
        let Some(Map::HashMap(map)) = bpf.map("RECEIVE_TRACE") else {
            anyhow::bail!("missing RECEIVE_TRACE hash map");
        };
        let map = MapData::from_fd(map.fd().as_fd().try_clone_to_owned()?)?;
        Ok(Arc::new(Self {
            map: Mutex::new(HashMap::try_from(Map::HashMap(map))?),
            _entries: entries,
            _exits: exits,
        }))
    }

    pub(crate) fn register(self: &Arc<Self>, fd: RawFd) -> io::Result<ReceiveRegistration> {
        let mut cookie = 0u64;
        let mut size = std::mem::size_of_val(&cookie) as libc::socklen_t;
        // SO_COOKIE initializes the exact field subsequently read by the hooks.
        let status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut size,
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of::<u64>() || cookie == 0 {
            return Err(io::Error::other("invalid owned UDP socket cookie"));
        }
        self.map
            .lock()
            .insert(cookie, ReceiveTraceBatch::default(), 1)
            .map_err(io::Error::other)?;
        Ok(ReceiveRegistration {
            trace: self.clone(),
            fd,
            cookie,
            epoch: 0,
        })
    }
}

pub(crate) struct ReceiveRegistration {
    trace: Arc<ReceiveTrace>,
    fd: RawFd,
    cookie: u64,
    epoch: u64,
}

impl ReceiveRegistration {
    pub(crate) fn begin(&mut self, fd: RawFd) -> bool {
        if fd != self.fd {
            return false;
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            return false;
        };
        self.epoch = epoch;
        self.trace
            .map
            .lock()
            .insert(
                self.cookie,
                ReceiveTraceBatch {
                    epoch,
                    active: 1,
                    ..Default::default()
                },
                2,
            )
            .is_ok()
    }

    pub(crate) fn finish(
        &self,
        count: usize,
    ) -> Option<[ReceiveTracePacket; RECEIVE_TRACE_BATCH_SIZE]> {
        let mut map = self.trace.map.lock();
        let batch = map.get(&self.cookie, 0).ok();
        // Even an errored syscall or failed read must disarm the registration.
        let disarmed = map
            .insert(self.cookie, ReceiveTraceBatch::default(), 2)
            .is_ok();
        let batch = batch?;
        if !disarmed
            || batch.epoch != self.epoch
            || batch.active != 1
            || batch.count as usize != count
            || batch.depth != 0
            || batch.lost != 0
            || count > RECEIVE_TRACE_BATCH_SIZE
        {
            return None;
        }
        Some(batch.packets)
    }
}

impl Drop for ReceiveRegistration {
    fn drop(&mut self) {
        let _ = self.trace.map.lock().remove(&self.cookie);
    }
}

pub(crate) fn packet_priority(
    packet: ReceiveTracePacket,
    length: u32,
    mark: Option<u32>,
) -> Option<u32> {
    (packet.valid == RECEIVE_TRACE_VALID && packet.length == length && mark == Some(packet.mark))
        .then_some(packet.priority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    #[ignore = "requires Linux 6.12+ and root; run in the eBPF VM"]
    fn receive_trace_registration_loss_and_successful_zero_byte() -> anyhow::Result<()> {
        let (bpf, trace) = ReceiveTrace::load_for_test()?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_nonblocking(true)?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut registration = trace.register(receiver.as_raw_fd())?;
        assert!(trace.register(receiver.as_raw_fd()).is_err());
        let cookie = registration.cookie;

        // Hooks and maps are owned by the registration, not the loader/backend.
        drop(bpf);
        drop(trace);
        let mut buffer = [0u8; 8];
        for (payload, flags, success, evidence) in [
            (Some(&b"peek"[..]), libc::MSG_PEEK, true, false),
            (None, 0, true, true),
            (Some(&b""[..]), 0, true, true),
            (None, 0, false, true),
            (Some(&b"after"[..]), 0, true, true),
            (None, libc::MSG_ERRQUEUE, false, false),
        ] {
            if let Some(payload) = payload {
                sender.send_to(payload, receiver.local_addr()?)?;
            }
            assert!(registration.begin(receiver.as_raw_fd()));
            let length = unsafe {
                libc::recv(
                    receiver.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    flags | libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(length >= 0, success);
            let metadata = registration.finish(usize::from(success));
            assert_eq!(metadata.is_some(), evidence);
            if success && evidence {
                let packet = metadata.unwrap()[0];
                assert_eq!(packet.valid, RECEIVE_TRACE_VALID);
                assert_eq!(packet.length, length as u32);
            }
        }

        for loss in 0..5 {
            assert!(registration.begin(receiver.as_raw_fd()));
            let mut batch = ReceiveTraceBatch {
                epoch: registration.epoch,
                active: 1,
                count: 3,
                ..Default::default()
            };
            for (index, packet) in batch.packets[..3].iter_mut().enumerate() {
                *packet = ReceiveTracePacket {
                    priority: index as u32 + 100,
                    mark: 77,
                    length: 1,
                    valid: RECEIVE_TRACE_VALID,
                };
            }
            match loss {
                0 => batch.packets[1].valid = 0,
                1 => batch.count = 2,
                2 => batch.epoch -= 1,
                3 => batch.depth = 1,
                _ => batch.lost = 1,
            }
            registration.trace.map.lock().insert(cookie, batch, 2)?;
            let result = registration.finish(3);
            if loss == 0 {
                let packets = result.expect("located candidate hole retains other slots");
                assert_eq!(packet_priority(packets[0], 1, Some(77)), Some(100));
                assert_eq!(packet_priority(packets[1], 1, Some(77)), None);
                assert_eq!(packet_priority(packets[2], 1, Some(77)), Some(102));
                assert_eq!(packet_priority(packets[2], 1, Some(78)), None);
                assert_eq!(packet_priority(packets[2], 2, Some(77)), None);
            } else {
                assert!(result.is_none(), "unlocated loss must invalidate the batch");
            }
        }

        let trace = registration.trace.clone();
        drop(registration);
        assert!(trace.map.lock().get(&cookie, 0).is_err());
        let mut registration = trace.register(receiver.as_raw_fd())?;
        assert!(registration.begin(receiver.as_raw_fd()));
        assert!(registration.finish(0).is_some());
        Ok(())
    }
}
