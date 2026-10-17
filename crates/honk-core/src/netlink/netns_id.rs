use super::*;
use std::os::fd::BorrowedFd;

const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;

impl NlSock {
    pub(crate) fn ensure_netns_id(&mut self, namespace: BorrowedFd<'_>) -> io::Result<i32> {
        let id = self.netns_id(namespace)?;
        if id >= 0 {
            return Ok(id);
        }
        match self.request(
            RTM_NEWNSID,
            NLM_F_REQUEST | NLM_F_ACK,
            &[0; 4],
            &[
                (NETNSA_NSID, Attr::U32(u32::MAX)),
                (NETNSA_FD, Attr::U32(namespace.as_raw_fd() as u32)),
            ],
        ) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
            Err(error) => return Err(error),
        }
        let id = self.netns_id(namespace)?;
        if id < 0 {
            return Err(io::Error::other("network namespace ID remains unassigned"));
        }
        Ok(id)
    }

    fn netns_id(&mut self, namespace: BorrowedFd<'_>) -> io::Result<i32> {
        self.seq = self.seq.wrapping_add(1);
        let mut request = [0u8; 28];
        request[..4].copy_from_slice(&28u32.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETNSID.to_ne_bytes());
        request[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        request[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        request[20..22].copy_from_slice(&8u16.to_ne_bytes());
        request[22..24].copy_from_slice(&NETNSA_FD.to_ne_bytes());
        request[24..].copy_from_slice(&namespace.as_raw_fd().to_ne_bytes());
        self.send_datagram(&request)?;
        let mut response = vec![0u8; 256];
        loop {
            let received = self.recv_one(&mut response)?;
            if let Some(id) = netns_id_reply(&response[..received], self.seq)? {
                return Ok(id);
            }
        }
    }
}

fn netns_id_reply(mut data: &[u8], sequence: u32) -> io::Result<Option<i32>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed namespace ID reply");
    while !data.is_empty() {
        if data.len() < 16 {
            return Err(invalid());
        }
        let length = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if length < 16 || length > data.len() {
            return Err(invalid());
        }
        let kind = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        let seq = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        if seq == sequence {
            match kind {
                NLMSG_ERROR => {
                    if length < 20 {
                        return Err(invalid());
                    }
                    let error = i32::from_ne_bytes(data[16..20].try_into().unwrap());
                    if error < 0 {
                        return Err(io::Error::from_raw_os_error(
                            error.checked_neg().ok_or_else(invalid)?,
                        ));
                    }
                    if error > 0 {
                        return Err(invalid());
                    }
                }
                RTM_NEWNSID => {
                    if length < 20 {
                        return Err(invalid());
                    }
                    let mut attrs = &data[20..length];
                    let mut id = None;
                    while !attrs.is_empty() {
                        if attrs.len() < 4 {
                            return Err(invalid());
                        }
                        let size = u16::from_ne_bytes(attrs[..2].try_into().unwrap()) as usize;
                        let kind = u16::from_ne_bytes(attrs[2..4].try_into().unwrap());
                        if size < 4 || size > attrs.len() {
                            return Err(invalid());
                        }
                        if kind == NETNSA_NSID {
                            if size != 8 || id.is_some() {
                                return Err(invalid());
                            }
                            let value = i32::from_ne_bytes(attrs[4..8].try_into().unwrap());
                            if value < -1 {
                                return Err(invalid());
                            }
                            id = Some(value);
                        }
                        attrs = attrs.get(align(size)..).ok_or_else(invalid)?;
                    }
                    return id.map(Some).ok_or_else(invalid);
                }
                _ => return Err(invalid()),
            }
        }
        data = data.get(align(length)..).ok_or_else(invalid)?;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn reply(id: i32) -> Vec<u8> {
        let mut value = vec![0u8; 20];
        value[4..6].copy_from_slice(&RTM_NEWNSID.to_ne_bytes());
        value[8..12].copy_from_slice(&7u32.to_ne_bytes());
        put_attr(&mut value, NETNSA_NSID, &Attr::U32(id as u32));
        let size = value.len() as u32;
        value[..4].copy_from_slice(&size.to_ne_bytes());
        value
    }

    #[test]
    fn namespace_reply_preserves_unassigned_and_rejects_ambiguous_ids() {
        for id in [-1, 0, 31] {
            assert_eq!(netns_id_reply(&reply(id), 7).unwrap(), Some(id));
            assert_eq!(netns_id_reply(&reply(id), 8).unwrap(), None);
        }
        assert!(netns_id_reply(&reply(-2), 7).is_err());
        let mut duplicate = reply(1);
        put_attr(&mut duplicate, NETNSA_NSID, &Attr::U32(2));
        let size = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&size.to_ne_bytes());
        assert!(netns_id_reply(&duplicate, 7).is_err());
        for end in 1..28 {
            assert!(netns_id_reply(&reply(1)[..end], 7).is_err());
        }
        let mut denied = vec![0u8; 20];
        denied[..4].copy_from_slice(&20u32.to_ne_bytes());
        denied[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        denied[8..12].copy_from_slice(&7u32.to_ne_bytes());
        denied[16..20].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            netns_id_reply(&denied, 7).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    #[ignore = "requires root and the disposable kernel VM gate"]
    fn netns_fd_ids_are_stable_and_distinct() {
        let make_namespace = || {
            std::thread::spawn(|| {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
                std::fs::File::open("/proc/thread-self/ns/net").unwrap()
            })
            .join()
            .unwrap()
        };
        let decoy = make_namespace();
        let namespace = make_namespace();
        let mut nl = NlSock::new().unwrap();
        assert_eq!(nl.netns_id(namespace.as_fd()).unwrap(), -1);
        let decoy_id = nl.ensure_netns_id(decoy.as_fd()).unwrap();
        let id = nl.ensure_netns_id(namespace.as_fd()).unwrap();
        assert!(id >= 0 && id != decoy_id);
        assert_eq!(nl.ensure_netns_id(namespace.as_fd()).unwrap(), id);
        let not_namespace = tempfile::tempfile().unwrap();
        assert!(nl.ensure_netns_id(not_namespace.as_fd()).is_err());
    }
}
