use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const DEFRAG_MAX_PENDING: usize = 64;
const DEFRAG_MAX_FRAGMENTS: usize = 64;
const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

struct DefragBuffer {
    frags: Vec<Option<Vec<u8>>>,
    peer: Option<SocketAddr>,
    count: usize,
    bytes: usize,
    updated: Instant,
}

pub(crate) struct Defragmenter {
    map: HashMap<u64, DefragBuffer>,
    latest_packet: Option<u64>,
    max_payload: usize,
}

impl Defragmenter {
    pub(crate) fn new(max_payload: usize) -> Self {
        Self {
            map: HashMap::new(),
            latest_packet: None,
            max_payload,
        }
    }

    fn packet_key(&mut self, packet_id: u16) -> u64 {
        let packet_id = u64::from(packet_id);
        let Some(latest) = self.latest_packet else {
            // Leave one complete cycle below the initial key for delayed fragments.
            let key = (1 << 16) | packet_id;
            self.latest_packet = Some(key);
            return key;
        };
        let base = latest & !u64::from(u16::MAX);
        let candidate = base | packet_id;
        let delta = candidate as i128 - latest as i128;
        let key = if delta > i128::from(1u64 << 15) {
            candidate.saturating_sub(1 << 16)
        } else if delta < -i128::from(1u64 << 15) {
            candidate.saturating_add(1 << 16)
        } else {
            candidate
        };
        if key > latest {
            self.latest_packet = Some(key);
        }
        key
    }

    pub(crate) fn feed(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        peer: Option<SocketAddr>,
        data: Vec<u8>,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        if frag_total == 0
            || usize::from(frag_id) >= usize::from(frag_total)
            || usize::from(frag_total) > DEFRAG_MAX_FRAGMENTS
            || data.len() > self.max_payload
        {
            return None;
        }
        let peer = peer.map(|peer| match peer {
            SocketAddr::V6(v6) => v6
                .ip()
                .to_ipv4_mapped()
                .map(|ip| SocketAddr::new(ip.into(), v6.port()))
                .unwrap_or(peer),
            SocketAddr::V4(_) => peer,
        });
        let packet_key = self.packet_key(packet_id);
        if frag_total == 1 {
            return peer.map(|peer| (data, peer));
        }
        let frag_total = usize::from(frag_total);
        if self.map.len() >= DEFRAG_MAX_PENDING && !self.map.contains_key(&packet_key) {
            self.map
                .retain(|_, buffer| buffer.updated.elapsed() < DEFRAG_MAX_AGE);
            if self.map.len() >= DEFRAG_MAX_PENDING {
                return None;
            }
        }
        let entry = self.map.entry(packet_key).or_insert_with(|| DefragBuffer {
            frags: (0..frag_total).map(|_| None).collect(),
            peer: None,
            count: 0,
            bytes: 0,
            updated: Instant::now(),
        });
        if entry.updated.elapsed() >= DEFRAG_MAX_AGE || entry.frags.len() != frag_total {
            entry.frags = (0..frag_total).map(|_| None).collect();
            entry.peer = None;
            entry.count = 0;
            entry.bytes = 0;
        }
        let frag_id = usize::from(frag_id);
        if entry.frags[frag_id].is_some() {
            return None;
        }
        if let (Some(chosen), Some(peer)) = (entry.peer, peer)
            && chosen != peer
        {
            return None;
        }
        let Some(bytes) = entry.bytes.checked_add(data.len()) else {
            self.map.remove(&packet_key);
            return None;
        };
        if bytes > self.max_payload {
            self.map.remove(&packet_key);
            return None;
        }
        entry.peer = entry.peer.or(peer);
        entry.frags[frag_id] = Some(data);
        entry.count += 1;
        entry.bytes = bytes;
        entry.updated = Instant::now();
        if entry.count != entry.frags.len() {
            return None;
        }
        let entry = self.map.remove(&packet_key).expect("entry just inserted");
        let mut data = Vec::with_capacity(entry.bytes);
        for frag in entry.frags.into_iter().flatten() {
            data.extend_from_slice(&frag);
        }
        entry.peer.map(|peer| (data, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);

    #[test]
    fn mapped_peers_match_ipv4_without_changing_native_ipv6() {
        let mapped = "[::ffff:127.0.0.1]:53".parse().unwrap();
        let mut defrag = Defragmenter::new(4);
        for (first, last) in [(PEER, mapped), (mapped, PEER)] {
            assert!(defrag.feed(7, 0, 2, Some(first), vec![1]).is_none());
            assert_eq!(
                defrag.feed(7, 0, 1, Some(mapped), vec![3]),
                Some((vec![3], PEER))
            );
            assert_eq!(
                defrag.feed(7, 1, 2, Some(last), vec![2]),
                Some((vec![1, 2], PEER))
            );
        }
        let native = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            5353,
            17,
            23,
        ));
        assert_eq!(
            defrag.feed(8, 0, 1, Some(native), vec![1]),
            Some((vec![1], native))
        );
        assert!(defrag.feed(8, 1, 2, Some(native), vec![2]).is_none());
        assert_eq!(
            defrag.feed(8, 0, 2, Some(native), vec![1]),
            Some((vec![1, 2], native))
        );
    }

    #[test]
    fn reassembly_is_bounded_and_packet_id_wrap_is_distinct() {
        let mut defrag = Defragmenter::new(4);
        assert!(defrag.feed(7, 0, 65, Some(PEER), vec![]).is_none());
        assert!(defrag.feed(8, 0, 2, Some(PEER), vec![1, 2, 3]).is_none());
        assert!(defrag.feed(8, 1, 2, Some(PEER), vec![4, 5]).is_none());

        assert!(defrag.feed(0, 0, 2, Some(PEER), vec![0]).is_none());
        assert_eq!(
            defrag.feed(32_767, 0, 1, Some(PEER), vec![0]),
            Some((vec![0], PEER))
        );
        assert_eq!(
            defrag.feed(65_534, 0, 1, Some(PEER), vec![0]),
            Some((vec![0], PEER))
        );
        assert_eq!(
            defrag.feed(1, 0, 1, Some(PEER), vec![0]),
            Some((vec![0], PEER))
        );
        assert!(defrag.feed(0, 0, 2, Some(PEER), vec![2]).is_none());
        assert_eq!(
            defrag.feed(0, 1, 2, Some(PEER), vec![3]),
            Some((vec![2, 3], PEER))
        );
    }

    #[test]
    fn inferred_previous_cycle_ids_never_alias() {
        let mut defrag = Defragmenter::new(8);
        assert!(defrag.feed(1, 0, 2, Some(PEER), vec![1]).is_none());
        assert!(defrag.feed(40_001, 0, 2, Some(PEER), vec![2]).is_none());
        assert!(defrag.feed(50_001, 1, 2, Some(PEER), vec![3]).is_none());
        assert_eq!(
            defrag.feed(40_001, 1, 2, Some(PEER), vec![4]),
            Some((vec![2, 4], PEER))
        );
        assert_eq!(
            defrag.feed(50_001, 0, 2, Some(PEER), vec![5]),
            Some((vec![5, 3], PEER))
        );
    }

    #[test]
    fn delayed_previous_cycle_fragments_do_not_collide() {
        let mut defrag = Defragmenter::new(8);
        assert!(defrag.feed(65_530, 0, 2, Some(PEER), vec![1]).is_none());
        assert!(defrag.feed(100, 0, 2, Some(PEER), vec![2]).is_none());
        assert!(defrag.feed(0, 0, 2, Some(PEER), vec![3]).is_none());
        assert!(defrag.feed(65_500, 0, 2, Some(PEER), vec![4]).is_none());
        assert_eq!(
            defrag.feed(0, 1, 2, Some(PEER), vec![5]),
            Some((vec![3, 5], PEER))
        );
        assert_eq!(
            defrag.feed(65_500, 1, 2, Some(PEER), vec![6]),
            Some((vec![4, 6], PEER))
        );
    }

    #[test]
    fn an_expired_buffer_does_not_absorb_a_new_packet() {
        let mut defrag = Defragmenter::new(8);
        assert!(defrag.feed(7, 0, 2, Some(PEER), vec![1]).is_none());
        let key = defrag.packet_key(7);
        defrag.map.get_mut(&key).expect("buffer pending").updated =
            Instant::now() - DEFRAG_MAX_AGE - Duration::from_secs(1);
        assert!(defrag.feed(7, 1, 2, Some(PEER), vec![3]).is_none());
        assert_eq!(
            defrag.feed(7, 0, 2, Some(PEER), vec![2]),
            Some((vec![2, 3], PEER))
        );
    }

    #[test]
    fn malformed_fragments_do_not_advance_packet_epoch() {
        let mut defrag = Defragmenter::new(8);
        assert_eq!(defrag.packet_key(10), (1 << 16) | 10);
        assert!(defrag.feed(65_000, 0, 65, Some(PEER), vec![1]).is_none());
        assert_eq!(defrag.latest_packet, Some((1 << 16) | 10));
        assert!(defrag.feed(11, 0, 2, Some(PEER), vec![2]).is_none());
        assert_eq!(
            defrag.feed(11, 1, 2, Some(PEER), vec![3]),
            Some((vec![2, 3], PEER))
        );
    }

    #[test]
    fn peer_metadata_obeys_duplicate_conflict_and_entry_lifetime() {
        let other: SocketAddr = "192.0.2.99:99".parse().unwrap();
        let mut defrag = Defragmenter::new(4);
        assert!(defrag.feed(7, 1, 3, None, vec![2]).is_none());
        assert!(defrag.feed(7, 1, 3, Some(other), vec![9, 9, 9]).is_none());
        assert!(defrag.feed(7, 0, 3, Some(PEER), vec![1]).is_none());
        let key = defrag.packet_key(7);
        let before = &defrag.map[&key];
        assert_eq!(
            (before.count, before.bytes, before.peer),
            (2, 2, Some(PEER))
        );
        assert!(defrag.feed(7, 2, 3, Some(other), vec![9]).is_none());
        let after = &defrag.map[&key];
        assert_eq!((after.count, after.bytes, after.peer), (2, 2, Some(PEER)));
        assert_eq!(
            defrag.feed(7, 2, 3, None, vec![3]),
            Some((vec![1, 2, 3], PEER))
        );
        assert!(!defrag.map.contains_key(&key));

        assert!(defrag.feed(7, 0, 2, Some(PEER), vec![1]).is_none());
        defrag.map.get_mut(&key).unwrap().updated = Instant::now() - DEFRAG_MAX_AGE;
        assert!(defrag.feed(7, 1, 2, None, vec![4]).is_none());
        assert_eq!(defrag.map[&key].peer, None);
        assert_eq!(
            defrag.feed(7, 0, 2, Some(other), vec![3]),
            Some((vec![3, 4], other))
        );

        assert!(defrag.feed(7, 0, 3, Some(PEER), vec![1]).is_none());
        assert!(defrag.feed(7, 1, 2, None, vec![4]).is_none());
        assert_eq!(defrag.map[&key].peer, None);
        assert_eq!(
            defrag.feed(7, 0, 2, Some(other), vec![3]),
            Some((vec![3, 4], other))
        );
        assert!(defrag.feed(7, 0, 2, Some(PEER), vec![1]).is_none());
        assert_eq!(
            defrag.feed(7, 0, 1, Some(other), vec![]),
            Some((vec![], other))
        );
        assert_eq!(
            defrag.feed(7, 1, 2, None, vec![2]),
            Some((vec![1, 2], PEER))
        );
    }

    #[test]
    fn pending_peer_entries_remain_bounded_and_expire_together() {
        let mut defrag = Defragmenter::new(4);
        for packet in 0..DEFRAG_MAX_PENDING as u16 {
            assert!(defrag.feed(packet, 0, 2, Some(PEER), vec![1]).is_none());
        }
        assert!(defrag.feed(100, 0, 2, Some(PEER), vec![1]).is_none());
        assert_eq!(defrag.map.len(), DEFRAG_MAX_PENDING);
        assert!(!defrag.map.contains_key(&((1 << 16) | 100)));
        for entry in defrag.map.values_mut() {
            entry.updated = Instant::now() - DEFRAG_MAX_AGE;
        }
        assert!(defrag.feed(100, 1, 2, None, vec![2]).is_none());
        assert_eq!(defrag.map.len(), 1);
        assert_eq!(
            defrag.feed(100, 0, 2, Some(PEER), vec![1]),
            Some((vec![1, 2], PEER))
        );
    }

    #[test]
    fn wrapped_packet_ids_do_not_reuse_old_peer_metadata() {
        let mut defrag = Defragmenter::new(4);
        let other = "192.0.2.99:99".parse().unwrap();
        assert!(defrag.feed(0, 0, 2, Some(PEER), vec![1]).is_none());
        for packet in [32_767, 65_534, 1] {
            assert_eq!(
                defrag.feed(packet, 0, 1, Some(other), vec![]),
                Some((vec![], other))
            );
        }
        assert!(defrag.feed(0, 1, 2, None, vec![3]).is_none());
        assert_eq!(
            defrag.feed(0, 0, 2, Some(other), vec![2]),
            Some((vec![2, 3], other))
        );
    }
}
