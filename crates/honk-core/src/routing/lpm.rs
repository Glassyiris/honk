use super::*;

/// Binary LPM trie. Insert CIDRs and check IP matches in O(key_bits) time.
/// Handles IPv4 (32-bit trie) and IPv6 (128-level trie).
#[derive(Debug, Clone)]
pub(crate) struct BinaryLpmTrie {
    nodes: Vec<TrieNode>,
    key_bits: u8,
}

#[derive(Debug, Clone, Copy, Default)]
struct TrieNode {
    zero: u32,
    one: u32,
    matched: bool,
}

impl BinaryLpmTrie {
    pub(crate) fn from_nets(nets: &[ipnet::IpNet]) -> Self {
        if nets.is_empty() {
            return Self {
                nodes: vec![TrieNode::default()],
                key_bits: 32,
            };
        }

        // Determine address family from the first entry.
        let first = nets[0].addr();
        let (key_bits, to_chunks) = if first.is_ipv4() {
            (32u8, ipv4_to_chunks as fn(IpAddr) -> Vec<u8>)
        } else {
            (128u8, ipv6_to_chunks as fn(IpAddr) -> Vec<u8>)
        };

        let mut trie = Self {
            nodes: vec![TrieNode::default()],
            key_bits,
        };

        for net in nets {
            // Skip entries of the wrong family (shouldn't happen, but be safe).
            if net.addr().is_ipv4() != (key_bits == 32) {
                continue;
            }
            let chunks = to_chunks(net.addr());
            let prefix = net.prefix_len() as u32;
            trie.insert(&chunks, prefix);
        }

        trie
    }

    fn insert(&mut self, chunks: &[u8], prefix: u32) {
        let mut node_idx = 0u32;
        for bit_idx in 0..prefix {
            let byte = chunks[(bit_idx / 8) as usize];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;

            // Read the current child index (copy out of self.nodes).
            let child_val = if bit == 0 {
                self.nodes[node_idx as usize].zero
            } else {
                self.nodes[node_idx as usize].one
            };

            let next_idx = if child_val == 0 {
                let new_idx = self.nodes.len() as u32;
                self.nodes.push(TrieNode::default());
                let parent = &mut self.nodes[node_idx as usize];
                if bit == 0 {
                    parent.zero = new_idx;
                } else {
                    parent.one = new_idx;
                }
                new_idx
            } else {
                child_val
            };
            node_idx = next_idx;
        }
        self.nodes[node_idx as usize].matched = true;
    }

    pub(crate) fn matches(&self, ip: &IpAddr) -> bool {
        if self.nodes.len() <= 1 {
            return false; // only root, no entries
        }

        let chunks: Vec<u8> = if ip.is_ipv4() {
            if self.key_bits != 32 {
                return false;
            }
            ipv4_to_chunks(*ip)
        } else {
            if self.key_bits != 128 {
                return false;
            }
            ipv6_to_chunks(*ip)
        };

        let mut node_idx = 0u32;
        for bit_idx in 0..self.key_bits as u32 {
            if self.nodes[node_idx as usize].matched {
                return true;
            }
            let byte = chunks[(bit_idx / 8) as usize];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;

            let child = if bit == 0 {
                self.nodes[node_idx as usize].zero
            } else {
                self.nodes[node_idx as usize].one
            };

            if child == 0 {
                return self.nodes[node_idx as usize].matched;
            }
            node_idx = child;
        }
        self.nodes[node_idx as usize].matched
    }
}

fn ipv4_to_chunks(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(_) => unreachable!(),
    }
}

fn ipv6_to_chunks(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V6(v6) => v6.octets().to_vec(),
        IpAddr::V4(_) => unreachable!(),
    }
}
