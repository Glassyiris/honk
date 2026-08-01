//! Bounded connected DNS-over-UDP exchange pool.
//!
//! A single generation-owned socket owns its receive loop. Requests receive a
//! pool-local DNS ID and are demultiplexed by ID plus question, so a delayed
//! packet cannot be delivered to a different question after ID reuse.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use honk_ebpf_common::DAE_BYPASS_MARK;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};

const MAX_PENDING: usize = 1024;
const ID_QUARANTINE: Duration = Duration::from_secs(3);

struct Pending {
    question: Vec<u8>,
    original_id: [u8; 2],
    reply: oneshot::Sender<Vec<u8>>,
}

struct State {
    next_id: u16,
    pending: HashMap<u16, Pending>,
    retired: VecDeque<(Instant, u16)>,
}

/// One bounded, connected socket for a direct UDP upstream.
pub struct UdpPool {
    socket: Arc<UdpSocket>,
    state: Mutex<State>,
    timeout: Duration,
}

impl UdpPool {
    pub async fn new(address: SocketAddr, timeout: Duration) -> anyhow::Result<Arc<Self>> {
        let domain = if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        honk_outbound::util::set_mark_best_effort(&socket, DAE_BYPASS_MARK)?;
        let unspecified = if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        socket.bind(&SocketAddr::new(unspecified, 0).into())?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);
        socket.connect(address).await?;
        let pool = Arc::new(Self {
            socket: Arc::clone(&socket),
            state: Mutex::new(State {
                next_id: 0,
                pending: HashMap::new(),
                retired: VecDeque::new(),
            }),
            timeout,
        });
        tokio::spawn(Self::receive_loop(Arc::downgrade(&pool), socket));
        Ok(pool)
    }

    pub async fn exchange(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if query.len() < 12 {
            anyhow::bail!("malformed DNS query");
        }
        let original_id = [query[0], query[1]];
        let question = query[12..Self::question_end(query)?].to_vec();
        let (reply, receiver) = oneshot::channel();
        let id = {
            let mut state = self.state.lock().await;
            Self::purge_retired(&mut state);
            if state.pending.len() >= MAX_PENDING {
                anyhow::bail!("UDP DNS exchange pool saturated");
            }
            let id = Self::allocate_id(&mut state)
                .ok_or_else(|| anyhow::anyhow!("UDP DNS IDs exhausted"))?;
            state.pending.insert(
                id,
                Pending {
                    question,
                    original_id,
                    reply,
                },
            );
            id
        };
        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&id.to_be_bytes());
        if let Err(error) = self.socket.send(&wire).await {
            self.unregister(id).await;
            return Err(error.into());
        }
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => anyhow::bail!("UDP DNS receive loop stopped"),
            Err(_) => {
                self.unregister(id).await;
                anyhow::bail!("UDP DNS query timed out after {:?}", self.timeout)
            }
        }
    }

    async fn receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0; 65535];
        loop {
            let Ok(Ok(length)) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buffer)).await
            else {
                if pool.strong_count() == 0 {
                    break;
                }
                continue;
            };
            if length < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            let pending = {
                let mut state = pool.state.lock().await;
                let matches = Self::question_end(&buffer[..length]).is_ok_and(|end| {
                    state
                        .pending
                        .get(&id)
                        .is_some_and(|pending| pending.question == buffer[12..end])
                });
                if matches {
                    state.pending.remove(&id)
                } else {
                    None
                }
            };
            if let Some(pending) = pending {
                let mut response = buffer[..length].to_vec();
                response[..2].copy_from_slice(&pending.original_id);
                let _ = pending.reply.send(response);
            }
        }
    }

    async fn unregister(&self, id: u16) {
        let mut state = self.state.lock().await;
        if state.pending.remove(&id).is_some() {
            Self::retire_id(&mut state, id);
        }
    }

    fn purge_retired(state: &mut State) {
        let now = Instant::now();
        while state
            .retired
            .front()
            .is_some_and(|(until, _)| *until <= now)
        {
            state.retired.pop_front();
        }
    }
    fn retire_id(state: &mut State, id: u16) {
        state
            .retired
            .push_back((Instant::now() + ID_QUARANTINE, id));
    }
    fn question_end(wire: &[u8]) -> anyhow::Result<usize> {
        if wire.len() < 17 {
            anyhow::bail!("malformed DNS question");
        }
        let mut index = 12;
        loop {
            let label_len = *wire
                .get(index)
                .ok_or_else(|| anyhow::anyhow!("malformed DNS name"))?
                as usize;
            index += 1;
            if label_len == 0 {
                break;
            }
            if label_len > 63 || index + label_len > wire.len() {
                anyhow::bail!("malformed DNS name");
            }
            index += label_len;
        }
        if index + 4 > wire.len() {
            anyhow::bail!("malformed DNS question");
        }
        Ok(index + 4)
    }
    fn allocate_id(state: &mut State) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            if !state.pending.contains_key(&id)
                && !state.retired.iter().any(|(_, retired)| *retired == id)
            {
                return Some(id);
            }
        }
        None
    }
}
