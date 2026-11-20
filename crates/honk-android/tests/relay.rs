//! End to end on the build host, no tun needed: a SOCK_SEQPACKET socketpair stands in for the
//! tun fd (it keeps packet boundaries), an endpoint-mode honk Stack plays the apps behind the
//! VPN, and a loopback TCP server is the upstream. Every flow uploads, then the server answers
//! with a download; byte counts and EOFs must match in both directions.

use honk_netstack::{Config, Stack, StreamError};
use honkengine::engine;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const UP: u64 = 8 << 20;
const DOWN: u64 = 12 << 20;

fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: fds is valid for two ints.
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    assert_eq!(r, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn upstream() -> (u16, mpsc::Receiver<u64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let mut s = s.unwrap();
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 << 10];
                let mut got = 0u64;
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => got += n as u64,
                        Err(e) => panic!("upstream read: {e}"),
                    }
                }
                tx.send(got).unwrap();
                let mut left = DOWN;
                while left > 0 {
                    let n = left.min(buf.len() as u64) as usize;
                    s.write_all(&buf[..n]).unwrap();
                    left -= n as u64;
                }
            });
        }
    });
    (port, rx)
}

fn relay(flows: usize, mtu: u16) {
    let (port, uploads) = upstream();
    let (tun, peer) = seqpacket_pair();
    let params = engine::Params::parse(
        tun.as_raw_fd(),
        i32::from(mtu),
        "127.0.0.1",
        i32::from(port),
        "",
    )
    .unwrap();
    let handle = engine::start(params).unwrap();

    let peer = peer.as_raw_fd();
    honkengine::sys::set_nonblocking(peer).unwrap();
    let t0 = Instant::now();
    let mut cfg = Config::new([1; 32]);
    cfg.local_v4 = Some(Ipv4Addr::new(198, 18, 0, 2));
    cfg.mtu = mtu;
    let mut st = Stack::new(cfg, t0);
    let ids: Vec<_> = (0..flows)
        .map(|i| {
            let dst = SocketAddr::from(([198, 18, 0, 1], 5000 + i as u16));
            st.tcp_connect(t0, dst).unwrap()
        })
        .collect();
    let data = vec![0x5a; 64 << 10];
    let mut buf = vec![0u8; 65536];
    let mut pkt = vec![0u8; usize::from(mtu) + 64];
    let (mut written, mut read) = (vec![0u64; flows], vec![0u64; flows]);
    let (mut shut, mut eof) = (vec![false; flows], vec![false; flows]);
    let deadline = t0 + Duration::from_secs(120);
    while eof.iter().any(|e| !e) {
        let now = Instant::now();
        assert!(
            now < deadline,
            "timed out: written {written:?} read {read:?}"
        );
        loop {
            match honkengine::sys::read(peer, &mut buf) {
                Ok(n) => {
                    st.receive(now, &buf[..n]);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("peer read: {e}"),
            }
        }
        if st.poll_timeout().is_some_and(|d| d <= now) {
            st.handle_timeout(now);
        }
        while st.poll_event().is_some() {}
        for (i, &id) in ids.iter().enumerate() {
            while written[i] < UP {
                let n = (UP - written[i]).min(data.len() as u64) as usize;
                match st.tcp_write(id, &data[..n]) {
                    Ok(w) => written[i] += w as u64,
                    Err(StreamError::WouldBlock) => break,
                    Err(e) => panic!("write {i}: {e}"),
                }
            }
            if written[i] == UP && !shut[i] {
                st.tcp_shutdown(id).unwrap();
                shut[i] = true;
            }
            while !eof[i] {
                match st.tcp_read(id, &mut buf) {
                    Ok(0) => eof[i] = true,
                    Ok(n) => read[i] += n as u64,
                    Err(StreamError::WouldBlock) => break,
                    Err(e) => panic!("read {i}: {e}"),
                }
            }
        }
        while let Some(n) = st.poll_transmit(now, &mut pkt) {
            loop {
                match honkengine::sys::write(peer, &pkt[..n]) {
                    Ok(_) => break,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_micros(50))
                    }
                    Err(e) => panic!("peer write: {e}"),
                }
            }
        }
        let mut pfd = libc::pollfd {
            fd: peer,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is valid for the call.
        unsafe { libc::poll(&mut pfd, 1, 1) };
    }
    for _ in 0..flows {
        assert_eq!(uploads.recv_timeout(Duration::from_secs(5)).unwrap(), UP);
    }
    assert!(read.iter().all(|&r| r == DOWN), "read {read:?}");
    let s = &engine::SHARED;
    let tx = s.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    let rx = s.rx_packets.load(std::sync::atomic::Ordering::Relaxed);
    assert!(tx > 0 && rx > 0);
    eprintln!(
        "flows {flows} mtu {mtu}: engine tun tx {tx} pkts, rx {rx} pkts in {:?}",
        t0.elapsed()
    );
    handle.stop();
}

#[test]
fn relay_one_flow_mtu1500_then_four_flows_mtu8500() {
    // Sequential: the engine is a process-wide singleton (its counters are global).
    relay(1, 1500);
    relay(4, 8500);
}
