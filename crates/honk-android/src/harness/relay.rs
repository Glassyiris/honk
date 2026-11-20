//! The SOCKS5 front hev connects to, standing in for a proxy: CONNECT without authentication
//! only, and every request goes on to one fixed upstream (the sink) whatever destination it
//! names. Owns the relay role's threads: a pinned acceptor, then two threads per connection,
//! one per direction, so a half-close in one direction leaves the other open.
//!
//! Blocking `std::net` sockets and no runtime, so the relay adds no threads or timers of its own
//! to the measured process. It never times out by itself; `stop` (from the runner thread, after
//! the engine has stopped) shuts its streams down.

use super::load::{Conns, Server, WRITE_SIZE};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Barrier, mpsc};
use std::thread;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const CONNECT: u8 = 1;
const SUCCEEDED: u8 = 0;
const GENERAL_FAILURE: u8 = 1;
const CONNECTION_REFUSED: u8 = 5;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

pub struct Relay {
    pub server: Server,
}

impl Relay {
    pub fn start(upstream: SocketAddr, cpus: &[usize]) -> Result<Relay, String> {
        let server = Server::start("tb-relay", cpus, move |client, conns| {
            serve(client, conns, upstream)
        })?;
        Ok(Relay { server })
    }
}

fn serve(client: TcpStream, conns: &Conns, upstream: SocketAddr) {
    // Both directions are registered before the upstream connect, so the sink accepting this
    // flow proves that the accounting lists all of it; and both stay until both have ended, so
    // a window read after one direction drained still finds them.
    let (entered, ended) = (Barrier::new(2), Barrier::new(2));
    thread::scope(|s| {
        let (tx, rx) = mpsc::channel::<TcpStream>();
        let (client, entered, ended) = (&client, &entered, &ended);
        let back = thread::Builder::new()
            .name("tb-relay".into())
            .spawn_scoped(s, move || {
                let _guard = conns.threads.enter();
                entered.wait();
                if let Ok(upstream) = rx.recv() {
                    pump(&upstream, client);
                    ended.wait();
                }
            });
        let Ok(back) = back else { return };
        entered.wait();
        if let Ok(upstream) = accept_connect(client, upstream)
            && let Ok(_tracked) = conns.streams.track(&upstream)
            && let Ok(back_end) = upstream.try_clone()
        {
            // The other direction is past the barrier and waits for this.
            let _ = tx.send(back_end);
            pump(client, &upstream);
            ended.wait();
            let _ = back.join();
        }
    });
}

/// Copies until EOF or an error, then half-closes the far side.
fn pump(from: &TcpStream, to: &TcpStream) {
    let mut buf = vec![0u8; WRITE_SIZE];
    while let Ok(k @ 1..) = (&*from).read(&mut buf) {
        if (&*to).write_all(&buf[..k]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn reply(mut c: &TcpStream, code: u8) -> io::Result<()> {
    // Bound address 0.0.0.0:0; hev does not use it.
    c.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

/// Reads the greeting and the request, connects to `upstream` for a CONNECT, and replies
/// success only once that connect has succeeded.
fn accept_connect(mut c: &TcpStream, upstream: SocketAddr) -> io::Result<TcpStream> {
    let refused = |m: &str| {
        Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("socks5: {m}"),
        ))
    };
    let mut head = [0u8; 2];
    c.read_exact(&mut head)?;
    let mut methods = vec![0u8; usize::from(head[1])];
    c.read_exact(&mut methods)?;
    if head[0] != VERSION || !methods.contains(&NO_AUTH) {
        c.write_all(&[VERSION, 0xff])?;
        return refused("no acceptable method");
    }
    c.write_all(&[VERSION, NO_AUTH])?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req)?;
    let addr_len = match req[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            c.read_exact(&mut n)?;
            usize::from(n[0])
        }
        _ => {
            reply(c, ADDRESS_TYPE_NOT_SUPPORTED)?;
            return refused("unknown address type");
        }
    };
    // The destination (and port) is read and ignored.
    c.read_exact(&mut vec![0u8; addr_len + 2])?;
    if req[0] != VERSION || req[1] != CONNECT {
        reply(c, COMMAND_NOT_SUPPORTED)?;
        return refused("only CONNECT is supported");
    }
    match TcpStream::connect(upstream) {
        Ok(u) => {
            let _ = u.set_nodelay(true);
            reply(c, SUCCEEDED)?;
            Ok(u)
        }
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::ConnectionRefused => CONNECTION_REFUSED,
                _ => GENERAL_FAILURE,
            };
            reply(c, code)?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys;
    use std::net::TcpListener;
    use std::time::Duration;

    const GREETING: [u8; 3] = [VERSION, 1, NO_AUTH];
    /// CONNECT 198.18.0.1:5201, the bench target.
    const CONNECT_V4: [u8; 10] = [VERSION, CONNECT, 0, 1, 198, 18, 0, 1, 0x14, 0x51];
    /// BIND to the same address.
    const BIND_V4: [u8; 10] = [VERSION, 2, 0, 1, 198, 18, 0, 1, 0x14, 0x51];

    /// Sends the greeting and `request`; returns the reply code.
    fn request(relay: &Relay, request: &[u8]) -> (TcpStream, u8) {
        let mut c = TcpStream::connect(relay.server.addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(&GREETING).unwrap();
        let mut choice = [0u8; 2];
        c.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [VERSION, NO_AUTH]);
        c.write_all(request).unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap();
        (c, reply[1])
    }

    fn read_all(mut s: &TcpStream) -> u64 {
        let mut buf = vec![0u8; WRITE_SIZE];
        let mut n = 0;
        while let Ok(k @ 1..) = s.read(&mut buf) {
            n += k as u64;
        }
        n
    }

    /// An upstream that reads to EOF, then writes `answer` bytes and closes; it reports what it
    /// read.
    fn upstream(answer: usize) -> (SocketAddr, thread::JoinHandle<u64>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let got = read_all(&s);
            s.write_all(&vec![7u8; answer]).unwrap();
            got
        });
        (addr, t)
    }

    #[test]
    fn connect_relays_both_ways_with_half_close() {
        let (addr, up) = upstream(3 << 20);
        let relay = Relay::start(addr, &sys::affinity(0).unwrap()).unwrap();
        let (c, code) = request(&relay, &CONNECT_V4);
        assert_eq!(code, SUCCEEDED);
        (&c).write_all(&vec![5u8; 5 << 20]).unwrap();
        // Half-close: the upstream sees EOF, and its answer still arrives afterwards.
        c.shutdown(Shutdown::Write).unwrap();
        assert_eq!(read_all(&c), 3 << 20);
        assert_eq!(up.join().unwrap(), 5 << 20);
        assert!(
            relay
                .server
                .wait_idle(std::time::Instant::now() + Duration::from_secs(10))
        );
        relay.server.stop();
    }

    #[test]
    fn both_directions_stay_listed_until_both_end() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = Relay::start(l.local_addr().unwrap(), &sys::affinity(0).unwrap()).unwrap();
        let mut c = TcpStream::connect(relay.server.addr).unwrap();
        c.write_all(&GREETING).unwrap();
        c.read_exact(&mut [0u8; 2]).unwrap();
        c.write_all(&CONNECT_V4).unwrap();
        let (u, _) = l.accept().unwrap();
        // The acceptor and one thread per direction: the sink accepting a flow proves that the
        // relay's accounting lists all of it.
        assert_eq!(relay.server.threads().len(), 3);
        // The upstream's direction ends (the reply, then EOF); a window read now still finds it.
        drop(u);
        assert_eq!(read_all(&c), 10);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(relay.server.threads().len(), 3);
        drop(c);
        relay.server.stop();
    }

    #[test]
    fn other_commands_are_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let relay = Relay::start(l.local_addr().unwrap(), &sys::affinity(0).unwrap()).unwrap();
        let (c, code) = request(&relay, &BIND_V4);
        assert_eq!(code, COMMAND_NOT_SUPPORTED);
        assert_eq!(read_all(&c), 0);
        assert!(l.accept().is_err(), "the upstream was dialled");
        relay.server.stop();
    }

    #[test]
    fn upstream_down_fails_the_request() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let relay = Relay::start(addr, &sys::affinity(0).unwrap()).unwrap();
        let (c, code) = request(&relay, &CONNECT_V4);
        assert_eq!(code, CONNECTION_REFUSED);
        assert_eq!(read_all(&c), 0);
        relay.server.stop();
    }
}
