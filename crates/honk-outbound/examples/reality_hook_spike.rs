//! Spike: prove the two rprx BoringSSL client hooks actually take effect on
//! the wire.
//!
//! Hook 1 (`SSL_set1_client_x25519_private_key`): the key_share extension in
//! the ClientHello must carry the public key corresponding to our preset
//! 32-byte private key instead of a random one.
//!
//! Hook 2 (`SSL_set_client_hello_fixup_cb`): the callback fires after the
//! ClientHello is fully serialized and before it is hashed into the
//! transcript; rewriting legacy_session_id in place must show up in the
//! bytes the server receives.
//!
//! A raw TCP listener plays the "server": it reads the first TLS record
//! (the ClientHello), asserts on its bytes, and closes. The client-side
//! handshake error is expected and ignored.
//!
//! Run: cargo run -p honk-outbound --example reality_hook_spike

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Context;
use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslContextBuilder, SslMethod, SslStream, SslVerifyMode};
use foreign_types::ForeignType;

const SSL_GROUP_X25519: u16 = 29;
const PRESET_PRIVATE_KEY: [u8; 32] = [0x42; 32];
const MAGIC_SESSION_ID: [u8; 32] = [0xAB; 32];

#[derive(Default, Debug)]
struct CbObservations {
    calls: usize,
    msg_len: usize,
    handshake_type: u8,
    session_id_len: u8,
    client_random: Vec<u8>,
}

fn observations() -> &'static Mutex<CbObservations> {
    static OBS: OnceLock<Mutex<CbObservations>> = OnceLock::new();
    OBS.get_or_init(|| Mutex::new(CbObservations::default()))
}

extern "C" fn fixup_cb(
    _ssl: *mut boring_sys::SSL,
    msg: *mut u8,
    msg_len: usize,
) -> std::os::raw::c_int {
    let msg = unsafe { std::slice::from_raw_parts_mut(msg, msg_len) };
    let mut obs = observations().lock().unwrap();
    obs.calls += 1;
    obs.msg_len = msg_len;
    // Handshake message layout: header [0..4], legacy_version [4..6],
    // client_random [6..38], session_id_len [38], session_id [39..].
    obs.handshake_type = msg[0];
    obs.session_id_len = msg[38];
    obs.client_random = msg[6..38].to_vec();
    if msg[38] == 32 && msg_len >= 71 {
        msg[39..71].copy_from_slice(&MAGIC_SESSION_ID);
    }
    1
}

fn expected_public_key() -> [u8; 32] {
    let mut public = [0u8; 32];
    unsafe {
        boring_sys::X25519_public_from_private(public.as_mut_ptr(), PRESET_PRIVATE_KEY.as_ptr())
    };
    public
}

struct ParsedClientHello {
    client_random: Vec<u8>,
    session_id: Vec<u8>,
    x25519_key_share: Option<Vec<u8>>,
}

fn parse_client_hello(msg: &[u8]) -> ParsedClientHello {
    assert_eq!(msg[0], 1, "handshake type must be client_hello");
    let hs_len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
    assert_eq!(hs_len + 4, msg.len(), "handshake length prefix mismatch");
    let session_id_len = msg[38] as usize;
    let session_id = msg[39..39 + session_id_len].to_vec();
    let mut cur = 39 + session_id_len;
    let cs_len = u16::from_be_bytes([msg[cur], msg[cur + 1]]) as usize;
    cur += 2 + cs_len;
    let comp_len = msg[cur] as usize;
    cur += 1 + comp_len;
    let ext_total = u16::from_be_bytes([msg[cur], msg[cur + 1]]) as usize;
    cur += 2;
    let ext_end = cur + ext_total;
    let mut x25519_key_share = None;
    while cur + 4 <= ext_end {
        let etype = u16::from_be_bytes([msg[cur], msg[cur + 1]]);
        let elen = u16::from_be_bytes([msg[cur + 2], msg[cur + 3]]) as usize;
        let edata = &msg[cur + 4..cur + 4 + elen];
        if etype == 0x0033 {
            // key_share: client_shares_len(2), then (group(2), len(2), key)*
            let mut kcur = 2;
            while kcur + 4 <= edata.len() {
                let group = u16::from_be_bytes([edata[kcur], edata[kcur + 1]]);
                let klen = u16::from_be_bytes([edata[kcur + 2], edata[kcur + 3]]) as usize;
                if group == SSL_GROUP_X25519 {
                    x25519_key_share = Some(edata[kcur + 4..kcur + 4 + klen].to_vec());
                }
                kcur += 4 + klen;
            }
        }
        cur += 4 + elen;
    }
    ParsedClientHello {
        client_random: msg[6..38].to_vec(),
        session_id,
        x25519_key_share,
    }
}

fn run_server(listener: TcpListener) -> ParsedClientHello {
    let (mut conn, _) = listener.accept().unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut record_header = [0u8; 5];
    conn.read_exact(&mut record_header).unwrap();
    assert_eq!(
        record_header[0], 22,
        "first record must be a handshake record"
    );
    let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    let mut payload = vec![0u8; record_len];
    conn.read_exact(&mut payload).unwrap();
    parse_client_hello(&payload)
}

fn run_client(addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);
    let ctx = builder.build();
    let ssl = Ssl::new(&ctx)?;

    let ok = unsafe {
        boring_sys::SSL_set1_client_x25519_private_key(ssl.as_ptr(), PRESET_PRIVATE_KEY.as_ptr())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_x25519_private_key");
    }
    unsafe { boring_sys::SSL_set_client_hello_fixup_cb(ssl.as_ptr(), Some(fixup_cb)) };

    let groups = std::ffi::CString::new("X25519").unwrap();
    let ok = unsafe { boring_sys::SSL_set1_groups_list(ssl.as_ptr(), groups.as_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_groups_list");
    }
    let shares = [SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }

    let tcp = TcpStream::connect(addr)?;
    let mut stream = SslStream::new(ssl, tcp)?;
    // The fake server never answers; the ClientHello is already on the wire
    // by the time this fails.
    let _ = stream.connect();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server = std::thread::spawn(move || run_server(listener));

    run_client(addr)?;
    let ch = server.join().expect("server thread panicked");

    let obs = observations().lock().unwrap();
    println!(
        "callback fired {} time(s), msg_len={}",
        obs.calls, obs.msg_len
    );
    assert_eq!(obs.calls, 1, "fixup callback must fire exactly once");
    assert_eq!(obs.handshake_type, 1, "callback msg must be a ClientHello");
    assert_eq!(obs.session_id_len, 32, "compat session_id must be 32 bytes");

    println!(
        "client_random in callback == on wire: {}",
        obs.client_random == ch.client_random
    );
    assert_eq!(obs.client_random, ch.client_random);

    println!(
        "session_id on wire == magic (hook 2): {}",
        ch.session_id == MAGIC_SESSION_ID
    );
    assert_eq!(
        ch.session_id, MAGIC_SESSION_ID,
        "fixup rewrite not on the wire"
    );

    let expected_pub = expected_public_key();
    let got_pub = ch
        .x25519_key_share
        .as_ref()
        .expect("no X25519 key_share entry in ClientHello");
    println!(
        "x25519 key_share == preset key's public (hook 1): {}",
        *got_pub == expected_pub
    );
    assert_eq!(
        *got_pub, expected_pub,
        "key_share does not match preset private key"
    );

    println!("SPIKE OK: both hooks verified on the wire");
    Ok(())
}
