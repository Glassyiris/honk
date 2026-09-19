use super::{AsyncReadWrite, Node, transport_node, wrap_grpc};
use std::{future::Future, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub(super) const DATA: u8 = 0;
pub(super) const HEADERS: u8 = 1;
pub(super) const RESET: u8 = 3;
pub(super) const SETTINGS: u8 = 4;
pub(super) const GOAWAY: u8 = 7;
pub(super) const CONTINUATION: u8 = 9;
pub(super) const END_STREAM: u8 = 1;
pub(super) const END_HEADERS: u8 = 4;
pub(super) const PADDED: u8 = 8;

pub(super) fn grpc_node() -> Node {
    let mut node = transport_node(443);
    node.transport_mut().unwrap().grpc_service = Some("svc".into());
    node
}

pub(super) fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    assert!(
        len <= 16_384,
        "fixture exceeds the default peer frame limit"
    );
    let mut wire = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

pub(super) async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    io.read_exact(&mut header).await.unwrap();
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    let mut payload = vec![0; len];
    io.read_exact(&mut payload).await.unwrap();
    (header[3], header[4], stream, payload)
}

pub(super) async fn read_request<R: AsyncRead + Unpin>(io: &mut R) {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let (kind, _, stream, _) = read_frame(io).await;
    assert_eq!((kind, stream), (SETTINGS, 0));
    loop {
        let (kind, flags, stream, _) = read_frame(io).await;
        if stream == 1 && matches!(kind, HEADERS | CONTINUATION) && flags & END_HEADERS != 0 {
            return;
        }
    }
}

pub(super) fn hpack_integer(out: &mut Vec<u8>, mut value: usize, prefix: u8, mask: u8) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    value -= max;
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) fn literal(name: &[u8], value: &[u8], indexed: bool) -> Vec<u8> {
    let mut field = vec![if indexed { 0x40 } else { 0 }];
    hpack_integer(&mut field, name.len(), 7, 0);
    field.extend_from_slice(name);
    hpack_integer(&mut field, value.len(), 7, 0);
    field.extend_from_slice(value);
    field
}

pub(super) fn response_headers() -> Vec<u8> {
    let mut block = vec![0x88]; // Static :status 200; no dynamic entries.
    block.extend(literal(b"content-type", b"application/grpc", false));
    block
}

pub(super) fn trailers(status: &[u8]) -> Vec<u8> {
    frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &literal(b"grpc-status", status, false),
    )
}

pub(super) fn gun_message(content: &[u8]) -> Vec<u8> {
    let mut message = vec![0, 0, 0, 0, 0, 0x0a];
    let mut len = content.len();
    while len >= 128 {
        message.push((len as u8 & 0x7f) | 0x80);
        len >>= 7;
    }
    message.push(len as u8);
    message.extend_from_slice(content);
    let protobuf_len = (message.len() - 5) as u32;
    message[1..5].copy_from_slice(&protobuf_len.to_be_bytes());
    message
}

pub(super) fn data(content: &[u8]) -> Vec<u8> {
    frame(DATA, 0, 1, &gun_message(content))
}

pub(super) async fn raw_response<F, Fut>(wire: Vec<u8>, check: F)
where
    F: FnOnce(Box<dyn AsyncReadWrite>) -> Fut,
    Fut: Future<Output = ()>,
{
    let (client, mut server) = tokio::io::duplex(256 * 1024);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let serve = async move {
        read_request(&mut server).await;
        server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
        // A rejecting client may close the connection before the whole script is sent.
        let _ = server.write_all(&wire).await;
        let mut sink = tokio::io::sink();
        tokio::select! {
            _ = done_rx => {}
            _ = tokio::io::copy(&mut server, &mut sink) => {}
        }
    };
    let consume = async move {
        let stream = wrap_grpc(&grpc_node(), Box::new(client)).await.unwrap();
        check(stream).await;
        let _ = done_tx.send(());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("gRPC exchange stalled");
}

pub(super) async fn terminal_error(stream: &mut Box<dyn AsyncReadWrite>) -> std::io::Error {
    let mut byte = [0];
    let error = stream
        .read(&mut byte)
        .await
        .expect_err("terminal failure became EOF");
    let repeated = stream
        .read(&mut byte)
        .await
        .expect_err("read lost the terminal failure");
    assert_eq!(repeated.kind(), error.kind());
    let repeated = stream
        .write(b"late")
        .await
        .expect_err("write lost the terminal failure");
    assert_eq!(repeated.kind(), error.kind());
    let repeated = stream
        .flush()
        .await
        .expect_err("flush lost the terminal failure");
    assert_eq!(repeated.kind(), error.kind());
    error
}
