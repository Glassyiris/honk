use tokio::io::AsyncRead as _;

use super::*;

/// AsyncRead yielding at most `chunk` bytes per poll, to force frame
/// headers and UUID detection across read boundaries.
struct ChunkedReader {
    data: std::collections::VecDeque<u8>,
    chunk: usize,
}

impl tokio::io::AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = self.chunk.min(buf.remaining()).min(self.data.len());
        let (front, _) = self.data.as_slices();
        buf.put_slice(&front[..n]);
        self.data.drain(..n);
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectRead for ChunkedReader {}

struct SegmentedReader {
    segments: std::collections::VecDeque<std::collections::VecDeque<u8>>,
}

impl tokio::io::AsyncRead for SegmentedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        while self
            .segments
            .front()
            .is_some_and(|segment| segment.is_empty())
        {
            self.segments.pop_front();
        }
        let Some(segment) = self.segments.front_mut() else {
            return std::task::Poll::Ready(Ok(()));
        };
        let count = segment.len().min(buf.remaining());
        let (front, _) = segment.as_slices();
        buf.put_slice(&front[..count]);
        segment.drain(..count);
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectRead for SegmentedReader {}

struct DirectSwitchIo {
    prefix: std::collections::VecDeque<u8>,
    raw: TcpStream,
    outer_writes: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for DirectSwitchIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix.is_empty() {
            return std::pin::Pin::new(&mut self.raw).poll_read(cx, buf);
        }
        let count = self.prefix.len().min(buf.remaining());
        let (front, _) = self.prefix.as_slices();
        buf.put_slice(&front[..count]);
        self.prefix.drain(..count);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for DirectSwitchIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.outer_writes.lock().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectRead for DirectSwitchIo {
    fn poll_direct_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Option<std::task::Poll<std::io::Result<()>>> {
        Some(std::pin::Pin::new(&mut self.get_mut().raw).poll_read(cx, buf))
    }
}

fn vision_frame(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
    let mut frame = vec![
        command,
        (content.len() >> 8) as u8,
        content.len() as u8,
        (padding >> 8) as u8,
        padding as u8,
    ];
    frame.extend_from_slice(content);
    frame.extend(std::iter::repeat_n(0u8, padding));
    frame
}

async fn unpad_all(uuid: [u8; 16], data: &[u8], chunk: usize) -> Vec<u8> {
    let reader = ChunkedReader {
        data: data.iter().copied().collect(),
        chunk,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn vision_unpad_frames_then_raw_tail() {
    let uuid = [7u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"hello", 3));
    data.extend(vision_frame(0, b"world", 0));
    data.extend(vision_frame(VISION_COMMAND_END, b"!", 2));
    data.extend_from_slice(b"RAW-TAIL");
    for chunk in [1usize, 3, 7, 1024] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            b"helloworld!RAW-TAIL",
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_unpad_direct_command_switches_to_raw() {
    let uuid = [9u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(VISION_COMMAND_DIRECT, b"abc", 1));
    data.extend_from_slice(b"rest-is-raw");
    for chunk in [2usize, 1024] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            b"abcrest-is-raw",
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_one_byte_destination_buffers_preserve_payload() {
    let uuid = [3_u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"first", 4));
    data.extend(vision_frame(0, b"", 0));
    data.extend(vision_frame(VISION_COMMAND_END, b"second", 2));
    data.extend_from_slice(b"-raw");
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 8192,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut output = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let size = stream.read(&mut byte).await.unwrap();
        if size == 0 {
            break;
        }
        assert_eq!(size, 1);
        output.push(byte[0]);
    }
    assert_eq!(output, b"firstsecond-raw");
}

#[tokio::test]
async fn vision_accepts_every_source_frame_boundary() {
    let uuid = [4_u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"alpha", 3));
    data.extend(vision_frame(0, b"", 2));
    data.extend(vision_frame(VISION_COMMAND_END, b"omega", 0));
    data.extend_from_slice(b"-tail");

    for boundary in 0..=data.len() {
        let reader = SegmentedReader {
            segments: vec![
                data[..boundary].iter().copied().collect(),
                data[boundary..].iter().copied().collect(),
            ]
            .into(),
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"alphaomega-tail", "boundary={boundary}");
    }
}

#[tokio::test]
async fn vision_truncated_detected_frame_ends_cleanly() {
    let uuid = [5_u8; 16];
    let mut truncated_content = uuid.to_vec();
    truncated_content.extend_from_slice(&[0, 0, 5, 0, 0]);
    truncated_content.extend_from_slice(b"ab");
    assert_eq!(unpad_all(uuid, &truncated_content, 2).await, b"ab");

    let mut truncated_padding = uuid.to_vec();
    truncated_padding.extend_from_slice(&[0, 0, 3, 0, 5]);
    truncated_padding.extend_from_slice(b"abc\0\0");
    assert_eq!(unpad_all(uuid, &truncated_padding, 3).await, b"abc");
}

#[tokio::test]
async fn vision_sub_probe_size_streams_pass_through_raw() {
    let uuid = [6_u8; 16];
    let mut source = uuid.to_vec();
    source.extend_from_slice(&[0, 0, 0, 0]);
    for length in 0..21 {
        assert_eq!(
            unpad_all(uuid, &source[..length], 1).await,
            source[..length],
            "length={length}"
        );
    }
}

#[tokio::test]
async fn vision_direct_drains_buffered_tail_and_keeps_outer_writes() {
    let uuid = [8_u8; 16];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"raw-tail").await.unwrap();
    });
    let raw = TcpStream::connect(address).await.unwrap();
    let mut prefix = uuid.to_vec();
    prefix.extend(vision_frame(VISION_COMMAND_DIRECT, b"framed-", 1));
    prefix.extend_from_slice(b"buffered-");
    let outer_writes = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let io = DirectSwitchIo {
        prefix: prefix.into(),
        raw,
        outer_writes: std::sync::Arc::clone(&outer_writes),
    };
    let mut stream = VisionStream::new(io, uuid);
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"framed-buffered-raw-tail");

    stream.write_all(b"outer-uplink").await.unwrap();
    assert_eq!(&*outer_writes.lock(), b"outer-uplink");
    server.await.unwrap();
}

#[derive(Debug)]
struct TlsRecordCapture {
    tcp: std::net::TcpStream,
    received: Vec<u8>,
}

impl std::io::Read for TlsRecordCapture {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = buf.len().min(3);
        let count = std::io::Read::read(&mut self.tcp, &mut buf[..count])?;
        self.received.extend_from_slice(&buf[..count]);
        Ok(count)
    }
}

impl std::io::Write for TlsRecordCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.tcp, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.tcp)
    }
}

fn assert_tls13_upload(tls: &mut boring::ssl::SslStream<TlsRecordCapture>, expected: &[u8]) {
    use std::io::Read as _;

    let mut plaintext = vec![0; expected.len()];
    tls.read_exact(&mut plaintext).unwrap();
    assert_eq!(plaintext, expected);
    let wire = &tls.get_ref().received;
    assert_eq!(wire.get(..3), Some([23, 3, 3].as_slice()));
    let length = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    assert_eq!(length, expected.len() + 1 + 16);
    assert_eq!(wire.len(), 5 + length);
    tls.get_mut().received.clear();
}

/// Downstream Direct must not strip the outer TLS writer from later uploads.
#[tokio::test]
async fn vision_downstream_direct_keeps_uplink_tls_records() {
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
    use boring::x509::X509;
    use tokio_rustls::rustls;

    let uuid = [5u8; 16];
    let inner_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut inner_client = rustls::ClientConnection::new(
        Arc::new(inner_config),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut inner_hello = Vec::new();
    inner_client.write_tls(&mut inner_hello).unwrap();
    assert_eq!(inner_hello[0], 22);
    assert_eq!(inner_hello[5], 1);
    assert_eq!(
        inner_hello.len(),
        5 + usize::from(u16::from_be_bytes([inner_hello[3], inner_hello[4]]))
    );
    assert!(inner_hello.len() < 16_384);

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (request_read, request_ready) = tokio::sync::oneshot::channel();
    let expected_hello = inner_hello.clone();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};

        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        let acceptor = acceptor.build();
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = acceptor
            .accept(TlsRecordCapture {
                tcp,
                received: Vec::new(),
            })
            .unwrap();
        assert_eq!(tls.ssl().version2(), Some(SslVersion::TLS1_3));
        assert!(matches!(
            tls.ssl().current_cipher().unwrap().name(),
            "TLS_AES_128_GCM_SHA256" | "TLS_AES_256_GCM_SHA384" | "TLS_CHACHA20_POLY1305_SHA256"
        ));

        let mut expected_header = vec![0];
        expected_header.extend_from_slice(&uuid);
        expected_header
            .extend_from_slice(b"\x12\x0a\x10xtls-rprx-vision\x01\x01\xbb\x01\x7f\x00\x00\x01");
        let mut header = vec![0; expected_header.len()];
        tls.read_exact(&mut header).unwrap();
        assert_eq!(header, expected_header);
        tls.get_mut().received.clear();
        request_read.send(()).unwrap();

        assert_tls13_upload(&mut tls, &expected_hello);
        let mut frame = vec![0, 0];
        frame.extend_from_slice(&uuid);
        frame.extend(vision_frame(0, b"hel", 2));
        frame.extend(vision_frame(VISION_COMMAND_DIRECT, b"lo", 0));
        tls.write_all(&frame).unwrap();
        tls.flush().unwrap();
        // Only the downstream switches to raw TCP; keep TLS for the next upload.
        tls.get_mut().tcp.write_all(b" world").unwrap();
        assert_tls13_upload(&mut tls, &expected_hello);
        tls.get_mut()
            .tcp
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
    });

    let mut node = vless_node("05050505-0505-0505-0505-050505050505");
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut proxy = VLessHandler::new()
            .dial(
                &node,
                "127.0.0.1:443".parse().unwrap(),
                None,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();
        request_ready.await.unwrap();
        assert_eq!(
            proxy.stream.write(&inner_hello).await.unwrap(),
            inner_hello.len()
        );
        proxy.stream.flush().await.unwrap();

        let mut out = vec![0; 11];
        proxy.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
        assert_eq!(
            proxy.stream.write(&inner_hello).await.unwrap(),
            inner_hello.len()
        );
        proxy.stream.flush().await.unwrap();
        proxy.stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    })
    .await
    .unwrap();
    server.join().unwrap();
}

#[tokio::test]
async fn vision_passthrough_without_uuid_prefix() {
    let uuid = [7u8; 16];
    let data = b"plain stream, not vision framed".to_vec();
    for chunk in [4usize, 1024] {
        assert_eq!(unpad_all(uuid, &data, chunk).await, data, "chunk={chunk}");
    }
}

#[tokio::test]
async fn vision_unpad_lab_frame_sequence() {
    // Mirrored from a live sing-box vision downlink trace: big content
    // frames with long padding, then a Direct switch to raw.
    let uuid = [7u8; 16];
    let mk = |command: u8, content: usize, padding: usize, fill: u8| {
        let mut frame = vec![
            command,
            (content >> 8) as u8,
            content as u8,
            (padding >> 8) as u8,
            padding as u8,
        ];
        frame.extend(std::iter::repeat_n(fill, content));
        frame.extend(std::iter::repeat_n(0u8, padding));
        frame
    };
    let mut data = uuid.to_vec();
    data.extend(mk(0, 146, 135, b'a'));
    data.extend(mk(0, 5219, 180, b'b'));
    data.extend(mk(VISION_COMMAND_DIRECT, 647, 262, b'c'));
    data.extend_from_slice(b"RAW-TAIL");

    let mut expected = Vec::new();
    expected.extend(std::iter::repeat_n(b'a', 146));
    expected.extend(std::iter::repeat_n(b'b', 5219));
    expected.extend(std::iter::repeat_n(b'c', 647));
    expected.extend_from_slice(b"RAW-TAIL");

    for chunk in [7usize, 1400, 8192, 65536] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            expected,
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_unknown_command_fails() {
    let uuid = [7u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0x42, b"x", 0));
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 1024,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut out = Vec::new();
    let err = stream.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn response_strip_header_and_addon() {
    let mut data = vec![0x00, 0x03, 0xaa, 0xbb, 0xcc];
    data.extend_from_slice(b"payload-bytes");
    for chunk in [1usize, 2, 5, 1024] {
        let reader = ChunkedReader {
            data: data.iter().copied().collect(),
            chunk,
        };
        let mut stream = ResponseHeaderStrip::new(reader);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"payload-bytes", "chunk={chunk}");
    }
}

#[tokio::test]
async fn response_strip_rejects_nonzero_version() {
    let data = vec![0x01, 0x00, 0xff];
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 1024,
    };
    let mut stream = ResponseHeaderStrip::new(reader);
    let mut out = Vec::new();
    let err = stream.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&err),
        crate::group::ScoreOutcome::NodeFailure
    );
}
