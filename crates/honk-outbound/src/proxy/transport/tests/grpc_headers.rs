use super::grpc_peer::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn grpc_dynamic_metadata_survives_header_blocks_before_failed_status() {
    let mut initial = response_headers();
    initial.extend(literal(b"x-trace", b"a", true));
    let mut wire = frame(HEADERS, END_HEADERS, 1, &initial);
    wire.extend(data(b"partial"));
    // The reference must be decoded before status 13, rather than masked by an early refusal.
    let mut final_block = vec![0xbe]; // Dynamic index 62: x-trace: a.
    final_block.extend(literal(b"grpc-status", b"13", false));
    wire.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &final_block));
    raw_response(wire, |mut stream| async move {
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"partial");
        let error = terminal_error(&mut stream).await;
        assert!(error.to_string().contains("grpc-status 13"), "{error}");
    })
    .await;
}

#[tokio::test]
async fn grpc_dynamic_table_counts_exact_value_octets() {
    let mut wire = frame(HEADERS, END_HEADERS, 1, &response_headers());
    wire.extend(data(b"partial"));
    // RFC 7541 entry size: 32 + one name octet + one value octet = 34.
    let mut final_block = vec![0x3f, 3];
    final_block.extend(literal(b"x", &[0x80], true));
    final_block.push(0xbe);
    final_block.extend(literal(b"grpc-status", b"13", false));
    wire.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &final_block));
    raw_response(wire, |mut stream| async move {
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"partial");
        let error = terminal_error(&mut stream).await;
        assert!(error.to_string().contains("grpc-status 13"), "{error}");
    })
    .await;
}

#[tokio::test]
async fn grpc_rejects_hpack_table_update_above_advertised_limit() {
    let mut block = Vec::new();
    hpack_integer(&mut block, 4097, 5, 0x20);
    block.extend(response_headers());
    let mut wire = frame(HEADERS, END_HEADERS, 1, &block);
    wire.extend(data(b"must not escape"));
    wire.extend(trailers(b"0"));
    raw_response(wire, |mut stream| async move {
        terminal_error(&mut stream).await;
    })
    .await;
}

#[tokio::test]
async fn grpc_rejects_aggregate_headers_across_continuations() {
    let mut block = response_headers();
    for _ in 0..6 {
        block.extend(literal(b"x-fill", &vec![b'a'; 12_000], false));
    }
    let mut wire = Vec::new();
    let count = block.len().div_ceil(16_384);
    for (index, chunk) in block.chunks(16_384).enumerate() {
        wire.extend(frame(
            if index == 0 { HEADERS } else { CONTINUATION },
            if index + 1 == count { END_HEADERS } else { 0 },
            1,
            chunk,
        ));
    }
    wire.extend(data(b"must not escape"));
    wire.extend(trailers(b"0"));
    raw_response(wire, |mut stream| async move {
        terminal_error(&mut stream).await;
    })
    .await;
}

#[tokio::test]
async fn grpc_invalid_hpack_huffman_and_huge_lengths_are_errors_not_panics() {
    let mut huge_length = vec![0]; // Literal with a new name of usize::MAX octets.
    hpack_integer(&mut huge_length, usize::MAX, 7, 0);
    for malformed in [
        vec![0x80],             // Indexed field zero is forbidden.
        vec![0, 0x81, 0xff, 0], // Huffman EOS padding longer than seven bits.
        huge_length,
    ] {
        let (client, mut server) = tokio::io::duplex(4096);
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let serve = async {
            read_request(&mut server).await;
            let mut wire = frame(SETTINGS, 0, 0, &[]);
            wire.extend(frame(HEADERS, END_HEADERS, 1, &response_headers()));
            wire.extend(data(b"partial"));
            server.write_all(&wire).await.unwrap();
            // Compression errors can invalidate an entire unread h2 batch;
            // deliver the payload before introducing the malformed block.
            seen_rx.await.unwrap();
            server
                .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &malformed))
                .await
                .unwrap();
            let _ = done_rx.await;
        };
        let consume = async {
            let mut stream = super::wrap_grpc(&grpc_node(), Box::new(client))
                .await
                .unwrap();
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"partial");
            seen_tx.send(()).unwrap();
            terminal_error(&mut stream).await;
            let _ = done_tx.send(());
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(consume, serve);
        })
        .await
        .expect("malformed trailer exchange stalled");
    }
}

#[tokio::test]
async fn grpc_trailers_only_and_http_refusals_are_retained_errors() {
    let mut block = response_headers();
    block.extend(literal(b"grpc-status", b"14", false));
    raw_response(
        frame(HEADERS, END_HEADERS | END_STREAM, 1, &block),
        |mut stream| async move {
            let error = terminal_error(&mut stream).await;
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
            assert!(error.to_string().contains("grpc-status 14"), "{error}");
        },
    )
    .await;

    let mut block = vec![0x8d]; // Static :status 404.
    block.extend(literal(b"content-type", b"text/html", false));
    let mut wire = frame(HEADERS, END_HEADERS, 1, &block);
    wire.extend(frame(DATA, END_STREAM, 1, b"<html>not found</html>"));
    raw_response(wire, |mut stream| async move {
        let error = terminal_error(&mut stream).await;
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    })
    .await;
}

#[tokio::test]
async fn grpc_reset_and_excluding_goaway_are_retained_errors() {
    let mut excluded = 0u32.to_be_bytes().to_vec();
    excluded.extend_from_slice(&0u32.to_be_bytes());
    let mut failed = 1u32.to_be_bytes().to_vec();
    failed.extend_from_slice(&11u32.to_be_bytes());
    for wire in [
        frame(RESET, 0, 1, &7u32.to_be_bytes()),
        frame(GOAWAY, 0, 0, &excluded),
        frame(GOAWAY, 0, 0, &failed),
    ] {
        raw_response(wire, |mut stream| async move {
            terminal_error(&mut stream).await;
        })
        .await;
    }
}

#[tokio::test]
async fn grpc_complete_padded_continuation_with_ok_trailers_reads_to_eof() {
    let mut wire = frame(HEADERS, END_HEADERS, 1, &response_headers());
    wire.extend(data(b"pong"));
    let block = literal(b"grpc-status", b"0", false);
    let (head, tail) = block.split_at(4);
    let mut padded = vec![2];
    padded.extend_from_slice(head);
    padded.extend_from_slice(&[0, 0]);
    wire.extend(frame(HEADERS, END_STREAM | PADDED, 1, &padded));
    wire.extend(frame(CONTINUATION, END_HEADERS, 1, tail));
    raw_response(wire, |mut stream| async move {
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"pong");
    })
    .await;
}

#[tokio::test]
async fn grpc_graceful_goaway_lets_the_admitted_stream_finish() {
    let mut goaway = 1u32.to_be_bytes().to_vec();
    goaway.extend_from_slice(&0u32.to_be_bytes());
    let mut wire = frame(GOAWAY, 0, 0, &goaway);
    wire.extend(frame(HEADERS, END_HEADERS, 1, &response_headers()));
    wire.extend(data(b"late"));
    wire.extend(trailers(b"0"));
    raw_response(wire, |mut stream| async move {
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"late");
    })
    .await;
}

#[tokio::test]
async fn grpc_split_trailers_only_refusal_waits_for_complete_continuation() {
    let mut block = response_headers();
    block.extend(literal(b"grpc-status", b"14", false));
    let (head, tail) = block.split_at(block.len() - 2);
    let mut wire = frame(HEADERS, END_STREAM, 1, head);
    wire.extend(frame(CONTINUATION, END_HEADERS, 1, tail));
    raw_response(wire, |mut stream| async move {
        let error = terminal_error(&mut stream).await;
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains("grpc-status 14"), "{error}");
    })
    .await;
}

#[tokio::test]
async fn grpc_failed_trailers_from_h2_server_are_an_error() {
    use super::wrap_grpc;
    let (client, server) = tokio::io::duplex(4096);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let serve = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (_, mut respond) = connection.accept().await.expect("request").unwrap();
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut body = respond.send_response(response, false).unwrap();
        body.send_data(gun_message(b"pong").into(), false).unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "13".parse().unwrap());
        trailers.insert("grpc-message", "internal".parse().unwrap());
        body.send_trailers(trailers).unwrap();
        tokio::select! {
            _ = done_rx => {}
            _ = connection.accept() => {}
        }
    };
    let consume = async {
        let mut stream = wrap_grpc(&grpc_node(), Box::new(client)).await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        let error = terminal_error(&mut stream).await;
        assert!(error.to_string().contains("grpc-status 13"), "{error}");
        drop(stream);
        let _ = done_tx.send(());
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("h2 trailers exchange stalled");
}
