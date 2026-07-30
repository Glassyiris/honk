use std::hint::black_box;
use std::time::Duration;

use criterion::Criterion;
use honk_core::dns::forwarder::build_dns_query;
use honk_core::dns::transport::exchange_length_prefixed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

pub(super) fn bench_length_prefix_roundtrip(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    c.bench_function("dns_length_prefix_duplex", |b| {
        b.to_async(&runtime).iter(|| async {
            let (mut client, mut server_stream) = tokio::io::duplex(4096);
            let query = build_dns_query("example.com", 1);
            let server = tokio::spawn(async move {
                let mut length = [0_u8; 2];
                server_stream
                    .read_exact(&mut length)
                    .await
                    .expect("query length");
                let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
                server_stream.read_exact(&mut query).await.expect("query");
                let response = mock_response(u16::from_be_bytes([query[0], query[1]]));
                server_stream
                    .write_all(
                        &u16::try_from(response.len())
                            .expect("response length")
                            .to_be_bytes(),
                    )
                    .await
                    .expect("response length");
                server_stream.write_all(&response).await.expect("response");
            });
            let response = exchange_length_prefixed(&mut client, &query, Duration::from_secs(1))
                .await
                .expect("exchange");
            server.await.expect("server");
            black_box(response);
        });
    });
}

fn mock_response(transaction_id: u16) -> Vec<u8> {
    let mut response = vec![
        (transaction_id >> 8) as u8,
        transaction_id as u8,
        0x81,
        0x80,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        0,
    ];
    response.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0,
        0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1,
    ]);
    response
}
