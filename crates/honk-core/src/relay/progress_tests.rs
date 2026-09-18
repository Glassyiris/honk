use super::*;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};

#[tokio::test]
async fn copy_reports_response_while_client_blocked_and_progress_before_eof() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut client, mut relay_client) = tokio::io::duplex(1);
        let (relay_proxy, mut peer) = tokio::io::duplex(64);
        relay_client.write_all(b"x").await.unwrap();
        peer.write_all(b"pong").await.unwrap();
        let responses = Arc::new(AtomicUsize::new(0));
        let response_ready = Arc::new(tokio::sync::Notify::new());
        let transferred = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let progress = RelayProgress {
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            first_response: Some(Arc::new({
                let responses = responses.clone();
                let response_ready = response_ready.clone();
                move || {
                    responses.fetch_add(1, Ordering::Relaxed);
                    response_ready.notify_one();
                }
            })),
            on_transfer: Some(Arc::new({
                let transferred = transferred.clone();
                move |up, down| {
                    assert!(up == 0 || down == 0);
                    transferred.0.fetch_add(up, Ordering::Relaxed);
                    transferred.1.fetch_add(down, Ordering::Relaxed);
                }
            })),
        };
        let address = "127.0.0.1:1".parse().unwrap();
        let relay = tokio::spawn(splice::relay_auto(
            relay_client,
            relay_proxy,
            address,
            address,
            Some(progress),
        ));
        response_ready.notified().await;
        assert_eq!(responses.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 0);
        assert!(!relay.is_finished());

        let mut prefix = [0; 1];
        client.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"x");
        for expected in [b"pong", b"more"] {
            if expected == b"more" {
                peer.write_all(expected).await.unwrap();
            }
            let mut reply = [0; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, expected);
        }
        client.write_all(b"u").await.unwrap();
        let mut request = [0; 1];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"u");
        assert_eq!(transferred.0.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 8);
        assert_eq!(responses.load(Ordering::Relaxed), 1);
        assert!(!relay.is_finished());

        client.shutdown().await.unwrap();
        peer.shutdown().await.unwrap();
        let stats = relay.await.unwrap().unwrap();
        assert_eq!((stats.client_to_proxy, stats.proxy_to_client), (1, 8));
        assert_eq!(transferred.0.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 8);
    })
    .await
    .expect("copy observations waited for client reads or EOF");
}

struct FailAfter {
    inner: DuplexStream,
    remaining: usize,
}

impl AsyncRead for FailAfter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FailAfter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let len = bytes.len().min(self.remaining).min(3);
        let written = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &bytes[..len]))?;
        self.remaining -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn copy_transfer_counts_only_accepted_partial_writes_before_error() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut client, relay_client) = tokio::io::duplex(64);
        let (relay_proxy, mut peer) = tokio::io::duplex(64);
        client.write_all(b"abcdefgh").await.unwrap();
        let upload = Arc::new(AtomicU64::new(0));
        let accepted = Arc::new(AtomicU64::new(0));
        let progress = RelayProgress {
            upload: upload.clone(),
            download: Arc::new(AtomicU64::new(0)),
            first_response: None,
            on_transfer: Some(Arc::new({
                let accepted = accepted.clone();
                move |up, down| {
                    assert_eq!(down, 0);
                    accepted.fetch_add(up, Ordering::Relaxed);
                }
            })),
        };
        let address = "127.0.0.1:1".parse().unwrap();
        let error = splice::relay_auto(
            relay_client,
            FailAfter {
                inner: relay_proxy,
                remaining: 5,
            },
            address,
            address,
            Some(progress),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"abcde");
        assert_eq!(accepted.load(Ordering::Relaxed), 5);
        assert_eq!(
            upload.load(Ordering::Relaxed),
            8,
            "tracker retains source-read accounting"
        );
    })
    .await
    .expect("partial-write failure did not terminate relay");
}
