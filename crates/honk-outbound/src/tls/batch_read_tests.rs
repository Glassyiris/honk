use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn eof_delivers_partial_then_zero() {
    let (mut w, r) = tokio::io::duplex(64);
    let mut s = BatchRead::new(r);
    w.write_all(&[7u8; 10]).await.unwrap();
    drop(w); // EOF
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(n, 10, "buffered data must be delivered before EOF");
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn preserves_error_after_batched_bytes() {
    struct Scripted {
        step: u8,
    }

    impl tokio::io::AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.step += 1;
            match self.step {
                1 => {
                    buf.put_slice(b"ok");
                    std::task::Poll::Ready(Ok(()))
                }
                2 => std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "scripted read failure",
                ))),
                3 => {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
                _ => std::task::Poll::Ready(Ok(())),
            }
        }
    }

    let mut stream = BatchRead::new(Scripted { step: 0 });
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ok");

    let error = stream.read(&mut buf).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn read_larger_than_inner_chunks() {
    // Simulate one-record-per-poll inner reads (TLS): cap each inner
    // poll at 8 bytes; the wrapper must still fill the big buffer.
    struct Chunked<R> {
        inner: R,
    }
    impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Chunked<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let cap = buf.remaining().min(8);
            let (r, n) = {
                let mut small = buf.take(cap);
                let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut small);
                (r, small.filled().len())
            };
            if r.is_ready() {
                // SAFETY: `take` views the front of `buf`'s unfilled
                // region; bytes it initialized are the front of ours.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
            }
            r
        }
    }
    let (mut w, r) = tokio::io::duplex(64);
    let mut s = BatchRead::new(Chunked { inner: r });
    for i in 0..4u8 {
        w.write_all(&[i; 8]).await.unwrap();
    }
    let mut buf = [0u8; 32];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(n, 32, "four 8-byte records must batch into one read");
    for i in 0..4usize {
        assert!(buf[i * 8..(i + 1) * 8].iter().all(|&b| b == i as u8));
    }
}
