//! Shared DNS stream framing helpers (RFC 7766 length-prefix).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// Write a length-prefixed DNS message and read the response from `stream`.
pub async fn exchange_length_prefixed<S>(
    stream: &mut S,
    raw_query: &[u8],
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_length_prefixed(stream, raw_query).await?;
    read_length_prefixed(stream, query_timeout).await
}

pub(super) async fn write_length_prefixed<S>(stream: &mut S, raw_query: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(raw_query.len())
        .map_err(|_| anyhow::anyhow!("DNS message too large for stream framing"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(raw_query).await?;
    stream.flush().await?;
    Ok(())
}

pub(super) async fn read_length_prefixed<S>(
    stream: &mut S,
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    timeout(query_timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("DNS stream read length timed out"))??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        anyhow::bail!("invalid DNS stream response length {resp_len}");
    }
    let mut buf = vec![0u8; resp_len];
    timeout(query_timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("DNS stream read body timed out"))??;
    Ok(buf)
}

/// Force DNS message ID to 0 (DoH/DoQ cache-friendly / RFC 9250 §4.2.1).
#[inline]
pub fn force_dns_id_zero(msg: &mut [u8]) -> u16 {
    if msg.len() < 2 {
        return 0;
    }
    let orig = u16::from_be_bytes([msg[0], msg[1]]);
    msg[0] = 0;
    msg[1] = 0;
    orig
}

/// Restore a previously saved DNS message ID.
#[inline]
pub fn restore_dns_id(msg: &mut [u8], id: u16) {
    if msg.len() < 2 {
        return;
    }
    let bytes = id.to_be_bytes();
    msg[0] = bytes[0];
    msg[1] = bytes[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_zero_roundtrip() {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00];
        let orig = force_dns_id_zero(&mut msg);
        assert_eq!(orig, 0x1234);
        assert_eq!(&msg[..2], &[0, 0]);
        restore_dns_id(&mut msg, orig);
        assert_eq!(&msg[..2], &[0x12, 0x34]);
    }

    #[tokio::test]
    async fn length_prefix_exchange() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);
        let query = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01];
        let response = vec![0xAB, 0xCD, 0x81, 0x80, 0x00, 0x00];

        let server_resp = response.clone();
        let expected_query = query.clone();
        let server_task = tokio::spawn(async move {
            let mut len = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut len)
                .await
                .unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut buf = vec![0u8; n];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut buf)
                .await
                .unwrap();
            assert_eq!(buf, expected_query);
            let len = (server_resp.len() as u16).to_be_bytes();
            tokio::io::AsyncWriteExt::write_all(&mut server, &len)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut server, &server_resp)
                .await
                .unwrap();
        });

        let got = exchange_length_prefixed(&mut client, &query, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got, response);
        server_task.await.unwrap();
    }
}
