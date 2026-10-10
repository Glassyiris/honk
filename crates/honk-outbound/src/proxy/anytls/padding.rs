use md5::{Digest, Md5};
use rand::RngExt as _;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    CLIENT_NAME, CMD_WASTE, DEFAULT_PADDING_SCHEME, FRAME_HEADER_LEN, PaddingScheme, PaddingState,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum PaddingInstruction {
    Range(u16, u16),
    Check,
}

impl PaddingScheme {
    pub(super) fn parse(raw: &[u8]) -> Option<Self> {
        let mut values = HashMap::<&[u8], &[u8]>::new();
        for line in raw.split(|byte| *byte == b'\n') {
            let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
                continue;
            };
            values.insert(&line[..separator], &line[separator + 1..]);
        }

        let stop = std::str::from_utf8(values.get(b"stop".as_slice()).copied()?)
            .ok()?
            .parse::<u32>()
            .ok()?;
        let mut packets = HashMap::new();
        for (key, value) in values {
            if key == b"stop"
                || key.is_empty()
                || (key.len() > 1 && key[0] == b'0')
                || !key.iter().all(u8::is_ascii_digit)
            {
                continue;
            }
            let Ok(packet) = std::str::from_utf8(key).unwrap().parse::<u32>() else {
                continue;
            };
            let instructions: Vec<_> = value
                .split(|byte| *byte == b',')
                .filter_map(|part| {
                    if part == b"c" {
                        return Some(PaddingInstruction::Check);
                    }
                    let mut bounds = part.split(|byte| *byte == b'-');
                    let (Some(start), Some(end), None) =
                        (bounds.next(), bounds.next(), bounds.next())
                    else {
                        return None;
                    };
                    let (mut start, mut end) = (
                        std::str::from_utf8(start).ok()?.parse::<i64>().ok()?,
                        std::str::from_utf8(end).ok()?.parse::<i64>().ok()?,
                    );
                    if start <= 0 || end <= 0 {
                        return None;
                    }
                    if start > end {
                        std::mem::swap(&mut start, &mut end);
                    }
                    Some(PaddingInstruction::Range(
                        u16::try_from(start).ok()?,
                        u16::try_from(end).ok()?,
                    ))
                })
                .collect();
            if instructions.is_empty() {
                packets.remove(&packet);
            } else {
                packets.insert(packet, instructions);
            }
        }
        if packets
            .get(&0)
            .and_then(|instructions| instructions.first())
            .is_some_and(|instruction| matches!(instruction, PaddingInstruction::Check))
        {
            return None;
        }
        let digest = Md5::digest(raw);
        let mut md5 = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            md5.push(HEX[(byte >> 4) as usize] as char);
            md5.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Some(Self { stop, packets, md5 })
    }

    fn sample_range(start: u16, end: u16) -> usize {
        if start == end {
            start as usize
        } else {
            rand::rng().random_range(start..end) as usize
        }
    }

    pub(super) fn auth_padding_len(&self) -> usize {
        match self
            .packets
            .get(&0)
            .and_then(|instructions| instructions.first())
        {
            Some(PaddingInstruction::Range(start, end)) => Self::sample_range(*start, *end),
            Some(PaddingInstruction::Check) | None => 0,
        }
    }

    pub(super) fn settings_payload(&self) -> bytes::Bytes {
        bytes::Bytes::from(format!(
            "v=2\nclient={CLIENT_NAME}\npadding-md5={}\n",
            self.md5
        ))
    }
}

impl Default for PaddingState {
    fn default() -> Self {
        Self {
            current: parking_lot::RwLock::new(Arc::new(
                PaddingScheme::parse(DEFAULT_PADDING_SCHEME)
                    .expect("built-in AnyTLS padding scheme is valid"),
            )),
        }
    }
}

impl PaddingState {
    pub(super) fn snapshot(&self) -> Arc<PaddingScheme> {
        Arc::clone(&self.current.read())
    }

    pub(super) fn update(&self, raw: &[u8]) -> bool {
        let Some(scheme) = PaddingScheme::parse(raw) else {
            return false;
        };
        *self.current.write() = Arc::new(scheme);
        true
    }
}

pub(super) async fn write_padded<W>(
    writer: &mut W,
    mut payload: &[u8],
    scheme: &PaddingScheme,
    packet: u32,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(instructions) = (packet < scheme.stop)
        .then(|| scheme.packets.get(&packet))
        .flatten()
    else {
        return writer.write_all(payload).await;
    };

    for instruction in instructions {
        let PaddingInstruction::Range(start, end) = instruction else {
            if payload.is_empty() {
                return Ok(());
            }
            continue;
        };
        let target = PaddingScheme::sample_range(*start, *end);
        if payload.len() > target {
            writer.write_all(&payload[..target]).await?;
            payload = &payload[target..];
        } else if !payload.is_empty() {
            let padding_len = target.saturating_sub(payload.len() + FRAME_HEADER_LEN);
            if padding_len == 0 {
                writer.write_all(payload).await?;
            } else {
                let mut padded = Vec::with_capacity(payload.len() + FRAME_HEADER_LEN + padding_len);
                padded.extend_from_slice(payload);
                padded.push(CMD_WASTE);
                padded.extend_from_slice(&0u32.to_be_bytes());
                padded.extend_from_slice(&(padding_len as u16).to_be_bytes());
                padded.resize(padded.len() + padding_len, 0);
                writer.write_all(&padded).await?;
            }
            payload = &[];
        } else {
            let mut waste = vec![0; FRAME_HEADER_LEN + target];
            waste[0] = CMD_WASTE;
            waste[5..7].copy_from_slice(&(target as u16).to_be_bytes());
            writer.write_all(&waste).await?;
        }
    }
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    Ok(())
}
