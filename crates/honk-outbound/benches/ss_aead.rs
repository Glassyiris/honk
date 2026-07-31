//! AEAD micro-benchmark: RustCrypto `aes-gcm` vs BoringSSL `AeadCtx` on
//! Shadowsocks-sized chunks (16 KiB and 1400 B), seal and open.
//!
//! Run with:
//!   cargo bench -p honk-outbound --bench ss_aead

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const CHUNK: usize = 0x3FFF;

fn bench_seal(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];

    let mut g = c.benchmark_group("ss_aead_seal");
    for size in [1400usize, CHUNK] {
        let pt = vec![0xabu8; size];
        g.throughput(Throughput::Bytes(size as u64));

        g.bench_with_input(BenchmarkId::new("rustcrypto", size), &pt, |b, pt| {
            use aes_gcm::aead::{AeadInOut, KeyInit, inout::InOutBuf};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
            let mut out = Vec::with_capacity(size + 16);
            b.iter(|| {
                out.clear();
                out.extend_from_slice(pt);
                let tag = cipher
                    .encrypt_inout_detached(
                        <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(&nonce[..]).unwrap(),
                        b"",
                        InOutBuf::from(&mut out[..]),
                    )
                    .unwrap();
                black_box(&tag);
            });
        });

        g.bench_with_input(BenchmarkId::new("boringssl", size), &pt, |b, pt| {
            let ctx = boring::aead::AeadCtx::new_default_tag(
                &boring::aead::Algorithm::aes_128_gcm(),
                &key,
            )
            .unwrap();
            let mut out = Vec::with_capacity(size + 16);
            b.iter(|| {
                out.clear();
                out.extend_from_slice(pt);
                out.resize(pt.len() + 16, 0);
                let (body, tag) = out.split_at_mut(pt.len());
                ctx.seal_in_place(&nonce, body, tag, b"").unwrap();
                black_box(&tag[0]);
            });
        });
    }
    g.finish();
}

fn bench_open(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];

    let mut g = c.benchmark_group("ss_aead_open");
    for size in [1400usize, CHUNK] {
        // Pre-seal a chunk with BoringSSL (format is identical either way).
        let ctx =
            boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_128_gcm(), &key)
                .unwrap();
        let mut ct = vec![0xabu8; size];
        ct.resize(size + 16, 0);
        let (body, tag) = ct.split_at_mut(size);
        ctx.seal_in_place(&nonce, body, tag, b"").unwrap();
        let ct = ct;

        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::new("rustcrypto", size), &ct, |b, ct| {
            use aes_gcm::aead::{AeadInOut, KeyInit, inout::InOutBuf};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
            let mut buf = ct.clone();
            b.iter(|| {
                buf.copy_from_slice(ct);
                let (body, tag) = buf.split_at_mut(size);
                cipher
                    .decrypt_inout_detached(
                        <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(&nonce[..]).unwrap(),
                        b"",
                        InOutBuf::from(&mut *body),
                        <&aes_gcm::aead::Tag<aes_gcm::Aes128Gcm>>::try_from(&*tag).unwrap(),
                    )
                    .unwrap();
                black_box(body[0]);
            });
        });

        g.bench_with_input(BenchmarkId::new("boringssl", size), &ct, |b, ct| {
            let mut buf = ct.clone();
            b.iter(|| {
                buf.copy_from_slice(ct);
                let (body, tag) = buf.split_at_mut(size);
                ctx.open_in_place(&nonce, body, tag, b"").unwrap();
                black_box(body[0]);
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_seal, bench_open);
criterion_main!(benches);
