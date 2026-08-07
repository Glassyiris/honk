<!-- markdownlint-disable no-inline-html first-line-heading no-emphasis-as-heading -->

<div align="center">

# `📨 xdp`

**`AF_XDP` socket support in Rust**

[![Crates.io](https://img.shields.io/crates/v/xdp.svg)](https://crates.io/crates/xdp)
[![API Docs](https://docs.rs/xdp/badge.svg)](https://docs.rs/xdp)
[![dependency status](https://deps.rs/repo/codeberg/ca1ne/xdp/status.svg)](https://deps.rs/repo/codeberg/ca1ne/xdp)
<!-- [![Build Status](https://codeberg.org/ca1ne/xdp/workflows/CI/badge.svg)](https://codeberg.org/ca1ne/xdp/actions?workflow=CI) -->

</div>

This crate allows for the creation and usage of [AF_XDP] sockets on Linux, along with the attendant memory mappings and rings.

The primary difference between this crate and the other XSK/XDP crates available on crates.io is that this crate does not depend on any C code.

## Honk hardening fork

The `honk-linear-umem` branch is a deliberately source-incompatible fork for Honk's optional first-packet `AF_XDP` path. It pins the upstream `0.7.3` lineage while adding release-build frame ownership checks, automatic `XDP_RING_NEED_WAKEUP` handling, kernel-reported copy/zero-copy mode, and quiescent teardown accounting.

Packets follow one checked lifecycle: `Free -> Fill -> Rx -> Tx -> Completion -> Free`. Packet cloning and manual address/free APIs are removed; unsubmitted packets return their frame on drop, RX descriptors are range-checked within their exact UMEM frame, and completion frames remain quarantined through a full-ring drain before reuse. Ring operations report foreign-UMEM, invalid-descriptor, duplicate-completion, partial-drain, and post-submission wake failures. Shared UMEM and multi-buffer support remain intentionally unavailable.

## Why not use this crate?

This crate is still early days, and focused on the needs of [Quilkin](https://github.com/googleforgames/quilkin), so feature requests or bug fixes that don't pertain to it would most likely need outside contribution. There are already several other Rust crates available that (probably) have more full featured support.

## Features

- [x] Network interface enumeration and capability querying
- [x] Basic Umem support
- [ ] Shared Umem support
- [x] Fill, RX, TX, Completion rings
- [x] [TX checksum offload/completion timestamp](https://docs.kernel.org/networking/xsk-tx-metadata.html)
- [ ] [RX metadata](https://docs.kernel.org/networking/xdp-rx-metadata.html)

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[AF_XDP]: https://docs.ebpf.io/linux/concepts/af_xdp/
