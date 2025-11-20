#!/bin/bash
set -e

CARGO_BUILD_TARGET_DIR="target" cargo +nightly build -Zbuild-std=core --manifest-path crates/socket-router/Cargo.toml --target bpfel-unknown-none --release

#DIR="target/bpfel-unknown-none/release"

# if ! [ -d "$DIR" ]; then
#     mkdir -p "$DIR"
# fi

#clang -target bpf -Wall -O2 -g -c crates/socket-router/src/dummy.c -o "$DIR/dummy"
#clang -target bpf -Wall -O2 -g -c crates/socket-router/src/main.c -o "$DIR/socket-router"
#clang -target bpf -Wall -O2 -g -c crates/socket-router/src/main.c -o target/bpfel-unknown-none/release/socket-router-c.o
#bpftool gen object target/bpfel-unknown-none/release/socket-router-bpf target/bpfel-unknown-none/release/socket-router-c.o
