#!/bin/bash
# Builds libhonkengine.so for arm64-v8a into <out>/arm64-v8a/. Called by the TunBench Gradle build
# (task buildHonkEngine); usable by hand: ./build-android.sh /tmp/jni "$ANDROID_HOME/ndk/<ver>"
# NDK_HOST_TAG selects the NDK's prebuilt toolchain directory (default linux-x86_64).
set -euo pipefail
out="$1"
ndk="${2:-${ANDROID_NDK_HOME:?pass the NDK directory or set ANDROID_NDK_HOME}}"
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here" # rustup reads rust-toolchain.toml from the working directory

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
bin="$ndk/toolchains/llvm/prebuilt/${NDK_HOST_TAG:-linux-x86_64}/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin/aarch64-linux-android29-clang"
export CC_aarch64_linux_android="$bin/aarch64-linux-android29-clang"
export AR_aarch64_linux_android="$bin/llvm-ar"

cargo build --release --target aarch64-linux-android
mkdir -p "$out/arm64-v8a"
cp "$here/target/aarch64-linux-android/release/libhonkengine.so" "$out/arm64-v8a/libhonkengine.so"
