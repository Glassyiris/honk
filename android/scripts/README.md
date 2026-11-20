# Android benchmark harness

Tools for measuring honk-netstack on arm64 Android phones. Nothing here runs in CI, and the
results are not a performance gate.

## What it measures

1. **The netstack alone.** `crates/honk-netstack/examples/tcp_bulk.rs` runs an endpoint-mode client stack
   and a transparent-mode server stack in one thread and passes packets between them directly.
   There is no tun and no socket, so the CPU time is the cost of the two stacks per packet and
   per byte. The `stack` Criterion bench (`crates/honk-netstack/benches/stack.rs`) is
   cross-built alongside it.
2. **The Android VpnService path.** The TunBench app (`android/tunbench/`, package
   `dev.tunbench`) opens a VpnService tun that routes `198.18.0.0/15` and runs one of two engines
   on it:
   - `hev`: [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) 2.20.0, the
     baseline. It relays each flow to a SOCKS5 server.
   - `honk`: `crates/honk-android` (`libhonkengine.so`), honk's Android VpnService
     integration: honk-netstack in transparent mode on the tun fd. It relays every TCP flow to one fixed upstream. It ignores UDP.

   `bench.sh` runs iperf3 in Termux on the same phone through the tunnel. For each run it
   records throughput, the app's CPU time per GB, the Termux side's CPU time, whether the screen
   was on, the CPU clocks and temperatures mid-run, and the app's cpuset.
3. **A built-in generator and sink (planned).** This mode will generate and absorb traffic
   inside the app, so the Termux side's CPU time no longer weighs on the result.

## Prerequisites

- A Linux x86_64 build host. On other hosts, set `NDK_HOST_TAG` to the NDK's prebuilt
  directory name.
- JDK 21 (`JAVA_HOME`).
- Android SDK with NDK `30.0.16248370` (`ANDROID_HOME`, or `sdk.dir` in
  `android/tunbench/local.properties`).
- rustup with the repository's toolchain and the `aarch64-linux-android` target:
  `rustup target add aarch64-linux-android`.
- cargo-ndk 4.1.2: `cargo install cargo-ndk --version 4.1.2 --locked`.
- The hev submodule: `git submodule update --init --recursive`.
- On the phone, for the VpnService runs: USB debugging, Termux with `openssh`, `iperf3` and
  `tmux`, and a SOCKS5 redirector for hev. The redirector serves SOCKS5 and connects every
  request to the local iperf3 server; it is not part of this repository.

## Build

```sh
(cd android/tunbench && ./gradlew assembleDebug)
android/scripts/build-netstack-bench.sh       # tcp_bulk, tcp_bulk-native, netstack-criterion -> android/scripts/out/
```

The Gradle build takes the NDK from the Android Gradle plugin and needs no environment script.
`build-netstack-bench.sh` sources `android-env.sh` itself, which sets the NDK linker variables for
cargo: set `ANDROID_HOME` (default `$HOME/Android/Sdk`) and, on a non-Linux host, `NDK_HOST_TAG`
before running it.

The Gradle build runs the `buildHonkEngine` task, which runs `cargo ndk` in `crates/honk-android`
with the Android Gradle plugin's NDK to build `libhonkengine.so`. It builds hev with ndk-build.
The APK is `android/tunbench/app/build/outputs/apk/debug/app-debug.apk`.

`crates/honk-android` is not a workspace member and has its own `Cargo.lock`. Its relay test runs
on the build host: `cd crates/honk-android && cargo test --release`.

## Run

Netstack alone, on the phone:

```sh
adb push android/scripts/out/tcp_bulk /data/local/tmp/
adb shell /data/local/tmp/tcp_bulk --mtu 8500 --flows 1 --cpu 7
```

`tcp_bulk --help` prints the usage line; the flags are documented at the top of `tcp_bulk.rs`.

The VpnService path:

```sh
adb install -r android/tunbench/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n dev.tunbench/.MainActivity     # approve the VPN prompt once
adb shell am start -n dev.tunbench/.MainActivity --es action start \
    --es engine honk --es host 127.0.0.1 --es port 5202 --es mtu 8500 --es cpus 7
adb shell am start -n dev.tunbench/.MainActivity --es action stop
```

Intent extras:

| Extra | Meaning |
| --- | --- |
| `action` | `start` or `stop` |
| `engine` | `honk` or `hev` |
| `host`, `port` | `hev`: the SOCKS5 server. `honk`: the upstream that receives every flow. |
| `mtu` | tun MTU |
| `cpus` | CPU list for the engine's worker thread, e.g. `7` or `4-7` |

Once a second the app writes telemetry to `files/telemetry.txt` as one `key=value` line: the
engine, whether it runs, the CPUs requested, and the worker thread's CPU time, current core,
migrations, context switches, allowed CPUs and cpuset. Read it with
`adb shell run-as dev.tunbench cat files/telemetry.txt`.

`bench.sh` drives a full matrix: engines interleaved within each repetition, several iperf3
option sets, cooldown between runs. It writes one TSV row per run. Set `TERMUX_SSH` to the ssh
arguments that reach Termux. The script header lists the other variables (ports, redirector
command, sampled CPUs) and their defaults.

```sh
TERMUX_SSH="-p 8022 u0_a123@phone.lan" android/scripts/bench.sh -e "hev honk" -m 8500 -n 5 -A 7
```

## Known limits

- `crates/honk-android` is the first version of honk's Android VpnService integration: one
  worker thread on an epoll loop, TCP only. Its JNI API (`dev.tunbench.HonkEngine`) may change
  as the integration is adapted.
- `cpus` must fall inside the app's current cpuset (`/proc/<pid>/cpuset`). Otherwise the
  affinity request fails or is narrowed. The telemetry line shows the CPUs in effect.
- Turning the screen off cuts throughput to about a third. `bench.sh` keeps the screen on while
  USB is connected (`svc power stayon usb`) and records the wakefulness of every run.
- Use MTU 8500, the app's default.
- The thermal sensor names and the default `FREQ_CPUS` in `bench.sh` match Pixel devices.
