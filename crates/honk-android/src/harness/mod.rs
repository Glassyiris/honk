//! The bench runner (feature `bench`): test tooling that does not ship. It runs a JSON plan inside
//! the TunBench app with the generator, engine, relay (hev only) and sink on their own pinned
//! CPUs, and writes one JSON line per measurement.
//!
//! `plan` parses and schedules the plan, `run` owns the measurement sequence and the record,
//! `engine` starts the engine under test and finds its threads, `load` the generator, the
//! workload and the loopback server, `sink` the far end of the flows, `relay` the SOCKS5 front
//! for hev, `account` the per-role accounting and the checks that reject a window, `java` the
//! JNI surface below. Accounting reads go through
//! `crate::sys` only; nothing here writes `unsafe` code.
//!
//! # JNI surface
//!
//! Class `dev.tunbench.Bench`, two static natives. In Kotlin, `object Bench` with
//! `init { System.loadLibrary("honkengine") }` and `@JvmStatic external fun`, so a first call
//! does not depend on `HonkEngine` having loaded the library:
//!
//! - `run(host: BenchHost, planPath: String, outDir: String, runId: String): String?` runs the
//!   plan at `planPath`, writing `outDir/plan.json` (a copy) and `outDir/results.jsonl`, and
//!   returns null when every step was written, else why it stopped (`"cancelled"` after
//!   `stop`); a JNI error or a panic throws `RuntimeException`. It blocks until then; call it
//!   from one dedicated thread, which it pins to the plan's generator CPUs.
//! - `stop()` ends the current measurement as rejected (`cancelled`), tears it down within its
//!   deadline and makes `run` return; sent before `run`, it cancels that run.
//!
//! `host` is any object with these methods, which the runner calls by name and JNI signature:
//!
//! | Method | Signature | Does |
//! | --- | --- | --- |
//! | `openTun(mtu: Int): Int` | `(I)I` | establish the VPN with this MTU (198.18.0.0/15, the app not excluded); its fd, or -1 |
//! | `closeTun()` | `()V` | close that fd (called after the engine stopped) |
//! | `startHev(configPath: String, tunFd: Int): Boolean` | `(Ljava/lang/String;I)Z` | `TProxyService.TProxyStartService(configPath, tunFd)` |
//! | `stopHev(): Boolean` | `()Z` | `TProxyService.TProxyStopService()`; on false or an exception the tun stays open and `run` ends |
//! | `hevStats(): LongArray` | `()[J` | `TProxyService.TProxyGetStats()` |
//! | `platform(): String` | `()Ljava/lang/String;` | a JSON object, see [`account::Platform`] |
//! | `progress(done: Int, total: Int)` | `(II)V` | `done` of `total` lines are written |
//!
//! All run on the `run` thread except `startHev`, which runs on a native thread pinned to the
//! engine CPUs and named `tb-hev` (attached to the JVM for the call), so hev's threads inherit
//! both: the runner finds them by that name.

#![deny(unsafe_code)]

pub mod account;
pub mod engine;
mod java;
pub mod load;
pub mod plan;
pub mod relay;
pub mod run;
pub mod sink;
