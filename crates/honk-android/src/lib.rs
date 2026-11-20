//! honk's Android VpnService integration: honk-netstack as a transparent TCP terminator on the
//! tun fd, relaying every flow to one fixed upstream. JNI surface of `dev.tunbench.HonkEngine`,
//! plus thread helpers (affinity, naming, /proc telemetry) that the hev path uses as well. The
//! `bench` feature adds `harness`, the TunBench bench runner.
//!
//! Each native method is declared with `native_method!`, which checks it against its Java
//! signature and catches panics; errors are logged and the Java side gets the default value
//! (false, 0, null), as it did before. The macro's ABI check in jni-macros 0.22.4 expands to
//! `AtomicBool::fetch_update`, deprecated since Rust 1.99, hence `allow(deprecated)` on each,
//! the smallest item around the expansion (<https://github.com/jni-rs/jni-rs/issues/846>).

pub mod engine;
#[cfg(feature = "bench")]
pub mod harness;
pub mod sys;

use jni::errors::{LogErrorAndDefault, Result};
use jni::objects::{JClass, JLongArray, JString};
use jni::sys::jint;
use jni::{Env, NativeMethod, native_method};
use std::sync::Mutex;
use std::sync::atomic::Ordering::Relaxed;

static ENGINE: Mutex<Option<engine::Handle>> = Mutex::new(None);

/// A Java string argument; null (or unreadable) reads as empty.
fn get_string(env: &Env, s: &JString) -> String {
    s.try_to_string(env).unwrap_or_default()
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn start(
        tun_fd: jint,
        mtu: jint,
        target_host: JString,
        target_port: jint,
        cpu_list: JString,
    ) -> jboolean,
    export = "Java_dev_tunbench_HonkEngine_start",
    error_policy = LogErrorAndDefault,
};

fn start<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    mtu: jint,
    target_host: JString<'local>,
    target_port: jint,
    cpu_list: JString<'local>,
) -> Result<bool> {
    let host = get_string(env, &target_host);
    let cpus = get_string(env, &cpu_list);
    let mut slot = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        sys::log_error("start: already running");
        return Ok(false);
    }
    match engine::Params::parse(tun_fd, mtu, &host, target_port, &cpus).and_then(engine::start) {
        Ok(handle) => {
            *slot = Some(handle);
            Ok(true)
        }
        Err(e) => {
            sys::log_error(&format!("start: {e}"));
            Ok(false)
        }
    }
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn stop() -> void,
    export = "Java_dev_tunbench_HonkEngine_stop",
    error_policy = LogErrorAndDefault,
};

fn stop<'local>(_env: &mut Env<'local>, _class: JClass<'local>) -> Result<()> {
    let handle = ENGINE.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(h) = handle {
        h.stop();
    }
    Ok(())
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn is_running() -> jboolean,
    export = "Java_dev_tunbench_HonkEngine_isRunning",
    error_policy = LogErrorAndDefault,
};

fn is_running<'local>(_env: &mut Env<'local>, _class: JClass<'local>) -> Result<bool> {
    Ok(engine::SHARED.running.load(Relaxed))
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn stats() -> jlong[],
    export = "Java_dev_tunbench_HonkEngine_stats",
    error_policy = LogErrorAndDefault,
};

fn stats<'local>(env: &mut Env<'local>, _class: JClass<'local>) -> Result<JLongArray<'local>> {
    let s = &engine::SHARED;
    let values = [
        s.tx_packets.load(Relaxed) as i64,
        s.tx_bytes.load(Relaxed) as i64,
        s.rx_packets.load(Relaxed) as i64,
        s.rx_bytes.load(Relaxed) as i64,
    ];
    let array = env.new_long_array(values.len())?;
    array.set_region(env, 0, &values)?;
    Ok(array)
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn worker_tid() -> jint,
    export = "Java_dev_tunbench_HonkEngine_workerTid",
    error_policy = LogErrorAndDefault,
};

fn worker_tid<'local>(_env: &mut Env<'local>, _class: JClass<'local>) -> Result<jint> {
    Ok(engine::SHARED.tid.load(Relaxed))
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn worker_affinity() -> JString,
    export = "Java_dev_tunbench_HonkEngine_workerAffinity",
    error_policy = LogErrorAndDefault,
};

fn worker_affinity<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<JString<'local>> {
    let a = engine::SHARED
        .affinity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    env.new_string(a)
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn prepare_thread(cpu_list: JString, name: JString) -> JString,
    export = "Java_dev_tunbench_HonkEngine_prepareThread",
    error_policy = LogErrorAndDefault,
};

fn prepare_thread<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    cpu_list: JString<'local>,
    name: JString<'local>,
) -> Result<JString<'local>> {
    let cpus = get_string(env, &cpu_list);
    let name = get_string(env, &name);
    let result = sys::parse_cpu_list(&cpus)
        .and_then(|list| {
            if list.is_empty() {
                Ok(())
            } else {
                sys::set_affinity(&list)
            }
        })
        .and_then(|()| {
            if !name.is_empty() {
                sys::set_thread_name(&name);
            }
            sys::affinity_list()
        });
    let out = match result {
        Ok(list) => list,
        Err(e) => {
            sys::log_error(&format!("prepareThread({cpus:?}): {e}"));
            format!("error: sched_setaffinity({cpus}): {e}")
        }
    };
    env.new_string(out)
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn gettid() -> jint,
    export = "Java_dev_tunbench_HonkEngine_gettid",
    error_policy = LogErrorAndDefault,
};

fn gettid<'local>(_env: &mut Env<'local>, _class: JClass<'local>) -> Result<jint> {
    Ok(sys::gettid())
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn find_thread(name: JString, exclude: jint) -> jint,
    export = "Java_dev_tunbench_HonkEngine_findThread",
    error_policy = LogErrorAndDefault,
};

fn find_thread<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    name: JString<'local>,
    exclude: jint,
) -> Result<jint> {
    let name = get_string(env, &name);
    Ok(sys::find_thread(&name, exclude).unwrap_or(0))
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.HonkEngine",
    static fn telemetry(tid: jint) -> JString,
    export = "Java_dev_tunbench_HonkEngine_telemetry",
    error_policy = LogErrorAndDefault,
};

fn telemetry<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    tid: jint,
) -> Result<JString<'local>> {
    env.new_string(sys::telemetry(tid))
}
