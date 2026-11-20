//! honk's Android VpnService integration: honk-netstack as a transparent TCP terminator on the
//! tun fd, relaying every flow to one fixed upstream. JNI surface of `dev.tunbench.HonkEngine`,
//! plus thread helpers (affinity, naming, /proc telemetry) that the hev path uses as well.

pub mod engine;
pub mod sys;

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlongArray, jstring};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::Ordering::Relaxed;

static ENGINE: Mutex<Option<engine::Handle>> = Mutex::new(None);

fn get_string(env: &mut JNIEnv, s: &JString) -> String {
    if s.is_null() {
        return String::new();
    }
    env.get_string(s).map(Into::into).unwrap_or_default()
}

fn new_string(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map_or(ptr::null_mut(), |s| s.into_raw())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_start<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    tun_fd: jint,
    mtu: jint,
    target_host: JString<'l>,
    target_port: jint,
    cpu_list: JString<'l>,
) -> jboolean {
    let host = get_string(&mut env, &target_host);
    let cpus = get_string(&mut env, &cpu_list);
    let mut slot = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        sys::log_error("start: already running");
        return JNI_FALSE;
    }
    match engine::Params::parse(tun_fd, mtu, &host, target_port, &cpus).and_then(engine::start) {
        Ok(handle) => {
            *slot = Some(handle);
            JNI_TRUE
        }
        Err(e) => {
            sys::log_error(&format!("start: {e}"));
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_stop<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
    let handle = ENGINE.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(h) = handle {
        h.stop();
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_isRunning<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jboolean {
    if engine::SHARED.running.load(Relaxed) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_stats<'l>(
    env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jlongArray {
    let s = &engine::SHARED;
    let values = [
        s.tx_packets.load(Relaxed) as i64,
        s.tx_bytes.load(Relaxed) as i64,
        s.rx_packets.load(Relaxed) as i64,
        s.rx_bytes.load(Relaxed) as i64,
    ];
    let Ok(array) = env.new_long_array(values.len() as i32) else {
        return ptr::null_mut();
    };
    if env.set_long_array_region(&array, 0, &values).is_err() {
        return ptr::null_mut();
    }
    array.into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_workerTid<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jint {
    engine::SHARED.tid.load(Relaxed)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_workerAffinity<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jstring {
    let a = engine::SHARED
        .affinity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    new_string(&mut env, &a)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_prepareThread<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    cpu_list: JString<'l>,
    name: JString<'l>,
) -> jstring {
    let cpus = get_string(&mut env, &cpu_list);
    let name = get_string(&mut env, &name);
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
    new_string(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_gettid<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jint {
    sys::gettid()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_findThread<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    name: JString<'l>,
    exclude: jint,
) -> jint {
    let name = get_string(&mut env, &name);
    sys::find_thread(&name, exclude).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tunbench_HonkEngine_telemetry<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    tid: jint,
) -> jstring {
    let line = sys::telemetry(tid);
    new_string(&mut env, &line)
}
