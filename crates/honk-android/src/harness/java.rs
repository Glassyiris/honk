//! The JNI entry points of `dev.tunbench.Bench` and the `Host` backed by the app's host object,
//! both described in the `harness` module doc. `run` holds its calling thread until the plan
//! ends; `stop` may be called from any thread. A host call attaches its thread to the JVM when it
//! is not attached yet (the engine starter) and runs in a local frame of its own; a Java
//! exception comes back as an error.

use super::account::{Platform, Tun};
use super::engine::HEV_THREAD;
use super::load::Stop;
use super::plan::Plan;
use super::run::{self, Host};
use crate::{get_string, sys};
use jni::errors::{LogErrorAndDefault, Result as JniResult, ThrowRuntimeExAndDefault};
use jni::objects::{Global, JClass, JLongArray, JObject, JString, JValue};
use jni::{Env, JavaVM, NativeMethod, jni_sig, jni_str, native_method};
use std::fs::{self, File};
use std::io::BufWriter;
use std::os::fd::RawFd;
use std::path::PathBuf;

static STOP: Stop = Stop::new();

struct JavaHost {
    host: Global<JObject<'static>>,
    out_dir: PathBuf,
}

impl JavaHost {
    fn call<T>(
        &self,
        what: &str,
        f: impl FnOnce(&mut Env, &JObject) -> JniResult<T>,
    ) -> Result<T, String> {
        JavaVM::singleton()
            .and_then(|vm| vm.attach_current_thread(|env| f(env, &self.host)))
            .map_err(|e| format!("{what}: {e}"))
    }
}

impl Host for JavaHost {
    fn open_tun(&self, mtu: u16) -> Result<RawFd, String> {
        let fd = self.call("openTun", |env, h| {
            let args = [JValue::Int(i32::from(mtu))];
            env.call_method(h, jni_str!("openTun"), jni_sig!("(I)I"), &args)?
                .i()
        })?;
        if fd < 0 {
            return Err("openTun failed (logcat tag TunBench)".into());
        }
        Ok(fd)
    }

    fn close_tun(&self) {
        self.call("closeTun", |env, h| {
            env.call_method(h, jni_str!("closeTun"), jni_sig!("()V"), &[])?
                .v()
        })
        .unwrap_or_else(|e| sys::log_error(&e));
    }

    fn start_hev(&self, config: &str, tun: RawFd) -> Result<(), String> {
        let path = self.out_dir.join("hev-socks5-tunnel.yml");
        fs::write(&path, config).map_err(|e| format!("write {}: {e}", path.display()))?;
        let started = self.call("startHev", |env, h| {
            // Attaching to the JVM renamed this thread (ART names it after its new Java peer,
            // "Thread-N"); hev's threads take the name it has now.
            sys::set_thread_name(HEV_THREAD);
            let path = env.new_string(path.to_string_lossy())?;
            let args = [JValue::Object(&path), JValue::Int(tun)];
            let sig = jni_sig!("(Ljava/lang/String;I)Z");
            env.call_method(h, jni_str!("startHev"), sig, &args)?.z()
        })?;
        if !started {
            return Err("startHev failed (logcat tag TunBench)".into());
        }
        Ok(())
    }

    fn stop_hev(&self) -> Result<(), String> {
        let stopped = self.call("stopHev", |env, h| {
            env.call_method(h, jni_str!("stopHev"), jni_sig!("()Z"), &[])?
                .z()
        })?;
        if !stopped {
            return Err("stopHev failed (logcat tag TunBench)".into());
        }
        Ok(())
    }

    fn hev_tun(&self) -> Result<Tun, String> {
        let mut v = [0i64; 4];
        self.call("hevStats", |env, h| {
            let stats = env.call_method(h, jni_str!("hevStats"), jni_sig!("()[J"), &[])?;
            let array = env.cast_local::<JLongArray>(stats.l()?)?;
            array.get_region(env, 0, &mut v)
        })?;
        let [reads, read_bytes, writes, write_bytes] = v.map(|n| n as u64);
        Ok(Tun {
            reads,
            read_bytes,
            writes,
            write_bytes,
        })
    }

    fn platform(&self) -> Result<Platform, String> {
        let json = self.call("platform", |env, h| {
            let sig = jni_sig!("()Ljava/lang/String;");
            let s = env.call_method(h, jni_str!("platform"), sig, &[])?;
            env.cast_local::<JString>(s.l()?)?.try_to_string(env)
        })?;
        serde_json::from_str(&json).map_err(|e| format!("platform: {e}"))
    }

    fn progress(&self, done: usize, total: usize) {
        self.call("progress", |env, h| {
            let args = [JValue::Int(done as i32), JValue::Int(total as i32)];
            env.call_method(h, jni_str!("progress"), jni_sig!("(II)V"), &args)?
                .v()
        })
        .unwrap_or_else(|e| sys::log_error(&e));
    }
}

fn run_plan(host: &JavaHost, plan_path: &str, run_id: &str) -> Result<(), String> {
    let json = fs::read_to_string(plan_path).map_err(|e| format!("read {plan_path}: {e}"))?;
    let plan = Plan::parse(&json)?;
    let dir = &host.out_dir;
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    fs::write(dir.join("plan.json"), &json).map_err(|e| format!("copy the plan: {e}"))?;
    let path = dir.join("results.jsonl");
    let file = File::create(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
    run::run(&plan, run_id, host, &mut BufWriter::new(file), &STOP)
}

// See lib.rs for allow(deprecated): jni-macros 0.22.4 expands to AtomicBool::fetch_update.
#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.Bench",
    static fn run(host: JObject, plan_path: JString, out_dir: JString, run_id: JString) -> JString,
    fn = bench_run,
    export = "Java_dev_tunbench_Bench_run",
    // null means every step was written, so a JNI error or a panic must not come back as null.
    error_policy = ThrowRuntimeExAndDefault,
};

fn bench_run<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    host: JObject<'local>,
    plan_path: JString<'local>,
    out_dir: JString<'local>,
    run_id: JString<'local>,
) -> JniResult<JString<'local>> {
    let plan_path = get_string(env, &plan_path);
    let out_dir = PathBuf::from(get_string(env, &out_dir));
    let run_id = get_string(env, &run_id);
    let ran = env.new_global_ref(&host).map(|host| {
        let host = JavaHost { host, out_dir };
        run_plan(&host, &plan_path, &run_id)
    });
    // A stop sent before or during this run ended it; the next run starts without one.
    STOP.reset();
    match ran? {
        Ok(()) => Ok(JString::default()),
        Err(e) => {
            sys::log_error(&format!("bench: {e}"));
            env.new_string(e)
        }
    }
}

#[allow(deprecated)]
const _: NativeMethod = native_method! {
    java_type = "dev.tunbench.Bench",
    static fn stop() -> void,
    fn = bench_stop,
    export = "Java_dev_tunbench_Bench_stop",
    error_policy = LogErrorAndDefault,
};

fn bench_stop<'local>(_env: &mut Env<'local>, _class: JClass<'local>) -> JniResult<()> {
    STOP.set();
    Ok(())
}
