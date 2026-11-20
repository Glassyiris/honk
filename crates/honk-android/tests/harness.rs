//! The bench runner on the build host, no tun: the generator connects straight to the sink over
//! loopback, a stub stands in for the app and hev, and threads named like hev's stand in for an
//! engine (`common` holds these doubles). Accounting reads this process's own threads. The tests run one at a time: they pin
//! to the same CPUs, and the engine is every thread named `HEV_THREAD`.

mod common;

use common::*;
use honkengine::harness::engine::{self, HEV_THREAD, Running};
use honkengine::harness::load::{Flows, Server, Stop, Traffic, Workload};
use honkengine::harness::plan::{Case, Dir, Engine, Pin};
use honkengine::harness::run::{self, Setup, measure};
use honkengine::harness::sink::Sink;
use honkengine::sys;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn receivers_count_every_payload_byte() {
    let _serial = serial();
    let pin = pin();
    let payload = vec![1u8; 3 << 20];
    // up: the sink receives what a plain client writes.
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    let w = Workload::new(Traffic::Up);
    sink.set_workload(Some(w.clone()));
    w.open();
    let mut c = TcpStream::connect(sink.server.addr).unwrap();
    c.write_all(&payload).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let deadline = || Instant::now() + Duration::from_secs(10);
    assert!(w.wait_drained(1, deadline()));
    assert_eq!(w.received(), payload.len() as u64);
    w.stop();
    sink.server.stop();
    // down: the generator receives what a plain server writes.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let w = Workload::new(Traffic::Down);
    w.open();
    let mut flows = Flows::open(l.local_addr().unwrap(), 1, &w, pin.generator.as_slice());
    let (mut s, _) = l.accept().unwrap();
    s.write_all(&payload).unwrap();
    drop(s);
    assert!(w.wait_drained(1, deadline()));
    assert_eq!(w.received(), payload.len() as u64);
    w.stop();
    flows.join();
}

/// A connection accepted right before `stop` whose handler runs only after it: `stop` still
/// returns, the handler shut down or turned away.
#[test]
fn server_stop_returns_with_a_late_handler() {
    let _serial = serial();
    let cpu = cpus()[3];
    // The server's threads at nice 19 share their CPU with a busy thread at nice 0, so a new
    // handler waits long for its turn.
    let busy = Arc::new(AtomicBool::new(true));
    let hog = {
        let busy = busy.clone();
        thread::spawn(move || {
            sys::set_affinity(&[cpu]).unwrap();
            while busy.load(Relaxed) {}
        })
    };
    let server = thread::spawn(move || {
        // SAFETY: plain syscall on the calling thread; the threads it creates inherit the nice.
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19) }, 0);
        Server::start("tb-late", &[cpu], |mut s, _| {
            let _ = s.read(&mut [0u8; 1]);
        })
        .unwrap()
    })
    .join()
    .unwrap();
    let threads = || std::fs::read_dir("/proc/self/task").unwrap().count();
    let before = threads();
    let client = TcpStream::connect(server.addr).unwrap();
    // The acceptor has created the handler.
    let deadline = Instant::now() + Duration::from_secs(10);
    while threads() == before {
        assert!(Instant::now() < deadline, "no handler");
    }
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        server.stop();
        let _ = tx.send(());
    });
    thread::sleep(Duration::from_millis(300));
    busy.store(false, Relaxed);
    hog.join().unwrap();
    let stopped = rx.recv_timeout(Duration::from_secs(5)).is_ok();
    // Frees a handler left blocked on its read, so the stop above can end.
    drop(client);
    assert!(stopped, "stop waited on a handler registered after it");
}

/// A warmup that reached some other server that reads to EOF and closes, as the sink does.
#[test]
fn warmup_needs_the_sink_to_receive_it() {
    let _serial = serial();
    let sink = Sink::start(pin().sink.as_slice()).unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = other.local_addr().unwrap();
    let t = thread::spawn(move || {
        let (mut s, _) = other.accept().unwrap();
        std::io::copy(&mut s, &mut std::io::sink()).unwrap();
    });
    let stop = Stop::new();
    let timeout = Duration::from_secs(5);
    engine::warmup(sink.server.addr, &sink, None, &stop, timeout).unwrap();
    let e = engine::warmup(target, &sink, None, &stop, timeout).unwrap_err();
    assert!(e.contains("the sink did not receive it"), "{e}");
    t.join().unwrap();
    sink.server.stop();
}

/// `stop` while the warmup waits on a path that never answers.
#[test]
fn stop_cancels_the_warmup() {
    let _serial = serial();
    let sink = Sink::start(pin().sink.as_slice()).unwrap();
    // Connects (the kernel completes it) but never reads or closes.
    let dead_end = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = dead_end.local_addr().unwrap();
    let stop = Stop::new();
    let started = Instant::now();
    let e = thread::scope(|s| {
        let w = s.spawn(|| engine::warmup(target, &sink, None, &stop, Duration::from_secs(10)));
        thread::sleep(Duration::from_millis(300));
        stop.set();
        w.join().unwrap().unwrap_err()
    });
    assert_eq!(e, "cancelled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    sink.server.stop();
}

#[test]
fn bulk_window_reads_back_every_role() {
    let _serial = serial();
    let engine = StandIn::engine(|| ());
    for dir in [Dir::Up, Dir::Down] {
        let case = Case::Bulk {
            dir,
            flows: vec![2],
            seconds: 1,
        };
        let (m, sink) = measure_direct(case, 2, &StubHost::default(), &Stop::new());
        assert!(reasons(&m).is_empty(), "{dir:?}: {:?}", m.reasons);
        assert!(m.bytes.unwrap() > 1 << 20);
        let w = m.window.unwrap();
        let secs = w.elapsed_ns as f64 / 1e9;
        assert!((1.0..1.5).contains(&secs), "window {secs} s");
        let p = pin();
        let gen_threads = &w.roles.generator.threads;
        assert_eq!(gen_threads.len(), 2);
        assert!(
            gen_threads
                .iter()
                .all(|t| t.cpus == Some(p.generator.to_string()))
        );
        // The acceptor and the two connections.
        assert_eq!(w.roles.sink.threads.len(), 3);
        assert!(w.roles.sink.totals.cpu_ns.unwrap() > 0);
        assert_eq!(w.roles.engine.threads[0].tid, engine.tid);
        assert!(w.tun.unwrap().reads > 0);
        assert!(w.platform_start.is_some() && w.platform_end.is_some());
        sink.server.stop();
    }
}

/// The load stops before the window is read, so a slow read (the tun counters here) adds no
/// payload whose engine CPU the window left out.
#[test]
fn every_byte_counted_has_its_engine_cpu() {
    let _serial = serial();
    const NS_PER_BYTE: u64 = 20;
    let pin = pin();
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    let engine = forwarder(sink.server.addr, NS_PER_BYTE, Fault::None);
    let host = StubHost {
        tun_delay: Duration::from_millis(500),
        ..StubHost::default()
    };
    let setup = Setup {
        target: engine.addr,
        host: &host,
        engine: &Running::Hev,
        sink: &sink,
        relay: None,
        pin: &pin,
    };
    let case = Case::Bulk {
        dir: Dir::Up,
        flows: vec![1],
        seconds: 1,
    };
    let m = measure(&case, 1, &setup, &Stop::new());
    let bytes = m.bytes.unwrap();
    let w = m.window.as_ref().unwrap();
    let cpu = w.roles.engine.totals.cpu_ns.unwrap();
    // Slack: a thread still running when read lags by up to a scheduler tick.
    assert!(
        bytes * NS_PER_BYTE <= cpu + 20_000_000,
        "{bytes} bytes with {cpu} ns of engine CPU"
    );
    // The scans between the window's ends and the thread readings include the slow reads.
    let scans = (w.scan_start_ns, w.scan_end_ns);
    assert!(
        scans.0 >= 500_000_000 && scans.1 >= 500_000_000,
        "{scans:?}"
    );
    assert!(reasons(&m).is_empty(), "{:?}", m.reasons);
    engine.stop();
    sink.server.stop();
}

/// A flow the path resets halfway is rejected, though its threads live on and the other flows
/// deliver all they send.
#[test]
fn a_flow_reset_in_transfer_rejects_the_measurement() {
    let _serial = serial();
    let pin = pin();
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    let engine = forwarder(sink.server.addr, 0, Fault::ResetFirst);
    let host = StubHost::default();
    let setup = Setup {
        target: engine.addr,
        host: &host,
        engine: &Running::Hev,
        sink: &sink,
        relay: None,
        pin: &pin,
    };
    let case = Case::Bulk {
        dir: Dir::Up,
        flows: vec![3],
        seconds: 1,
    };
    let m = measure(&case, 3, &setup, &Stop::new());
    assert_eq!(reasons(&m), ["1 of 3 flows did not deliver all they sent"]);
    engine.stop();
    sink.server.stop();
}

/// A burst whose teardown outlasts the observe period leaves no tail to observe.
#[test]
fn a_tail_window_opened_after_its_end_is_rejected() {
    let _serial = serial();
    let pin = pin();
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    // The flow ends 1.5 s after the sink read its end.
    let slow = Fault::SlowAnswer(Duration::from_millis(1500));
    let engine = forwarder(sink.server.addr, 0, slow);
    let host = StubHost::default();
    let setup = Setup {
        target: engine.addr,
        host: &host,
        engine: &Running::Hev,
        sink: &sink,
        relay: None,
        pin: &pin,
    };
    let case = Case::Tail {
        burst_seconds: 1,
        observe_seconds: 1,
    };
    let m = measure(&case, 0, &setup, &Stop::new());
    let reasons = m.reasons.join("; ");
    assert!(
        reasons.contains(" ms after the observe period ended"),
        "{reasons}"
    );
    engine.stop();
    sink.server.stop();
}

/// bulk and sparse pass only with tun reads and writes in the window, whatever the receiver got.
#[test]
fn flows_without_tun_traffic_are_rejected() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let bulk = Case::Bulk {
        dir: Dir::Up,
        flows: vec![1],
        seconds: 1,
    };
    let sparse = Case::Sparse {
        interval_ms: 50,
        bytes: 64,
        seconds: 1,
    };
    for (case, counters, reason) in [
        (
            &bulk,
            Counters::Flat,
            "no tun reads or writes in the window",
        ),
        (&bulk, Counters::Unreadable, "tun counters: hevStats failed"),
        (
            &sparse,
            Counters::Flat,
            "no tun reads or writes in the window",
        ),
    ] {
        let host = StubHost {
            counters,
            ..StubHost::default()
        };
        let (m, sink) = measure_direct(case.clone(), 1, &host, &Stop::new());
        assert!(m.bytes.unwrap() > 0);
        assert_eq!(reasons(&m), [reason]);
        sink.server.stop();
    }
}

#[test]
fn sparse_reports_application_sends() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let case = Case::Sparse {
        interval_ms: 50,
        bytes: 64,
        seconds: 1,
    };
    let (m, sink) = measure_direct(case, 1, &StubHost::default(), &Stop::new());
    assert!(reasons(&m).is_empty(), "{:?}", m.reasons);
    let sends = m.sends.unwrap();
    assert!((18..=22).contains(&sends), "{sends} sends");
    let bytes = m.bytes.unwrap();
    assert!(
        bytes <= sends * 64 && bytes + 64 >= sends * 64,
        "{bytes} bytes"
    );
    sink.server.stop();
}

#[test]
fn idle_passes_on_thread_data_alone() {
    let _serial = serial();
    let engine = StandIn::engine(|| ());
    let host = StubHost {
        counters: Counters::Flat,
        ..StubHost::default()
    };
    let (m, sink) = measure_direct(Case::Idle { seconds: 1 }, 0, &host, &Stop::new());
    assert!(reasons(&m).is_empty(), "{:?}", m.reasons);
    assert_eq!((m.bytes, m.sends), (None, None));
    let roles = &m.window.as_ref().unwrap().roles;
    assert_eq!(roles.engine.threads[0].tid, engine.tid);
    assert!(roles.engine.totals.cpu_ns.is_some());
    sink.server.stop();
}

/// The platform probe calls into the app, which may take long: the window leaves it out.
#[test]
fn window_leaves_the_platform_probes_out() {
    let _serial = serial();
    // An engine thread that burns 200 ms of CPU while the app is probed.
    let (burn_tx, burn_rx) = mpsc::channel::<mpsc::Sender<()>>();
    let engine = StandIn::engine(move || {
        for done in burn_rx {
            let t = Instant::now();
            while t.elapsed() < Duration::from_millis(200) {}
            let _ = done.send(());
        }
    });
    engine.go();
    let host = StubHost {
        platform: Some(Box::new(move |_| {
            let (done_tx, done_rx) = mpsc::channel();
            burn_tx.send(done_tx).unwrap();
            done_rx.recv().unwrap();
            in_front()
        })),
        ..StubHost::default()
    };
    let (m, sink) = measure_direct(Case::Idle { seconds: 1 }, 0, &host, &Stop::new());
    let w = m.window.as_ref().unwrap();
    let cpu = w.roles.engine.totals.cpu_ns.unwrap();
    assert!(
        cpu < 50_000_000,
        "{cpu} ns in an idle window of {} ns",
        w.elapsed_ns
    );
    sink.server.stop();
    // Ends the burner first, so the stand-in can exit.
    drop(host);
}

#[test]
fn window_rejects_a_narrowed_mask_and_an_exited_thread() {
    let _serial = serial();
    // The engine on two CPUs, so a mask can narrow; idle has no relay or flows, and the relay's
    // CPU is free.
    let [e, g, r, s] = cpus();
    let json = format!(r#"{{"engine": "{e},{r}", "generator": "{g}", "sink": "{s}"}}"#);
    let pin: Pin = serde_json::from_str(&json).unwrap();
    let narrowed = StandIn::engine_on(&pin, move || sys::set_affinity(&[e]).unwrap());
    let exits = StandIn::engine_on(&pin, || ());
    let host = StubHost::default();
    let stop = Stop::new();
    let (m, sink) = thread::scope(|s| {
        let m = s.spawn(|| measure_pinned(&pin, Case::Idle { seconds: 1 }, 0, &host, &stop));
        thread::sleep(Duration::from_millis(300));
        narrowed.go();
        exits.go();
        exits.go();
        m.join().unwrap()
    });
    let reasons = m.reasons.join("; ");
    let changed = format!(
        "engine thread {} ({HEV_THREAD}) mask changed from {} to {e}",
        narrowed.tid, pin.engine
    );
    assert!(reasons.contains(&changed), "{reasons}");
    let exited = format!("engine thread {} ({HEV_THREAD}) exited", exits.tid);
    assert!(reasons.contains(&exited), "{reasons}");
    // The exited thread stays in the record, its values and the role's sums null.
    let engine = &m.window.as_ref().unwrap().roles.engine;
    let gone = engine.threads.iter().find(|t| t.tid == exits.tid).unwrap();
    assert_eq!((gone.cpu_ns, gone.last_cpu), (None, None));
    assert_eq!(gone.comm.as_deref(), Some(HEV_THREAD));
    assert_eq!(
        (engine.totals.cpu_ns, engine.totals.user_ticks),
        (None, None)
    );
    sink.server.stop();
}

/// A window needs the cpuset at both ends, and this host may have none.
#[test]
fn unreadable_cpuset_rejects_the_window() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let (m, sink) = measure_direct(
        Case::Idle { seconds: 1 },
        0,
        &StubHost::default(),
        &Stop::new(),
    );
    let w = m.window.as_ref().unwrap();
    match sys::cpuset() {
        Ok(cpuset) => {
            assert!(m.reasons.is_empty(), "{:?}", m.reasons);
            assert_eq!(w.cpuset_start.as_ref(), Some(&cpuset));
            assert_eq!(w.cpuset_end.as_ref(), Some(&cpuset));
        }
        Err(e) => assert_eq!(
            m.reasons,
            [
                format!("cpuset unreadable at the window start: {e}"),
                format!("cpuset unreadable at the window end: {e}")
            ]
        ),
    }
    sink.server.stop();
}

#[test]
fn screen_off_or_background_rejects_the_window() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    // On at the start, off and in the background at the end.
    let host = StubHost {
        platform: Some(Box::new(|calls| {
            let mut p = in_front();
            if calls > 0 {
                p.interactive = false;
                p.bench_activity_resumed = false;
            }
            p
        })),
        ..StubHost::default()
    };
    let (m, sink) = measure_direct(Case::Idle { seconds: 1 }, 0, &host, &Stop::new());
    assert_eq!(
        reasons(&m),
        [
            "screen off at the window end",
            "not foreground at the window end"
        ]
    );
    sink.server.stop();
}

#[test]
fn stop_cancels_a_bulk_window_and_tears_it_down() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let stop = Stop::new();
    let started = Instant::now();
    let host = StubHost::default();
    let (m, sink) = thread::scope(|s| {
        let m = s.spawn(|| {
            let case = Case::Bulk {
                dir: Dir::Up,
                flows: vec![2],
                seconds: 60,
            };
            measure_direct(case, 2, &host, &stop)
        });
        thread::sleep(Duration::from_millis(500));
        stop.set();
        m.join().unwrap()
    });
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(reasons(&m), ["cancelled"]);
    // Only the acceptor is left.
    assert_eq!(sink.server.threads().len(), 1);
    sink.server.stop();
}

/// `stop` while the flows wait for a sink that never accepts them, or for a connect that is
/// never answered.
#[test]
fn stop_cancels_the_wait_for_flows() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let pin = pin();
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    let dead_end = TcpListener::bind("127.0.0.1:0").unwrap();
    // A backlog of 0, full after one connection: it drops every later SYN.
    let full = TcpListener::bind("127.0.0.1:0").unwrap();
    // SAFETY: plain syscall on a listening socket; only its backlog changes.
    assert_eq!(unsafe { libc::listen(full.as_raw_fd(), 0) }, 0);
    let _queued = TcpStream::connect(full.local_addr().unwrap()).unwrap();
    for target in [dead_end.local_addr().unwrap(), full.local_addr().unwrap()] {
        let host = StubHost::default();
        let setup = Setup {
            target,
            host: &host,
            engine: &Running::Hev,
            sink: &sink,
            relay: None,
            pin: &pin,
        };
        let stop = Stop::new();
        let started = Instant::now();
        let m = thread::scope(|s| {
            let m = s.spawn(|| {
                let case = Case::Bulk {
                    dir: Dir::Up,
                    flows: vec![2],
                    seconds: 60,
                };
                measure(&case, 2, &setup, &stop)
            });
            thread::sleep(Duration::from_millis(300));
            stop.set();
            m.join().unwrap()
        });
        assert_eq!(m.reasons, ["cancelled"], "{target}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{target}: {:?}",
            started.elapsed()
        );
    }
    sink.server.stop();
}

#[test]
fn engine_start_finds_the_threads_it_created() {
    let _serial = serial();
    let host = StubHost::default();
    let pin = pin();
    let (tun, _peer) = UnixDatagram::pair().unwrap();
    let upstream = "127.0.0.1:9".parse().unwrap();
    for (engine, threads) in [(Engine::Hev, 2), (Engine::Honk, 1)] {
        let running =
            engine::start(engine, tun.as_raw_fd(), 1500, upstream, &pin.engine, &host).unwrap();
        let tids = settled(&running, threads);
        assert_eq!(tids.len(), threads, "{engine:?}: {tids:?}");
        for &tid in &tids {
            assert_eq!(
                sys::affinity(tid).unwrap(),
                pin.engine.as_slice(),
                "{engine:?} {tid}"
            );
        }
        running.stop(&host).unwrap();
    }
}

/// hev's threads are the ones named like its starter: not a thread the app starts meanwhile,
/// and also one hev creates later.
#[test]
fn hev_threads_are_found_by_name() {
    let _serial = serial();
    // Another thread of the app, which starts one of its own when asked.
    let (ask_tx, ask_rx) = mpsc::channel::<mpsc::Sender<()>>();
    let app = thread::spawn(move || {
        let mut started = Vec::new();
        for done in ask_rx {
            let jit = thread::Builder::new().name("Jit thread pool".into());
            started.push(StandIn::spawn(jit, None, || ()));
            done.send(()).unwrap();
        }
    });
    let ask_tx = Mutex::new(ask_tx);
    let host = StubHost {
        during_hev_start: Some(Box::new(move || {
            let (done_tx, done_rx) = mpsc::channel();
            ask_tx.lock().unwrap().send(done_tx).unwrap();
            done_rx.recv().unwrap();
        })),
        ..StubHost::default()
    };
    let (tun, _peer) = UnixDatagram::pair().unwrap();
    let upstream = "127.0.0.1:9".parse().unwrap();
    let running = engine::start(
        Engine::Hev,
        tun.as_raw_fd(),
        1500,
        upstream,
        &pin().engine,
        &host,
    )
    .unwrap();
    let at_start = settled(&running, 2);
    let names: Vec<_> = (at_start.iter())
        .map(|t| std::fs::read_to_string(format!("/proc/self/task/{t}/comm")).unwrap())
        .collect();
    assert_eq!(at_start.len(), 2, "{names:?}");
    // hev's first thread starts another, which the next window counts.
    host.hev.lock().unwrap()[0].go();
    let (m, sink) = measure_direct(Case::Idle { seconds: 1 }, 0, &host, &Stop::new());
    let engine = &m.window.as_ref().unwrap().roles.engine;
    assert_eq!(engine.threads.len(), 3, "{:?}", engine.threads);
    assert!(
        at_start
            .iter()
            .all(|t| engine.threads.iter().any(|x| x.tid == *t))
    );
    sink.server.stop();
    running.stop(&host).unwrap();
    drop(host);
    app.join().unwrap();
}

/// A thread hev starts inside the window is in no total: the window is rejected.
#[test]
fn an_engine_thread_started_in_the_window_rejects_it() {
    let _serial = serial();
    let _engine = StandIn::engine(|| ());
    let host = StubHost::default();
    let stop = Stop::new();
    let (late, (m, sink)) = thread::scope(|s| {
        let m = s.spawn(|| measure_direct(Case::Idle { seconds: 1 }, 0, &host, &stop));
        thread::sleep(Duration::from_millis(300));
        let late = StandIn::engine(|| ());
        (late, m.join().unwrap())
    });
    let changed = format!(
        "engine threads changed in the window: added [{}], removed []",
        late.tid
    );
    assert_eq!(reasons(&m), [changed]);
    sink.server.stop();
}

#[test]
fn run_writes_a_line_per_step_until_stopped() {
    let _serial = serial();
    let plan = plan(
        r#"["hev", "honk"]"#,
        r#"[{ "kind": "bulk", "dir": "up", "flows": [4], "seconds": 1 },
            { "kind": "idle", "seconds": 1 }]"#,
    );
    let host = StubHost::default();
    let mut out = Vec::new();
    let r = thread::scope(|s| {
        s.spawn(|| run::run(&plan, "test-run", &host, &mut out, &host.stop))
            .join()
            .unwrap()
    });
    assert_eq!(r, Err("cancelled".into()));
    let lines: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(*host.progress.lock().unwrap(), [(1, 4), (2, 4), (3, 4)]);
    let engines: Vec<_> = lines
        .iter()
        .map(|l| l["engine"].as_str().unwrap())
        .collect();
    assert_eq!(engines, ["hev", "honk", "hev"]);
    let first = &lines[0];
    assert_eq!(
        (
            first["run"].as_str(),
            first["seq"].as_u64(),
            first["case_index"].as_u64()
        ),
        (Some("test-run"), Some(0), Some(0))
    );
    assert_eq!(
        (
            first["flows"].as_u64(),
            first["case"]["kind"].as_str(),
            first["case"]["flows"].as_u64()
        ),
        (Some(4), Some("bulk"), Some(4))
    );
    assert_eq!(lines[2]["flows"], 0);
    assert_eq!(first["pin"], serde_json::to_value(pin()).unwrap());
    assert!(
        lines
            .iter()
            .all(|l| l["status"] == "rejected" && l["reason"] == "open tun: no VpnService here")
    );
}

#[test]
fn a_run_stopped_before_its_first_step_opens_no_tun() {
    let _serial = serial();
    let plan = plan(r#"["honk"]"#, r#"[{ "kind": "idle", "seconds": 1 }]"#);
    let host = StubHost::default();
    host.stop.set();
    let mut out = Vec::new();
    let r = thread::scope(|s| {
        s.spawn(|| run::run(&plan, "test-run", &host, &mut out, &host.stop))
            .join()
            .unwrap()
    });
    assert_eq!(r, Err("cancelled".into()));
    assert!(!host.tun_opened.load(Relaxed));
    assert!(out.is_empty());
}

/// hev may still use the tun when its stop fails: the tun stays open and the run ends.
#[test]
fn a_failed_hev_stop_keeps_the_tun_and_ends_the_run() {
    let _serial = serial();
    let plan = plan(r#"["hev"]"#, r#"[{ "kind": "idle", "seconds": 1 }]"#);
    let (tun, _peer) = UnixDatagram::pair().unwrap();
    // Set once hev runs, so the warmup ends at once.
    let stop = Arc::new(Stop::new());
    let host = StubHost {
        tun: Some(tun.as_raw_fd()),
        hev_stop_fails: true,
        during_hev_start: Some(Box::new({
            let stop = stop.clone();
            move || stop.set()
        })),
        ..StubHost::default()
    };
    let not_stopped = "the engine did not stop (stub: hev still runs); its tun is left open";
    let mut out = Vec::new();
    // Then with a full results file: the error says both.
    let runs: [(&mut (dyn Write + Send), String); 2] = [
        (&mut out, not_stopped.into()),
        (
            &mut Full,
            format!("{not_stopped}; write results: No space left on device (os error 28)"),
        ),
    ];
    for (out, error) in runs {
        stop.reset();
        let r = thread::scope(|s| {
            s.spawn(|| run::run(&plan, "test-run", &host, out, &stop))
                .join()
                .unwrap()
        });
        assert_eq!(r, Err(error));
        assert!(!host.tun_closed.load(Relaxed));
    }
    let line: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        line["reason"],
        "cancelled; stop the engine: stub: hev still runs"
    );
    host.end_hev();
}
