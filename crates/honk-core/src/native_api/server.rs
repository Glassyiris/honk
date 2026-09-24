//! HTTP connection, observer and credential-worker ownership.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::Extension;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::types::{TrafficBytes, TrafficConnections, TrafficRates, TrafficSummary};
use super::{NativeState, Peer, canonical_ip, router, timestamp};
use crate::connection_tracker::ConnectionTracker;

pub(super) async fn sample_traffic(state: Arc<NativeState>, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous: Option<(Instant, Option<(u64, u64)>)> = None;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = interval.tick() => {
                state.observation.settings.maintain(&state.observation);
                state.observation.flows.maintain();
                let now = Instant::now();
                let totals = state.stats.traffic_totals();
                let rates = previous.and_then(|(instant, old)| {
                    let elapsed = now.duration_since(instant);
                    let (old_up, old_down) = old?;
                    let (up, down) = totals?;
                    let up = up.checked_sub(old_up)?;
                    let down = down.checked_sub(old_down)?;
                    if elapsed.is_zero() { return None; }
                    let rate = |bytes: u64| u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos()).ok().map(|value| value.to_string());
                    Some(TrafficRates { window_seconds: elapsed.as_secs_f64(), upload_bytes_per_second: rate(up), download_bytes_per_second: rate(down) })
                });
                let (mut tcp, mut udp) = (0u64, 0u64);
                state.tracker.visit(|entry| match entry.network.as_str() { "tcp" => tcp += 1, "udp" => udp += 1, _ => {} });
                *state.sample.write() = Some(TrafficSummary {
                    scope: "visible", observed_by: "userspace", counter_since: Some(timestamp(state.stats.counter_since())), sampled_at: Some(timestamp(SystemTime::now())),
                    connections: TrafficConnections { tcp: Some(tcp), udp: Some(udp), total: Some(tcp + udp) },
                    bytes: TrafficBytes { upload: totals.map(|bytes| bytes.0.to_string()), download: totals.map(|bytes| bytes.1.to_string()) }, rates,
                });
                previous = Some((now, totals));
                let sample = state.sample.read().clone().expect("sample published above");
                state.observation.telemetry.sample(&sample).await;
                state.observation.events.publish("runtime.updated", serde_json::json!({}), None);
            }
        }
    }
}

struct NativeConsumer(Arc<ConnectionTracker>);
impl Drop for NativeConsumer {
    fn drop(&mut self) {
        self.0.disable_native();
    }
}

/// Owns HTTP connections through bounded grace, then joins admitted credential work.
pub struct NativeServer {
    stop: watch::Sender<bool>,
    supervisor: JoinHandle<()>,
}

impl NativeServer {
    pub fn start(listener: TcpListener, state: Arc<NativeState>) -> Self {
        let (stop, receiver) = watch::channel(false);
        state.tracker.enable_native();
        let consumer = NativeConsumer(Arc::clone(&state.tracker));
        let supervisor = tokio::spawn(supervise(listener, state, receiver, consumer));
        Self { stop, supervisor }
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        if self.supervisor.await.is_err() {
            tracing::error!(message = "native HTTP supervisor failed");
        }
    }
}
struct NativeIo {
    stream: tokio::net::TcpStream,
    idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_pending: bool,
}

impl NativeIo {
    fn new(stream: tokio::net::TcpStream) -> Self {
        Self {
            stream,
            idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_pending: false,
        }
    }

    fn progress(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(30));
    }

    fn pending_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;
        if !self.write_pending {
            self.write_pending = true;
            self.write_idle
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(30));
        }
        if self.write_idle.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl tokio::io::AsyncRead for NativeIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.progress();
        }
        if result.is_pending() && self.idle.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        result
    }
}

impl tokio::io::AsyncWrite for NativeIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.stream).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result
            && n > 0
        {
            self.progress();
            self.write_pending = false;
        }
        if result.is_pending() {
            self.pending_write(cx)
        } else {
            result
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn supervise(
    listener: TcpListener,
    state: Arc<NativeState>,
    mut stop: watch::Receiver<bool>,
    _consumer: NativeConsumer,
) {
    let router = router(Arc::clone(&state));
    let observation = Arc::clone(&state.observation);
    let (sampler_stop, sampler_receiver) = watch::channel(false);
    let (connections_stop, connection_receiver) = watch::channel(false);
    let (probes_stop, probes_receiver) = watch::channel(false);
    let mut probes = observation
        .probes
        .start(Arc::clone(&state), probes_receiver);
    let mut probes_running = true;
    let (schedule_stop, schedule_receiver) = watch::channel(false);
    let mut schedule = tokio::spawn(super::geodata::schedule(
        Arc::clone(&state),
        schedule_receiver,
    ));
    let mut schedule_running = true;
    let mut sampler = tokio::spawn(sample_traffic(Arc::clone(&state), sampler_receiver));
    let mut sampler_running = true;
    let mut children = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = &mut probes => {
                probes_running = false;
                tracing::error!(message = "native probe supervisor stopped unexpectedly");
                break;
            }
            _ = &mut sampler => {
                sampler_running = false;
                tracing::error!(message = "native HTTP sampler stopped unexpectedly");
                break;
            }
            _ = &mut schedule => {
                schedule_running = false;
                tracing::error!(message = "native geodata schedule stopped unexpectedly");
                break;
            }
            child = children.join_next(), if !children.is_empty() => {
                if child.is_some_and(|result| result.is_err()) {
                    tracing::error!(message = "native HTTP connection task failed");
                    break;
                }
            }
            accepted = listener.accept(), if children.len() < 64 => {
                let Ok((stream, peer)) = accepted else {
                    tracing::error!(message = "native HTTP listener failed");
                    break;
                };
                let peer = Peer(canonical_ip(peer.ip()));
                let service = TowerToHyperService::new(
                    tower::Layer::layer(&Extension(peer), router.clone()),
                );
                let mut stop = connection_receiver.clone();
                children.spawn(async move {
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_headers(100).max_buf_size(32768);
                    let connection = builder.serve_connection(TokioIo::new(NativeIo::new(stream)), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        result = &mut connection => { let _ = result; }
                        _ = stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    if let Some(auth) = &state.auth {
        auth.close();
    }
    let _ = probes_stop.send(true);
    if probes_running {
        let _ = probes.await;
    }
    observation.settings.shutdown(&observation);
    observation.logs.shutdown();
    observation.events.shutdown();
    let _ = sampler_stop.send(true);
    if sampler_running {
        let _ = sampler.await;
    }
    let _ = schedule_stop.send(true);
    if schedule_running {
        let _ = schedule.await;
    }
    let _ = connections_stop.send(true);
    if tokio::time::timeout(Duration::from_secs(5), async {
        while children.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        children.abort_all();
        while children.join_next().await.is_some() {}
    }
    if let Some(auth) = &state.auth {
        auth.shutdown().await;
    }
}
