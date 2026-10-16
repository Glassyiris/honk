//! Lifetime authority comes from real accepted-FD adoption, never a fabricated pin.

use super::*;
use crate::control::connection::handoff::TcpFlowGuard;
use honk_ebpf_common::{
    RedirectEntry,
    conn::{TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const UP: &[u8] = b"client bytes after native metadata age";
const DOWN: &[u8] = b"accepted child bytes after native metadata age";

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    handle: &ControlPlaneHandle,
    listener: &TcpListener,
    client_ns: &OwnedFd,
    mut accepted: TcpStream,
    mut client: TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    key: TuplesKey,
    incarnation: u64,
    case: &str,
) -> anyhow::Result<()> {
    accepted.set_nodelay(true)?;
    client.set_nodelay(true)?;
    // Establish that these exact sockets exchange real application bytes before
    // age manipulation. Drain ACKs before every backdate, not a guessed sleep.
    transfer(&mut client, &mut accepted, UP).await?;
    transfer(&mut accepted, &mut client, DOWN).await?;
    quiesce(&accepted, &client).await?;
    let pins = live_pins()?;
    ensure!(
        pins.get(&incarnation, 0).is_err(),
        "unadopted child was pinned"
    );

    if matches!(
        case,
        "lifetime-pin-drop-error" | "lifetime-pin-retire-error"
    ) {
        return native_pin_error(handle, accepted, key, incarnation, case).await;
    }

    if matches!(
        case,
        "lifetime-unowned-redirect" | "lifetime-unowned-closing"
    ) {
        let closing = case == "lifetime-unowned-closing";
        if closing {
            half_close(&mut client, &mut accepted).await?;
        }
        backdate(handle, &key, closing).await?;
        // Keep the real retirement worker from reclaiming an expiry hint while
        // checking the kernel's non-deletion contract; packets still execute TC.
        let backend = handle.ebpf.read().await;
        let before = metadata(&key)?;
        if closing {
            refused(&mut accepted, &mut client, DOWN).await?;
        } else {
            refused(&mut client, &mut accepted, UP).await?;
        }
        assert_refused_metadata(&key, &before, closing)?;
        ensure!(pins.get(&incarnation, 0).is_err(), "refusal invented a pin");
        drop(backend);
        return Ok(());
    }

    let duplicate = if case == "lifetime-cancel" {
        Some(duplicate_stream(&accepted)?)
    } else {
        None
    };
    let mut flow = adopt(handle, accepted, key).await?;
    ensure!(
        pins.get(&incarnation, 0)? == 1,
        "adoption did not pin exact incarnation"
    );
    ensure!(
        handle.tcp_flow_pins.contains(&key),
        "adoption lost local tuple pin"
    );

    match case {
        "lifetime-idle" => {
            backdate(handle, &key, false).await?;
            transfer(&mut client, flow.stream_mut(), UP).await?;
            quiesce(flow.stream_mut(), &client).await?;
            backdate(handle, &key, false).await?;
            transfer(flow.stream_mut(), &mut client, DOWN).await?;
        }
        "lifetime-client-fin" => {
            half_close(&mut client, flow.stream_mut()).await?;
            backdate(handle, &key, true).await?;
            transfer(flow.stream_mut(), &mut client, DOWN).await?;
        }
        "lifetime-server-fin" => {
            half_close(flow.stream_mut(), &mut client).await?;
            backdate(handle, &key, true).await?;
            transfer(&mut client, flow.stream_mut(), UP).await?;
        }
        "lifetime-other-incarnation" => {
            half_close(&mut client, flow.stream_mut()).await?;
            let newer = supersede(handle, &key).await?;
            ensure!(newer != incarnation && pins.get(&newer, 0).is_err());
            backdate(handle, &key, true).await?;
            let backend = handle.ebpf.read().await;
            let before = metadata(&key)?;
            refused(flow.stream_mut(), &mut client, DOWN).await?;
            assert_refused_metadata(&key, &before, true)?;
            ensure!(
                pins.get(&incarnation, 0)? == 1,
                "foreign refusal removed old pin"
            );
            drop(backend);
            // Drop is exact-key cleanup even though tuple authority has moved.
            drop(flow);
            ensure!(pins.get(&incarnation, 0).is_err(), "old native pin leaked");
            ensure!(!handle.tcp_flow_pins.contains(&key), "old local pin leaked");
            return Ok(());
        }
        "lifetime-cancel" => {
            let duplicate = duplicate.context("missing duplicate accepted FD")?;
            let result = adopt(handle, duplicate, key).await;
            ensure!(
                result.is_err(),
                "same real child admitted a second native owner"
            );
            ensure!(
                pins.get(&incarnation, 0)? == 1,
                "duplicate refusal damaged original pin"
            );
            ensure!(handle.tcp_flow_pins.contains(&key));
            transfer(&mut client, flow.stream_mut(), UP).await?;
            quiesce(flow.stream_mut(), &client).await?;
            let before = metadata(&key)?;
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            let slot = sender.clone().reserve_owned().await?;
            let original_sink = handle.tcp_flow_pins.retirement_sink.lock().replace(sender);
            let mut retirement = Box::pin(flow.retire());
            tokio::select! {
                biased;
                result = &mut retirement => anyhow::bail!("retirement crossed full admission: {result}"),
                _ = tokio::task::yield_now() => {}
            }
            ensure!(
                pins.get(&incarnation, 0)? == 1,
                "pending admission released native pin"
            );
            drop(retirement);
            *handle.tcp_flow_pins.retirement_sink.lock() = original_sink;
            drop(slot);
            drop(receiver);
            // No await separates cancellation from these exact native/local checks.
            ensure!(
                pins.get(&incarnation, 0).is_err(),
                "cancelled admission leaked native pin"
            );
            ensure!(
                !handle.tcp_flow_pins.contains(&key),
                "cancelled admission leaked local refcount"
            );
            assert_authority(&key, before.0.incarnation)?;
            return Ok(());
        }
        "lifetime-new-syn" => {
            return superseding_syn(
                handle,
                listener,
                client_ns,
                flow,
                client,
                source,
                target,
                key,
                incarnation,
            )
            .await;
        }
        _ => anyhow::bail!("unknown lifetime case {case}"),
    }
    quiesce(flow.stream_mut(), &client).await?;
    ensure!(
        pins.get(&incarnation, 0)? == 1,
        "live transfer lost native owner"
    );
    assert_authority(&key, incarnation)?;
    close_and_retire(handle, flow, client, &key, incarnation).await
}

async fn adopt(
    handle: &ControlPlaneHandle,
    stream: TcpStream,
    key: TuplesKey,
) -> anyhow::Result<TcpFlowGuard> {
    let ownership = handle
        .ebpf
        .read()
        .await
        .tcp_socket_ownership(stream.as_fd())?;
    ensure!(
        matches!(ownership, TcpSocketOwnership::Kernel(_)),
        "real FD has no kernel proof"
    );
    #[cfg(feature = "native-api")]
    let observation = crate::control::connection::observation::ConnectionObservation::default();
    let (flow, handoff) = handle
        .adopt_tcp_flow(
            stream,
            key,
            ownership,
            #[cfg(feature = "native-api")]
            &observation,
        )
        .await?;
    ensure!(handoff.is_some(), "real adoption lost immutable handoff");
    Ok(flow)
}

fn live_pins() -> anyhow::Result<HashMap<aya::maps::MapData, u64, u8>> {
    Ok(HashMap::try_from(pinned_map(
        Path::new(ROOT),
        "TCP_LIVE_PINS",
    )?)?)
}

/// Keep an actually adopted guard across replacement of the real removal
/// worker. Only the exact native pin key is removed to force kernel ENOENT.
async fn native_pin_error(
    handle: &ControlPlaneHandle,
    accepted: TcpStream,
    key: TuplesKey,
    incarnation: u64,
    case: &str,
) -> anyhow::Result<()> {
    fn start(
        handle: &ControlPlaneHandle,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<anyhow::Error>,
    ) {
        let (fatal_tx, fatal) = tokio::sync::mpsc::unbounded_channel();
        let task = crate::control::spawn_udp_removal_worker(
            Arc::clone(&handle.udp_pool),
            Arc::clone(&handle.ebpf),
            Arc::clone(&handle.connection_tracker),
            fatal_tx,
            Arc::clone(&handle.tcp_flow_pins),
        );
        (task, fatal)
    }

    let (old_task, mut old_fatal) = start(handle);
    let flow = adopt(handle, accepted, key).await?;
    let mut pins = live_pins()?;
    ensure!(
        pins.get(&incarnation, 0)? == 1,
        "real adoption did not retain native pin"
    );
    // A stale guard-captured sender must not be able to deliver the later error.
    old_fatal.close();
    drop(old_fatal);
    let (current_task, mut current_fatal) = start(handle);
    tokio::time::timeout(NETNS_TEST_TIMEOUT, old_task).await??;
    {
        let _backend = handle.ebpf.write().await;
        pins.remove(&incarnation)?;
    }
    if case == "lifetime-pin-retire-error" {
        ensure!(
            !flow.retire().await,
            "native release failure was confirmed retired"
        );
    } else {
        // No queue admission occurred: this exercises TcpKernelPin::Drop, not
        // the worker's explicit release path or a manually echoed sender error.
        drop(flow);
    }
    let error = tokio::time::timeout(NETNS_TEST_TIMEOUT, current_fatal.recv())
        .await?
        .context("current removal epoch lost native pin release failure")?;
    ensure!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(libc::ENOENT))),
        "native release lost kernel ENOENT source: {error:#}"
    );
    ensure!(
        !handle.tcp_flow_pins.contains(&key),
        "failed native release leaked local owner"
    );
    ensure!(
        pins.get(&incarnation, 0).is_err(),
        "failed release recreated native pin"
    );
    // Join the actual worker so a late duplicate Drop report cannot hide behind
    // scheduling. Consumed explicit release must not retry/report again on Drop.
    let shutdown = handle.udp_pool.shutdown().await;
    handle.tcp_flow_pins.retirement_sink.lock().take();
    tokio::time::timeout(NETNS_TEST_TIMEOUT, current_task).await??;
    ensure!(
        shutdown.joined,
        "native release fixture did not drain UDP owner"
    );
    ensure!(
        current_fatal.try_recv().is_err(),
        "native release failure was reported twice"
    );
    assert_authority(&key, incarnation)?;
    Ok(())
}

fn metadata(key: &TuplesKey) -> anyhow::Result<(ConnState, RoutingHandoffEntry, RedirectEntry)> {
    let root = Path::new(ROOT);
    let flags = aya_obj::generated::BPF_F_LOCK as u64;
    let conns =
        pinned_hash_snapshot::<TuplesKey, FlowMapValue<ConnState>>(root, "CONN_STATE_MAP", flags)?;
    let handoffs = pinned_hash_snapshot::<TuplesKey, FlowMapValue<RoutingHandoffEntry>>(
        root,
        "ROUTING_HANDOFF_MAP",
        flags,
    )?;
    let redirects = pinned_hash_snapshot::<RedirectTuple, FlowMapValue<RedirectEntry>>(
        root,
        "REDIRECT_TRACK",
        flags,
    )?;
    let redirect_key = RedirectTuple::from_tuples(key);
    Ok((
        conns
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate) == super::super::support::bytes_of(key)
            })
            .context("missing conn metadata")?
            .1
            .value,
        handoffs
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate) == super::super::support::bytes_of(key)
            })
            .context("missing handoff metadata")?
            .1
            .value,
        redirects
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate)
                    == super::super::support::bytes_of(&redirect_key)
            })
            .context("missing redirect metadata")?
            .1
            .value,
    ))
}

async fn backdate(
    handle: &ControlPlaneHandle,
    key: &TuplesKey,
    closing: bool,
) -> anyhow::Result<()> {
    let _backend = handle.ebpf.write().await;
    let (mut conn, mut handoff, mut redirect) = metadata(key)?;
    let now = monotonic_ns()?;
    let old_aux = now
        .checked_sub(TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1)
        .context("kernel uptime too short to backdate actual redirect")?;
    // Preserve the real protocol state: Closing must have come from a FIN/RST.
    if closing {
        ensure!(
            conn.state == TcpState::TcpStateClosing as u8,
            "fixture never reached real Closing"
        );
        conn.last_seen_ns = now
            .checked_sub(TCP_CONN_STATE_CLOSING_TIMEOUT_NS + 1)
            .context("kernel uptime too short for Closing")?;
    } else {
        ensure!(
            conn.state == TcpState::TcpStateActive as u8,
            "idle fixture not ACTIVE"
        );
        conn.last_seen_ns = old_aux;
    }
    handoff.last_seen_ns = old_aux;
    redirect.last_seen_ns = old_aux;
    let root = Path::new(ROOT);
    let flags = 2 | aya_obj::generated::BPF_F_LOCK as u64;
    HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(pinned_map(
        root,
        "CONN_STATE_MAP",
    )?)?
    .insert(*key, FlowMapValue::new(conn), flags)?;
    HashMap::<_, TuplesKey, FlowMapValue<RoutingHandoffEntry>>::try_from(pinned_map(
        root,
        "ROUTING_HANDOFF_MAP",
    )?)?
    .insert(*key, FlowMapValue::new(handoff), flags)?;
    HashMap::<_, RedirectTuple, FlowMapValue<RedirectEntry>>::try_from(pinned_map(
        root,
        "REDIRECT_TRACK",
    )?)?
    .insert(
        RedirectTuple::from_tuples(key),
        FlowMapValue::new(redirect),
        flags,
    )?;
    Ok(())
}

async fn transfer(
    sender: &mut TcpStream,
    receiver: &mut TcpStream,
    bytes: &[u8],
) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        sender.write_all(bytes).await?;
        let mut received = vec![0; bytes.len()];
        receiver.read_exact(&mut received).await?;
        ensure!(
            received == bytes,
            "aged live owner changed application bytes"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("aged live owner blackholed application bytes")?
}

async fn refused(
    sender: &mut TcpStream,
    receiver: &mut TcpStream,
    bytes: &[u8],
) -> anyhow::Result<()> {
    sender.write_all(bytes).await?;
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_millis(350), receiver.read(&mut byte)).await;
    ensure!(
        result.is_err(),
        "aged unowned tuple delivered data/EOF instead of refusing: {result:?}"
    );
    // A real TCP segment remains unacknowledged, not merely an unpolled write.
    ensure!(
        unacked(sender)? > 0,
        "negative fixture did not leave an actual unacknowledged segment"
    );
    Ok(())
}

fn assert_authority(key: &TuplesKey, incarnation: u64) -> anyhow::Result<()> {
    let (conn, handoff, redirect) = metadata(key)?;
    ensure!(
        conn.incarnation == incarnation
            && handoff.incarnation == incarnation
            && redirect.incarnation == incarnation,
        "packet/refusal deleted or rebound authoritative metadata"
    );
    Ok(())
}

fn assert_refused_metadata(
    key: &TuplesKey,
    before: &(ConnState, RoutingHandoffEntry, RedirectEntry),
    closing: bool,
) -> anyhow::Result<()> {
    assert_authority(key, before.0.incarnation)?;
    let after = metadata(key)?;
    if closing {
        ensure!(
            after.0.last_seen_ns == before.0.last_seen_ns,
            "unowned Closing was refreshed"
        );
    } else {
        ensure!(
            after.2.last_seen_ns == before.2.last_seen_ns,
            "unowned aged redirect was refreshed"
        );
    }
    Ok(())
}

async fn half_close(sender: &mut TcpStream, receiver: &mut TcpStream) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        sender.shutdown().await?;
        let mut byte = [0];
        ensure!(
            receiver.read(&mut byte).await? == 0,
            "real FIN did not reach peer EOF"
        );
        quiesce(sender, receiver).await
    })
    .await
    .context("actual half-close did not reach peer EOF")?
}

fn unacked(stream: &TcpStream) -> anyhow::Result<u32> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&info) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&mut info as *mut libc::tcp_info).cast(),
                &mut length,
            )
        } == 0,
        "TCP_INFO: {}",
        std::io::Error::last_os_error()
    );
    Ok(info.tcpi_unacked)
}

async fn quiesce(left: &TcpStream, right: &TcpStream) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        loop {
            if unacked(left)? == 0 && unacked(right)? == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("application/FIN ACKs did not drain before backdating")?
}

fn duplicate_stream(stream: &TcpStream) -> anyhow::Result<TcpStream> {
    let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure!(
        fd >= 0,
        "duplicate accepted FD: {}",
        std::io::Error::last_os_error()
    );
    Ok(TcpStream::from_std(unsafe {
        std::net::TcpStream::from_raw_fd(fd)
    })?)
}

async fn close_and_retire(
    handle: &ControlPlaneHandle,
    mut flow: TcpFlowGuard,
    mut client: TcpStream,
    key: &TuplesKey,
    incarnation: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        client.shutdown().await?;
        let mut rest = Vec::new();
        flow.stream_mut().read_to_end(&mut rest).await?;
        ensure!(rest.is_empty(), "unexpected trailing client bytes");
        flow.stream_mut().shutdown().await?;
        client.read_to_end(&mut rest).await?;
        ensure!(rest.is_empty(), "unexpected trailing server bytes");
        ensure!(
            flow.retire().await,
            "normal worker retirement was not confirmed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("normal TCP closure/retirement did not complete")??;
    ensure!(
        live_pins()?.get(&incarnation, 0).is_err(),
        "normal closure leaked native pin"
    );
    ensure!(
        !handle.tcp_flow_pins.contains(key),
        "normal closure leaked local tuple pin"
    );
    let backend = handle.ebpf.read().await;
    ensure!(
        backend.tcp_conn_state_lookup(key)?.is_none(),
        "normal retirement retained conn"
    );
    ensure!(
        backend.routing_handoff_lookup(key)?.is_none(),
        "normal retirement retained handoff"
    );
    ensure!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
            .is_none(),
        "normal retirement retained redirect"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn superseding_syn(
    handle: &ControlPlaneHandle,
    listener: &TcpListener,
    client_ns: &OwnedFd,
    old: TcpFlowGuard,
    client: TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    key: TuplesKey,
    old_incarnation: u64,
) -> anyhow::Result<()> {
    // A real RST frees the client's tuple without waiting for TIME_WAIT, while
    // the accepted old FD and its native guard remain alive until exact release.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of_val(&linger) as _,
            )
        } == 0,
        "set client RST close"
    );
    drop(client);
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        while metadata(&key)?.0.state != TcpState::TcpStateClosing as u8 {
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("real old-client RST did not reach TC")??;
    let socket = in_test_netns(client_ns, || -> anyhow::Result<_> {
        let socket = if source.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(source)?;
        Ok(socket)
    })?;
    let mut client = tokio::time::timeout(NETNS_TEST_TIMEOUT, socket.connect(target)).await??;
    let (mut accepted, peer) =
        tokio::time::timeout(NETNS_TEST_TIMEOUT, listener.accept()).await??;
    ensure!(
        peer == source && accepted.local_addr()? == target,
        "superseding SYN changed tuple"
    );
    client.set_nodelay(true)?;
    accepted.set_nodelay(true)?;
    let newer = metadata(&key)?.0.incarnation;
    ensure!(
        newer != 0 && newer != old_incarnation,
        "ordinary SYN reused old incarnation"
    );
    let pins = live_pins()?;
    ensure!(
        pins.get(&old_incarnation, 0)? == 1 && pins.get(&newer, 0).is_err(),
        "new SYN inherited old pin"
    );
    transfer(&mut client, &mut accepted, UP).await?;
    quiesce(&accepted, &client).await?;
    backdate(handle, &key, false).await?;
    {
        let _backend = handle.ebpf.read().await;
        let before = metadata(&key)?;
        refused(&mut client, &mut accepted, UP).await?;
        assert_refused_metadata(&key, &before, false)?;
    }
    let mut new = adopt(handle, accepted, key).await?;
    ensure!(
        pins.get(&old_incarnation, 0)? == 1 && pins.get(&newer, 0)? == 1,
        "independent child adoption did not retain both incarnations"
    );
    // The refused segment must now arrive on retransmission using the new
    // child's own pin; do not rewrite timestamps or replay application bytes.
    let mut received = vec![0; UP.len()];
    tokio::time::timeout(
        NETNS_TEST_TIMEOUT,
        new.stream_mut().read_exact(&mut received),
    )
    .await??;
    ensure!(
        received == UP,
        "new native owner failed to resume refused real TCP bytes"
    );
    ensure!(old.retire().await, "superseded old owner retirement failed");
    ensure!(
        pins.get(&old_incarnation, 0).is_err() && pins.get(&newer, 0)? == 1,
        "old retirement removed/leaked an incarnation pin"
    );
    ensure!(
        handle.tcp_flow_pins.contains(&key),
        "old retirement removed newer tuple-local owner"
    );
    assert_authority(&key, newer)?;
    quiesce(new.stream_mut(), &client).await?;
    backdate(handle, &key, false).await?;
    transfer(new.stream_mut(), &mut client, DOWN).await?;
    close_and_retire(handle, new, client, &key, newer).await
}
