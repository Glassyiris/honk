use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn authorized(id: uuid::Uuid, revision: u64, url: String) -> AuthorizedSubscription {
    AuthorizedSubscription {
        subscription: Subscription {
            id,
            name: "provider".into(),
            url,
            download_detour: "direct".into(),
            update_interval: 0,
            ..Default::default()
        },
        revision,
    }
}

fn state() -> SupervisorState {
    SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), None)
}

#[tokio::test]
async fn shutdown_joins_pending_fetch_socket_instead_of_detaching_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let subscription = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut state = state();
    state.reconcile(vec![subscription]);
    state.start_pending(MAX_ACTIVE_FETCHES);
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    state.shutdown().await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(state.owned_task_count(), 0);
}

#[tokio::test]
async fn replacement_during_fetch_keeps_original_revision_until_publication_fence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let id = uuid::Uuid::new_v4();
    let original = authorized(id, 1, format!("http://{}", listener.local_addr().unwrap()));
    let (commands, mut receiver) = mpsc::channel(4);
    let mut state = state();
    state.reconcile(vec![original]);
    state.start_pending(MAX_ACTIVE_FETCHES);
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    state.reconcile(vec![authorized(
        id,
        2,
        "http://127.0.0.1:9/replaced".into(),
    )]);
    let body = "socks5://127.0.0.1:1080#fetched";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let completion = state.fetches.join_next().await.unwrap().unwrap();
    state.fetched(completion, &commands);
    let ControlCommand::MergeSubscription {
        revision, result, ..
    } = receiver.recv().await.unwrap()
    else {
        panic!("expected merge");
    };
    assert_eq!(
        revision, 1,
        "an old fetch must not acquire the replacement authorization"
    );
    result
        .send(SubscriptionMergeReply {
            outcome: ReloadOutcome::Rejected,
            node_count: 0,
            authorized: vec![state.providers[&id].authorized.clone()],
        })
        .unwrap();
    let (id, reply) = state.publications.join_next().await.unwrap().unwrap();
    state.finish(id, reply.map_err(|_| "publication_unavailable"));
    assert_eq!(state.flights[&id].authorized.revision, 2);
    assert!(state.observations.read()[&id].load.updated_at.is_none());
    assert!(state.observations.read()[&id].load.error.is_none());
    state.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_waits_for_admitted_merge_acknowledgement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let subscription = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let (commands, mut receiver) = mpsc::channel(4);
    let mut state = state();
    state.reconcile(vec![subscription.clone()]);
    state.start_pending(MAX_ACTIVE_FETCHES);
    let (mut socket, _) = listener.accept().await.unwrap();
    let body = "socks5://127.0.0.1:1080";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let completion = state.fetches.join_next().await.unwrap().unwrap();
    state.fetched(completion, &commands);
    let ControlCommand::MergeSubscription { result, .. } = receiver.recv().await.unwrap() else {
        panic!("expected merge");
    };
    let shutdown = tokio::spawn(async move {
        state.shutdown().await.unwrap();
        state
    });
    tokio::task::yield_now().await;
    assert!(
        !shutdown.is_finished(),
        "publication ownership must survive shutdown while commit outcome is unknown"
    );
    result
        .send(SubscriptionMergeReply {
            outcome: ReloadOutcome::Committed { generation: 2 },
            node_count: 1,
            authorized: vec![subscription.clone()],
        })
        .unwrap();
    let state = shutdown.await.unwrap();
    assert!(
        state.observations.read()[&subscription.subscription.id]
            .load
            .updated_at
            .is_some()
    );
    assert_eq!(state.owned_task_count(), 0);
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn refresh_queue_refusal_wakes_idempotent_waiters_and_shutdown_settles_accepted_jobs() {
    use crate::native_api::{
        events::EventHub,
        operations::{OperationKind, OperationStore},
        providers::RefreshOperation,
    };
    use axum::response::IntoResponse;
    let mut state = state();
    let instance = uuid::Uuid::new_v4().to_string();
    let operations = Arc::new(OperationStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let mut accepted = Vec::new();
    for index in 0..=MAX_REFRESH_QUEUE {
        let authorized = authorized(
            uuid::Uuid::new_v4(),
            index as u64 + 1,
            "http://127.0.0.1:9".into(),
        );
        state.providers.insert(
            authorized.subscription.id,
            Provider::new(authorized.clone()),
        );
        let path = format!("/api/v1/providers/{}/refresh", authorized.subscription.id);
        let reservation = operations
            .reserve(
                "control",
                "POST",
                &path,
                Some("key"),
                b"",
                OperationKind::ProviderRefresh,
            )
            .unwrap();
        let replay = operations
            .reserve(
                "control",
                "POST",
                &path,
                Some("key"),
                b"",
                OperationKind::ProviderRefresh,
            )
            .unwrap();
        state.refresh(
            authorized.subscription.clone(),
            RefreshOperation {
                display_name: authorized.subscription.name.clone(),
                display_url: authorized.subscription.url.clone(),
                display_download: None,
                reservation,
                operations: Arc::clone(&operations),
                instance: instance.clone(),
            },
        );
        if index == MAX_REFRESH_QUEUE {
            assert_eq!(
                replay
                    .admission()
                    .await
                    .unwrap_err()
                    .into_response()
                    .status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
        } else {
            accepted.push(replay.admission().await.unwrap().operation_id);
        }
    }
    state.shutdown().await.unwrap();
    for id in accepted {
        let response = operations.get(&id).unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(value["error"]["code"], "supervisor_stopped");
    }
}

#[tokio::test]
async fn pause_joins_fetches_and_resume_fetches_only_current_authorizations() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut periodic = authorized(
        uuid::Uuid::new_v4(),
        7,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    periodic.subscription.update_interval = 1;
    let startup = authorized(uuid::Uuid::new_v4(), 8, periodic.subscription.url.clone());
    let (commands, mut receiver) = mpsc::channel(4);
    let mut state = state();
    state.reconcile(vec![periodic.clone(), startup]);
    let accepted_at = SystemTime::UNIX_EPOCH + Duration::from_secs(17);
    state
        .observations
        .write()
        .get_mut(&periodic.subscription.id)
        .unwrap()
        .load = ProviderLoad {
        updated_at: Some(accepted_at),
        cached: true,
        error: Some("cache_load_failed"),
    };
    state.start_pending(MAX_ACTIVE_FETCHES);
    let mut sockets = Vec::new();
    for _ in 0..2 {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(socket.read_u8().await.unwrap());
        }
        sockets.push(socket);
    }
    state.pause_fetches("supervisor_paused").await.unwrap();
    for mut socket in sockets {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), socket.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
    let load = state.observations.read()[&periodic.subscription.id].load;
    assert_eq!(load.updated_at, Some(accepted_at));
    assert!(load.cached);
    assert_eq!(load.error, Some("cache_load_failed"));
    state.reconcile(vec![periodic.clone()]);
    state.start_pending(MAX_ACTIVE_FETCHES);
    assert!(receiver.try_recv().is_err());
    assert!(state.flights.is_empty());
    state.resume().await.unwrap();
    state.start_pending(MAX_ACTIVE_FETCHES);
    let (mut socket, _) = listener.accept().await.unwrap();
    let body = "socks5://127.0.0.1:1081#fresh";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let completion = state.fetches.join_next().await.unwrap().unwrap();
    state.fetched(completion, &commands);
    let ControlCommand::MergeSubscription {
        subscription_id,
        revision,
        nodes,
        result,
        ..
    } = receiver.recv().await.unwrap()
    else {
        panic!("expected merge");
    };
    assert_eq!(subscription_id, periodic.subscription.id);
    assert_eq!(revision, 7);
    assert_eq!(nodes[0].name, "fresh");
    result
        .send(SubscriptionMergeReply {
            outcome: ReloadOutcome::Rejected,
            node_count: 0,
            authorized: vec![periodic],
        })
        .unwrap();
    state.shutdown().await.unwrap();
    assert_eq!(state.owned_task_count(), 0);
}

#[test]
fn pause_joins_queued_blocking_persistence() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let directory = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::in_dir(directory.path());
        let subscription = authorized(uuid::Uuid::new_v4(), 1, "http://127.0.0.1:9".into());
        let mut state = state();
        state.reconcile(vec![subscription.clone()]);
        state.pending.clear();
        let (entered, entered_rx) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            released.recv().unwrap();
        });
        entered_rx.await.unwrap();
        let (writing, writing_rx) = oneshot::channel();
        let cache = store.clone();
        let fetched = subscription.clone();
        let task = state.fetches.spawn(async move {
            let mut diagnostics = Vec::new();
            {
                let persist = SubscriptionManager::persist_content(
                    &fetched.subscription,
                    Some(&cache),
                    "socks5://127.0.0.1:1080#old".into(),
                    &mut diagnostics,
                    0,
                );
                tokio::pin!(persist);
                std::future::poll_fn(|cx| {
                    assert!(persist.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                writing.send(()).unwrap();
                persist.await;
            }
            FetchCompletion {
                authorized: fetched,
                result: Some(Ok(Vec::new())),
                diagnostics,
            }
        });
        state
            .fetch_ids
            .insert(task.id(), subscription.subscription.id);
        writing_rx.await.unwrap();
        let pause = state.pause_fetches("supervisor_paused");
        tokio::pin!(pause);
        std::future::poll_fn(|cx| {
            assert!(
                pause.as_mut().poll(cx).is_pending(),
                "pause must retain the blocked cache writer"
            );
            std::task::Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        pause.await.unwrap();
        blocker.await.unwrap();
        let cached = store
            .load_nodes(&subscription.subscription)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached[0].name, "old");
    });
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn finish_pause_waits_for_late_enqueue_and_retains_removed_provider_commit() {
    use crate::native_api::{
        events::EventHub,
        operations::{OperationKind, OperationStore},
        providers::RefreshOperation,
    };
    let (merge_tx, mut merge_rx) = mpsc::channel(1);
    let held_capacity = merge_tx.clone().reserve_owned().await.unwrap();
    let mut state = state();
    let subscription = authorized(uuid::Uuid::new_v4(), 4, "http://127.0.0.1:9".into());
    state.reconcile(vec![subscription.clone()]);
    state.pending.clear();
    state.flights.clear();
    let instance = uuid::Uuid::new_v4().to_string();
    let operations = Arc::new(OperationStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let path = format!("/api/v1/providers/{}/refresh", subscription.subscription.id);
    let reservation = operations
        .reserve(
            "control",
            "POST",
            &path,
            Some("retained"),
            b"",
            OperationKind::ProviderRefresh,
        )
        .unwrap();
    let operation_id = reservation.id.clone();
    state.refresh(
        subscription.subscription.clone(),
        RefreshOperation {
            display_name: subscription.subscription.name.clone(),
            display_url: subscription.subscription.url.clone(),
            display_download: None,
            reservation,
            operations: Arc::clone(&operations),
            instance,
        },
    );
    state.pending.clear();
    operations.running(&operation_id);
    state.fetched(
        FetchCompletion {
            authorized: subscription.clone(),
            result: Some(Ok(Vec::new())),
            diagnostics: Vec::new(),
        },
        &merge_tx,
    );
    let (command_tx, commands) = mpsc::channel(4);
    let handle = SubscriptionSupervisorHandle {
        command_tx,
        observations: Arc::clone(&state.observations),
        caches: false,
    };
    let worker = tokio::spawn(state.run(commands, merge_tx));
    handle.begin_pause().await.unwrap();
    assert!(
        merge_rx.try_recv().is_err(),
        "the initial receive snapshot is empty"
    );
    let finish = handle.finish_pause();
    tokio::pin!(finish);
    std::future::poll_fn(|cx| {
        assert!(finish.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    handle.reconcile(Vec::new()).await.unwrap();
    assert!(
        handle.resume().await.is_err(),
        "unacknowledged publications prevent reopening"
    );
    drop(held_capacity);
    let ControlCommand::MergeSubscription {
        revision, result, ..
    } = merge_rx.recv().await.unwrap()
    else {
        panic!("expected merge");
    };
    assert_eq!(revision, 4);
    std::future::poll_fn(|cx| {
        assert!(finish.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    result
        .send(SubscriptionMergeReply {
            outcome: ReloadOutcome::Committed { generation: 9 },
            node_count: 3,
            authorized: vec![subscription],
        })
        .unwrap();
    finish.await.unwrap();
    let replay = operations
        .reserve(
            "control",
            "POST",
            &path,
            Some("retained"),
            b"",
            OperationKind::ProviderRefresh,
        )
        .unwrap();
    assert!(!replay.fresh);
    assert_eq!(replay.admission().await.unwrap().operation_id, operation_id);
    let response = operations.get(&operation_id).unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "succeeded");
    handle.resume().await.unwrap();
    handle.begin_pause().await.unwrap();
    handle.finish_pause().await.unwrap();
    let (done, wait) = oneshot::channel();
    handle
        .command_tx
        .send(SupervisorCommand::Shutdown { done })
        .await
        .unwrap();
    assert_eq!(wait.await.unwrap().unwrap(), 0);
    worker.await.unwrap();
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn pause_cancels_periodic_and_explicit_fetches_without_losing_replay() {
    use crate::native_api::{
        events::EventHub,
        operations::{OperationKind, OperationStore},
        providers::RefreshOperation,
    };
    use axum::response::IntoResponse;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut periodic = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    periodic.subscription.update_interval = 1;
    let explicit = authorized(uuid::Uuid::new_v4(), 2, periodic.subscription.url.clone());
    let queued = authorized(uuid::Uuid::new_v4(), 3, periodic.subscription.url.clone());
    let mut state = state();
    state.reconcile(vec![periodic, explicit.clone(), queued.clone()]);
    for id in [explicit.subscription.id, queued.subscription.id] {
        state.pending.retain(|pending| *pending != id);
        state.flights.remove(&id);
    }
    let instance = uuid::Uuid::new_v4().to_string();
    let operations = Arc::new(OperationStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let mut admitted = Vec::new();
    for subscription in [&explicit, &queued] {
        let path = format!("/api/v1/providers/{}/refresh", subscription.subscription.id);
        let reservation = operations
            .reserve(
                "control",
                "POST",
                &path,
                Some("keep"),
                b"",
                OperationKind::ProviderRefresh,
            )
            .unwrap();
        let id = reservation.id.clone();
        state.refresh(
            subscription.subscription.clone(),
            RefreshOperation {
                display_name: subscription.subscription.name.clone(),
                display_url: subscription.subscription.url.clone(),
                display_download: None,
                reservation,
                operations: Arc::clone(&operations),
                instance: instance.clone(),
            },
        );
        admitted.push((path, id));
        if subscription.subscription.id == explicit.subscription.id {
            state.start_pending(MAX_ACTIVE_FETCHES);
        }
    }
    let mut sockets = Vec::new();
    for _ in 0..2 {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(socket.read_u8().await.unwrap());
        }
        sockets.push(socket);
    }
    state.pause_fetches("supervisor_paused").await.unwrap();
    for mut socket in sockets {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), socket.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
    for (path, id) in admitted {
        let replay = operations
            .reserve(
                "control",
                "POST",
                &path,
                Some("keep"),
                b"",
                OperationKind::ProviderRefresh,
            )
            .unwrap();
        assert!(!replay.fresh);
        assert_eq!(replay.admission().await.unwrap().operation_id, id);
        let response = operations.get(&id).unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(value["error"]["code"], "supervisor_paused");
    }
    let path = format!("/api/v1/providers/{}/refresh", explicit.subscription.id);
    let reservation = operations
        .reserve(
            "control",
            "POST",
            &path,
            Some("paused"),
            b"",
            OperationKind::ProviderRefresh,
        )
        .unwrap();
    let admission = reservation.admission();
    state.refresh(
        explicit.subscription.clone(),
        RefreshOperation {
            display_name: explicit.subscription.name.clone(),
            display_url: explicit.subscription.url.clone(),
            display_download: None,
            reservation,
            operations,
            instance,
        },
    );
    assert_eq!(
        admission.await.unwrap_err().into_response().status(),
        axum::http::StatusCode::CONFLICT
    );
    assert_eq!(state.owned_task_count(), 0);
    state.shutdown().await.unwrap();
}

#[tokio::test]
async fn pause_preserves_a_completed_http_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let subscription = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let id = subscription.subscription.id;
    let mut state = state();
    state.reconcile(vec![subscription.clone()]);
    state.pending.clear();
    let fetch = fetch_once(
        Arc::clone(&state.manager),
        None,
        subscription,
        state.stop.subscribe(),
    );
    let (completed, completion) = oneshot::channel();
    let task = state.fetches.spawn(async move {
        let result = fetch.await;
        completed.send(()).unwrap();
        result
    });
    state.fetch_ids.insert(task.id(), id);
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    socket
        .write_all(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    completion.await.unwrap();
    state.pause_fetches("supervisor_paused").await.unwrap();
    assert_eq!(
        state.observations.read()[&id].load.error,
        Some("fetch_failed")
    );
    state.shutdown().await.unwrap();
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn native_startup_backpressures_all_subscriptions_without_dropping_them() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let count = MAX_ACTIVE_FETCHES * 5;
    let mut config = Config::default();
    config.experimental.native_api.enabled = true;
    config.subscriptions = (0..count)
        .map(|index| authorized(uuid::Uuid::new_v4(), 1, format!("{url}/{index}")).subscription)
        .collect();
    let prepare = tokio::spawn(async move {
        let supervisor = SubscriptionSupervisor::prepare(&mut config, None, Vec::new())
            .await
            .unwrap();
        (config, supervisor)
    });
    let mut initial = Vec::new();
    for _ in 0..MAX_ACTIVE_FETCHES {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(socket.read_u8().await.unwrap());
        }
        initial.push(socket);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "startup must not bypass the four-fetch ownership bound"
    );
    for index in 0..count {
        let mut socket = if let Some(socket) = initial.pop() {
            socket
        } else {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(socket.read_u8().await.unwrap());
            }
            socket
        };
        let body = format!("socks5://127.0.0.1:{}#startup-{index}", 10000 + index);
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }
    let (config, supervisor) = prepare.await.unwrap();
    let fetched: HashSet<_> = config
        .nodes
        .iter()
        .filter_map(|node| node.subscription_id)
        .collect();
    let expected: HashSet<_> = config
        .subscriptions
        .iter()
        .map(|subscription| subscription.id)
        .collect();
    assert_eq!(
        fetched, expected,
        "backpressure must preserve every valid startup provider"
    );
    assert_eq!(supervisor.shutdown().await.unwrap(), 0);
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn native_supervisor_fetch_leaves_no_keepalive_before_reopening() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let mut config = Config::default();
    config.experimental.native_api.enabled = true;
    config.subscriptions.push(provider.subscription);
    let prepare = tokio::spawn(async move {
        SubscriptionSupervisor::prepare(&mut config, None, Vec::new())
            .await
            .unwrap()
    });
    let (mut keepalive, _) = listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(keepalive.read_u8().await.unwrap());
    }
    let body = "socks5://127.0.0.1:1080#cached";
    keepalive
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut supervisor = prepare.await.unwrap();
    let (merges, mut publications) = mpsc::channel(4);
    supervisor.start(merges);
    let handle = supervisor.handle();
    // The marked client owns one connection per request, so no keepalive
    // outlives the completed fetch that a pause would have to close.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), keepalive.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    handle.begin_pause().await.unwrap();
    handle.finish_pause().await.unwrap();
    handle.resume().await.unwrap();
    let (mut active, _) = listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(active.read_u8().await.unwrap());
    }
    active
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
        .await
        .unwrap();
    handle.begin_pause().await.unwrap();
    handle.finish_pause().await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), active.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
    ));
    assert!(
        publications.try_recv().is_err(),
        "cancelled bodies must never become runtime publications"
    );
    assert_eq!(supervisor.shutdown().await.unwrap(), 0);
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn deferred_provider_survives_pause_and_same_revision_reconcile_until_replaced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut provider = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );
    provider.subscription.update_interval = 1;
    let mut supervisor = SubscriptionSupervisor::prepare(&mut Config::default(), None, Vec::new())
        .await
        .unwrap();
    let (merge_tx, mut merges) = mpsc::channel(4);
    supervisor.start(merge_tx);
    let handle = supervisor.handle();
    handle
        .reconcile_managed(vec![provider.clone()], provider.subscription.id)
        .await
        .unwrap();
    handle.begin_pause().await.unwrap();
    handle.finish_pause().await.unwrap();
    handle.reconcile(vec![provider.clone()]).await.unwrap();
    handle.resume().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1100), listener.accept())
            .await
            .is_err(),
        "neither resume nor periodic ticks may activate a deferred provider"
    );
    let deferred = handle.deferred_subscriptions().await.unwrap();
    assert_eq!(deferred.len(), 1);
    assert!(same_worker_spec(&deferred[0], &provider.subscription));

    provider.revision += 1;
    provider.subscription.name = "replacement-with-same-fetch-identity".into();
    handle.reconcile(vec![provider.clone()]).await.unwrap();
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let body = "socks5://127.0.0.1:11088#replacement";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let ControlCommand::MergeSubscription {
        revision,
        nodes,
        result,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), merges.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("expected replacement publication");
    };
    assert_eq!(revision, 2);
    assert_eq!(nodes[0].name, "replacement");
    assert!(handle.deferred_subscriptions().await.unwrap().is_empty());
    result
        .send(SubscriptionMergeReply {
            outcome: ReloadOutcome::Committed { generation: 2 },
            node_count: nodes.len(),
            authorized: vec![provider.clone()],
        })
        .unwrap();
    supervisor.shutdown().await.unwrap();
    assert!(
        handle
            .observation(&provider.subscription)
            .updated_at
            .is_some()
    );
}
