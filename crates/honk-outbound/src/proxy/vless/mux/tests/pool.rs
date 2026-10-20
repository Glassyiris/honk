use super::*;
use crate::session::SpeculativeCheckout;

async fn serve_idle_h2mux(wire: tokio::io::DuplexStream) -> usize {
    let io = server_carrier(wire, false).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut streams = Vec::new();
    while let Some(stream) = connection.accept().await {
        streams.push(stream.unwrap());
    }
    streams.len()
}

#[tokio::test]
async fn saturated_carrier_opens_the_second_pool_slot() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (first_client, first_server) = tokio::io::duplex(1 << 20);
    let first_server = tokio::spawn(serve_idle_h2mux(first_server));
    let first = connect(Box::new(first_client), false).await.unwrap();
    pool.insert(&first);
    let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
        .map(|_| first.try_reserve().unwrap())
        .collect();
    assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);

    let (second_client, second_server) = tokio::io::duplex(1 << 20);
    let second_server = tokio::spawn(serve_idle_h2mux(second_server));
    let second = pool
        .offer(move || async move { connect(Box::new(second_client), false).await })
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(pool.metrics().sessions, 2);

    drop(permits);
    pool.shutdown();
    assert_eq!(first_server.await.unwrap(), 0);
    assert_eq!(second_server.await.unwrap(), 0);
}

#[tokio::test]
async fn carrier_death_wakes_full_pool_waiters_with_child_permits_held() {
    enum Publication {
        Ordinary,
        Detached,
        Inserted,
    }
    for publication in [
        Publication::Ordinary,
        Publication::Detached,
        Publication::Inserted,
    ] {
        let pool = Arc::new(SessionPool::new(session_pool_config()));
        let (first_client, first_server) = tokio::io::duplex(1 << 20);
        let first_server = tokio::spawn(serve_idle_h2mux(first_server));
        let mut permits = Vec::new();
        let first = match publication {
            Publication::Ordinary => pool
                .offer(move || async move { connect(Box::new(first_client), false).await })
                .await
                .unwrap(),
            Publication::Detached => {
                let SpeculativeCheckout::Detached(mut reservation) =
                    pool.checkout_speculative().await.unwrap()
                else {
                    panic!("empty pool must reserve a detached dial");
                };
                let session = connect(Box::new(first_client), false).await.unwrap();
                permits.push(reservation.attach(&session).unwrap());
                reservation.commit().unwrap()
            }
            Publication::Inserted => {
                let session = connect(Box::new(first_client), false).await.unwrap();
                pool.insert(&session);
                session
            }
        };
        permits
            .extend((permits.len()..MAX_STREAMS_PER_SESSION).map(|_| first.try_reserve().unwrap()));
        let (second_client, second_server) = tokio::io::duplex(1 << 20);
        let second_server = tokio::spawn(serve_idle_h2mux(second_server));
        let second = pool
            .offer(move || async move { connect(Box::new(second_client), false).await })
            .await
            .unwrap();
        permits.extend((0..MAX_STREAMS_PER_SESSION).map(|_| second.try_reserve().unwrap()));

        let (replacement_client, replacement_server) = tokio::io::duplex(1 << 20);
        let replacement_server = tokio::spawn(serve_idle_h2mux(replacement_server));
        let mut normal = std::pin::pin!(
            pool.offer(move || async move { connect(Box::new(replacement_client), false).await })
        );
        let mut speculative = std::pin::pin!(pool.checkout_speculative());
        assert!(futures_util::poll!(normal.as_mut()).is_pending());
        assert!(futures_util::poll!(speculative.as_mut()).is_pending());

        first_server.abort();
        let _ = first_server.await;
        let SpeculativeCheckout::Detached(reservation) =
            tokio::time::timeout(std::time::Duration::from_secs(1), speculative)
                .await
                .expect("carrier death stranded the speculative checkout")
                .unwrap()
        else {
            panic!("the surviving carrier is still full");
        };
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), normal)
            .await
            .expect("carrier death stranded the replacement dial")
            .unwrap();
        assert!(first.is_closed());
        assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);
        assert_eq!(second.active_streams(), MAX_STREAMS_PER_SESSION);
        assert_eq!(second.state(), SessionState::Active);
        assert!(!Arc::ptr_eq(&replacement, &first));
        assert!(!Arc::ptr_eq(&replacement, &second));

        drop(reservation);
        pool.shutdown();
        drop(permits);
        second_server.await.unwrap();
        replacement_server.await.unwrap();
    }
}

async fn prepare_detached(
    pool: &Arc<VlessMuxPool>,
) -> (
    crate::proxy::PreparedUdpTransport,
    Arc<VlessMuxSession>,
    tokio::task::JoinHandle<usize>,
) {
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_idle_h2mux(server));
    let session = connect(Box::new(client), false).await.unwrap();
    let permit = reservation.attach(&session).unwrap();
    let transport = Arc::clone(&session)
        .open_packet(permit, "8.8.8.8:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("detached UDP stream must open"));
    let transport: Arc<dyn PacketTransport> = transport;
    (
        crate::proxy::PreparedUdpTransport::new(async move {
            reservation.commit()?;
            Ok(transport)
        }),
        session,
        server,
    )
}

#[tokio::test]
async fn detached_session_publishes_only_on_commit() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (loser, loser_session, loser_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    drop(loser);
    assert!(loser_session.is_closed());
    assert!(loser_server.await.unwrap() <= 1);

    let (winner, winner_session, winner_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    let transport = winner.commit().await.unwrap();
    assert_eq!(pool.live_session_count(), 1);
    assert!(!winner_session.is_closed());
    drop(transport);
    pool.shutdown();
    assert!(winner_session.is_closed());
    assert!(winner_server.await.unwrap() <= 1);
}
