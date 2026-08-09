use super::*;

#[tokio::test]
async fn udp_overload_is_refused_while_permit_owner_is_in_flight() {
    let upstream = Arc::new(BlockingFirstUpstream {
        first_entered: Notify::new(),
        release_first: Notify::new(),
    });
    let controller = controller_with_limit(upstream.clone(), 1);
    let first_client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first client");
    let second_client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind second client");
    let original_dst: SocketAddr = "127.0.0.1:53".parse().expect("original destination");
    // The reply path builds an IP_TRANSPARENT anyfrom socket bound to the
    // original destination — unprivileged runners (CI) cannot create it,
    // and the handler swallows the failure, so the REFUSED would never
    // arrive. Exercise the full path only where it can actually work.
    if crate::control::sockets::new_udp_reply_socket(original_dst).is_err() {
        eprintln!("skipping: transparent UDP reply socket needs privileges");
        return;
    }

    let first_query = query_with_txid("first.example", 0x1111);
    let first_task = {
        let controller = controller.clone();
        let client_addr = first_client.local_addr().expect("first client address");
        tokio::spawn(async move {
            controller
                .handle_udp_dns(&first_query, client_addr, original_dst)
                .await
        })
    };
    upstream.first_entered.notified().await;

    let second_query = query_with_txid("second.example", 0x2222);
    assert!(
        controller
            .handle_udp_dns(
                &second_query,
                second_client.local_addr().expect("second client address"),
                original_dst,
            )
            .await
            .expect("second handler")
    );
    let mut response = [0u8; 512];
    let received = tokio::time::timeout(
        Duration::from_secs(5),
        second_client.recv_from(&mut response),
    )
    .await
    .expect("overload response timeout")
    .expect("overload response")
    .0;
    assert_eq!(response[3] & 0x0f, 5);
    assert_eq!(&response[..2], &second_query[..2]);
    assert!(received >= 12);

    upstream.release_first.notify_one();
    let first_received = tokio::time::timeout(
        Duration::from_secs(5),
        first_client.recv_from(&mut response),
    )
    .await
    .expect("first response timeout")
    .expect("first response")
    .0;
    assert!(first_received >= 12);
    assert!(
        first_task
            .await
            .expect("first task")
            .expect("first handler")
    );
}
