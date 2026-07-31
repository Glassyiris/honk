use super::*;

#[tokio::test]
async fn first_tcp_frame_holds_permit_until_response_is_written() {
    let upstream = Arc::new(BlockingFirstUpstream {
        first_entered: Notify::new(),
        release_first: Notify::new(),
    });
    let controller = controller_with_limit(upstream.clone(), 1);
    let original_dst: SocketAddr = "127.0.0.1:53".parse().expect("original destination");

    let (mut first_client, mut first_server) = tcp_pair().await;
    let first_controller = controller.clone();
    let first_task = tokio::spawn(async move {
        first_controller
            .handle_tcp_dns(
                &mut first_server,
                "127.0.0.1:10001".parse().expect("first client"),
                original_dst,
            )
            .await
    });
    write_tcp_query(&mut first_client, &query_with_txid("first.example", 0x1111)).await;
    upstream.first_entered.notified().await;

    let (mut second_client, mut second_server) = tcp_pair().await;
    let second_controller = controller.clone();
    let second_task = tokio::spawn(async move {
        second_controller
            .handle_tcp_dns(
                &mut second_server,
                "127.0.0.1:10002".parse().expect("second client"),
                original_dst,
            )
            .await
    });
    write_tcp_query(
        &mut second_client,
        &query_with_txid("second.example", 0x2222),
    )
    .await;
    let second_response = read_tcp_response(&mut second_client).await;

    assert_eq!(second_response[3] & 0x0f, 5);

    upstream.release_first.notify_one();
    let first_response = read_tcp_response(&mut first_client).await;
    assert_eq!(first_response[3] & 0x0f, 0);
    drop(first_client);
    drop(second_client);
    first_task.await.expect("first task").expect("first query");
    second_task
        .await
        .expect("second task")
        .expect("second query");
}

#[tokio::test]
async fn cancelled_first_tcp_frame_releases_permit() {
    let upstream = Arc::new(BlockingFirstUpstream {
        first_entered: Notify::new(),
        release_first: Notify::new(),
    });
    let controller = controller_with_limit(upstream.clone(), 1);
    let original_dst: SocketAddr = "127.0.0.1:53".parse().expect("original destination");

    let (mut first_client, mut first_server) = tcp_pair().await;
    let first_controller = controller.clone();
    let first_task = tokio::spawn(async move {
        first_controller
            .handle_tcp_dns(
                &mut first_server,
                "127.0.0.1:10003".parse().expect("first client"),
                original_dst,
            )
            .await
    });
    write_tcp_query(&mut first_client, &query_with_txid("first.example", 0x3333)).await;
    upstream.first_entered.notified().await;
    first_task.abort();
    assert!(first_task.await.expect_err("cancelled task").is_cancelled());
    drop(first_client);

    let (mut resumed_client, mut resumed_server) = tcp_pair().await;
    let resumed_controller = controller.clone();
    let resumed_task = tokio::spawn(async move {
        resumed_controller
            .handle_tcp_dns(
                &mut resumed_server,
                "127.0.0.1:10004".parse().expect("resumed client"),
                original_dst,
            )
            .await
    });
    write_tcp_query(
        &mut resumed_client,
        &query_with_txid("resumed.example", 0x4444),
    )
    .await;
    let resumed_response = read_tcp_response(&mut resumed_client).await;
    assert_eq!(resumed_response[3] & 0x0f, 0);
    drop(resumed_client);
    resumed_task
        .await
        .expect("resumed task")
        .expect("resumed query");
}

#[tokio::test]
async fn malformed_first_tcp_frame_is_not_handled() {
    use tokio::io::AsyncWriteExt;

    let (controller, _) =
        test_controller(response_with_txid("example.com", 0x5555), Duration::ZERO);
    let (mut client, mut server) = tcp_pair().await;
    let task = tokio::spawn(async move {
        controller
            .handle_tcp_dns(
                &mut server,
                "127.0.0.1:10005".parse().expect("client address"),
                "127.0.0.1:53".parse().expect("original destination"),
            )
            .await
    });
    client
        .write_all(&5u16.to_be_bytes())
        .await
        .expect("write malformed length");
    client
        .write_all(&[0u8; 5])
        .await
        .expect("write malformed query");

    assert!(!task.await.expect("task").expect("handler"));
}

#[tokio::test]
async fn tcp_connection_handles_multiple_frames() {
    let (controller, _) = test_controller(response_with_txid("example.com", 0), Duration::ZERO);
    let (mut client, mut server) = tcp_pair().await;
    let task = tokio::spawn(async move {
        controller
            .handle_tcp_dns(
                &mut server,
                "127.0.0.1:10006".parse().expect("client address"),
                "127.0.0.1:53".parse().expect("original destination"),
            )
            .await
    });

    let first = query_with_txid("example.com", 0x1111);
    write_tcp_query(&mut client, &first).await;
    assert_eq!(&read_tcp_response(&mut client).await[0..2], &first[0..2]);

    let second = query_with_txid("example.com", 0x2222);
    write_tcp_query(&mut client, &second).await;
    assert_eq!(&read_tcp_response(&mut client).await[0..2], &second[0..2]);

    drop(client);
    assert!(task.await.expect("task").expect("handler"));
}
