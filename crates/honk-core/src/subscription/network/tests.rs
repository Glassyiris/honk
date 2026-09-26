use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_request(socket: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
}

fn subscription(listener: &TcpListener) -> Subscription {
    Subscription {
        url: format!("http://{}", listener.local_addr().unwrap()),
        ..Default::default()
    }
}

async fn peer_eof(socket: &mut TcpStream) {
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "pause acknowledgement requires actual socket closure, not only dropping the request future"
    );
}

#[tokio::test]
async fn completed_requests_release_sockets_and_resume_owns_a_fresh_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let network = Arc::new(SubscriptionNetwork::new().unwrap());
    network.ready().await.unwrap();
    for cycle in 0..3 {
        let sub = subscription(&listener);
        let requester = Arc::clone(&network);
        let fetch = tokio::spawn(async move { requester.fetch(&sub).await });
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
            .await
            .unwrap();
        assert_eq!(fetch.await.unwrap().unwrap(), b"body");
        network.pause().await.unwrap();
        peer_eof(&mut socket).await;
        assert!(network.fetch(&subscription(&listener)).await.is_err());
        if cycle < 2 {
            network.resume().await.unwrap();
        }
    }
}

#[tokio::test]
async fn pause_cancels_incomplete_response_and_backpressured_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let network = Arc::new(SubscriptionNetwork::new().unwrap());
    network.ready().await.unwrap();
    let mut requests = JoinSet::new();
    for _ in 0..MAX_REQUESTS * 3 {
        let requester = Arc::clone(&network);
        let sub = subscription(&listener);
        requests.spawn(async move { requester.fetch(&sub).await });
    }
    let mut sockets = Vec::new();
    for _ in 0..MAX_REQUESTS {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            .await
            .unwrap();
        sockets.push(socket);
    }
    network.pause().await.unwrap();
    while let Some(result) = requests.join_next().await {
        assert!(result.unwrap().is_err());
    }
    for mut socket in sockets {
        let error = tokio::time::timeout(Duration::from_secs(1), socket.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "queued work must not open a socket after pause"
    );
}

#[tokio::test]
async fn network_thread_panic_cannot_be_reported_as_a_successful_pause() {
    let network =
        SubscriptionNetwork::with_client(|| panic!("injected network thread panic")).unwrap();
    assert!(network.ready().await.is_err());
    assert!(network.pause().await.is_err());
    assert!(network.pause().await.is_err());
    assert!(network.resume().await.is_err());
}
