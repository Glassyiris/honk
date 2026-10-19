use super::*;
use crate::control::connection::build_tuples_key;
use crate::ebpf::UdpFlowOwner;
use honk_ebpf_common::TuplesKey;

const CLIENT: &str = "192.0.2.10:40000";
const DESTINATION: &str = "198.51.100.20:443";

fn flow(client: SocketAddr, destination: SocketAddr, proto: u8) -> TuplesKey {
    build_tuples_key(
        destination.ip(),
        destination.port(),
        client.ip(),
        client.port(),
        proto,
    )
}

async fn reserve(
    pool: &Arc<UdpEndpointPool>,
    owner: UdpFlowOwner,
    ready: bool,
) -> (UdpInitLease, u64) {
    let (client, destination): (SocketAddr, SocketAddr) =
        (CLIENT.parse().unwrap(), DESTINATION.parse().unwrap());
    let mut lease = match pool.reserve_owned_or_enqueue_at(
        client,
        destination,
        Bytes::from_static(b"first"),
        owner,
        None,
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        Instant::now(),
        &StatsManager::new(),
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("fresh owned endpoint"),
    };
    let generation = lease.generation();
    if ready {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = "127.0.0.1:53".parse().unwrap();
        let endpoint = Arc::new(UdpEndpoint::new(
            transport(socket, relay),
            relay,
            uuid::Uuid::new_v4(),
        ));
        assert!(lease.commit_ready(endpoint));
    }
    (lease, generation)
}

#[tokio::test]
async fn reclaimed_flow_retires_only_the_endpoint_of_that_incarnation() {
    let (client, destination): (SocketAddr, SocketAddr) =
        (CLIENT.parse().unwrap(), DESTINATION.parse().unwrap());
    for ready in [false, true] {
        let pool = Arc::new(UdpEndpointPool::new());
        let (_lease, _) = reserve(&pool, UdpFlowOwner::new(22, Some(7)).unwrap(), ready).await;
        let udp = flow(client, destination, 17);

        assert!(!pool.retire_reclaimed(&udp, 6), "older incarnation");
        assert!(!pool.retire_reclaimed(&udp, 8), "newer incarnation");
        assert!(
            !pool.retire_reclaimed(&flow(client, destination, 6), 7),
            "TCP tuple with the same addresses"
        );
        let other = "192.0.2.11:40000".parse().unwrap();
        assert!(!pool.retire_reclaimed(&flow(other, destination, 17), 7));
        assert!(pool.contains(client, destination), "ready={ready}");

        assert!(pool.retire_reclaimed(&udp, 7), "ready={ready}");
        assert!(pool.is_empty(), "ready={ready}");
        assert!(!pool.retire_reclaimed(&udp, 7));
    }
}

#[tokio::test]
async fn reclamation_leaves_an_endpoint_without_a_kernel_incarnation() {
    let (client, destination): (SocketAddr, SocketAddr) =
        (CLIENT.parse().unwrap(), DESTINATION.parse().unwrap());
    let pool = Arc::new(UdpEndpointPool::new());
    let (_lease, _) = reserve(&pool, UdpFlowOwner::new(22, None).unwrap(), false).await;

    assert!(!pool.retire_reclaimed(&flow(client, destination, 17), 7));
    assert!(pool.contains(client, destination));
}
