use super::*;
use crate::connection_tracker::ConnectionTracker;
use crate::control::connection::TcpFlowPins;
use crate::control::janitor::BpfJanitor;
use crate::control::retirement_worker::{RetirementPort, spawn_retirement_worker};
use crate::ebpf::{FlowExpiryHint, UdpFlowOwner, mock::MockEbpfBackend};
use honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;

const OLD_TOKEN: u32 = 22;
const OLD_INCARNATION: u64 = 7;
const NEW_TOKEN: u32 = 23;
const NEW_INCARNATION: u64 = 8;

fn flow_key(client_port: u16) -> FlowKey {
    FlowKey::new(
        format!("192.0.2.10:{client_port}").parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
    )
}

fn kernel_conn(state: UdpDecisionState, token: u32, incarnation: u64) -> ConnState {
    ConnState {
        state: state as u8,
        decision_token: token,
        incarnation,
        meta: RoutingMeta {
            raw: ROUTING_META_FLAG_PUBLISHED,
        },
        ..ConnState::default()
    }
}

struct Fixture {
    backend: Arc<RwLock<Box<dyn EbpfBackend>>>,
    endpoints: Arc<UdpEndpointPool>,
    pending: PendingUdpVerdicts,
    hints: mpsc::Sender<FlowExpiryHint>,
    fatal: mpsc::UnboundedReceiver<anyhow::Error>,
    _worker: crate::control::retirement_worker::RetirementWorker,
}

impl Fixture {
    fn new() -> Self {
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        let endpoints = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let (pending, _) =
            PendingUdpVerdicts::new(Arc::clone(&backend), Arc::clone(&endpoints), stats);
        pending.open_admission();
        let port = Arc::new(RetirementPort::default());
        let (hints, receiver) = mpsc::channel(4);
        *port.hints.lock() = Some(receiver);
        let (fatal_tx, fatal) = mpsc::unbounded_channel();
        let worker = spawn_retirement_worker(
            Arc::clone(&endpoints),
            Arc::clone(&backend),
            Arc::new(ConnectionTracker::new()),
            fatal_tx,
            Arc::new(TcpFlowPins::default()),
            Arc::clone(&port),
        );
        Self {
            backend,
            endpoints,
            pending,
            hints,
            fatal,
            _worker: worker,
        }
    }

    async fn serve(
        &self,
        key: FlowKey,
        token: u32,
        incarnation: u64,
        kernel: ConnState,
    ) -> UdpInitLease {
        self.backend
            .write()
            .await
            .udp_conn_state_store(&key.tuples(), &kernel)
            .unwrap();
        match self.endpoints.reserve_owned_or_enqueue_at(
            key.client,
            key.destination,
            bytes::Bytes::from_static(b"old flow"),
            UdpFlowOwner::new(token, Some(incarnation)).unwrap(),
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            Instant::now(),
            &StatsManager::new(),
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("endpoint must initialize"),
        }
    }

    async fn wait_until_endpoint_gone(&self, key: FlowKey) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.endpoints.contains(key.client, key.destination) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("reclaimed flow's endpoint must be retired");
        assert!(
            self.backend
                .read()
                .await
                .conn_state_lookup(&key.tuples())
                .unwrap()
                .is_none()
        );
    }

    async fn stage_successor(&self, key: FlowKey) -> NfqueueIngest {
        self.backend
            .write()
            .await
            .udp_conn_state_store(
                &key.tuples(),
                &kernel_conn(UdpDecisionState::Pending, NEW_TOKEN, NEW_INCARNATION),
            )
            .unwrap();
        let sink = Arc::new(Mutex::new(Vec::new()));
        let packet = QueuedPacket {
            tuple: UdpTuple {
                client: key.client,
                destination: key.destination,
            },
            payload: bytes::Bytes::from_static(b"uplink after kernel expiry"),
            mark: honk_ebpf_common::pack_nfqueue_mark(NEW_TOKEN).unwrap(),
            priority: None,
            received_at: Instant::now(),
        };
        self.pending
            .ingest_held_wait(
                packet,
                HeldVerdict::test(1, Instant::now(), sink),
                Some(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()),
            )
            .await
    }
}

#[tokio::test]
async fn hint_reclaiming_the_kernel_flow_lets_a_staged_successor_initialize() {
    let mut fixture = Fixture::new();
    let key = flow_key(40000);
    // Aborted is expiry-eligible even on a freshly booted host.
    let _old = fixture
        .serve(
            key,
            OLD_TOKEN,
            OLD_INCARNATION,
            kernel_conn(UdpDecisionState::Aborted, OLD_TOKEN, OLD_INCARNATION),
        )
        .await;
    fixture
        .hints
        .send(FlowExpiryHint {
            key: key.tuples(),
            incarnation: OLD_INCARNATION,
        })
        .await
        .unwrap();
    fixture.wait_until_endpoint_gone(key).await;

    assert!(matches!(
        fixture.stage_successor(key).await,
        NfqueueIngest::Initialize { .. }
    ));
    assert!(fixture.fatal.try_recv().is_err());
}

#[tokio::test]
async fn janitor_reclaiming_the_kernel_flow_lets_a_staged_successor_initialize() {
    let mut fixture = Fixture::new();
    let key = flow_key(40000);
    let _old = fixture
        .serve(
            key,
            OLD_TOKEN,
            OLD_INCARNATION,
            kernel_conn(UdpDecisionState::Proxy, OLD_TOKEN, OLD_INCARNATION),
        )
        .await;
    let janitor = BpfJanitor::new(
        Arc::clone(&fixture.backend),
        Arc::new(TcpFlowPins::default()),
    )
    .with_udp_pool(Arc::clone(&fixture.endpoints));

    let (deleted, _) = janitor
        .cleanup_conn_state_for_test(UDP_CONN_STATE_TIMEOUT_NS + 1)
        .await;
    assert_eq!(deleted, 1);
    fixture.wait_until_endpoint_gone(key).await;

    assert!(matches!(
        fixture.stage_successor(key).await,
        NfqueueIngest::Initialize { .. }
    ));
    assert!(fixture.fatal.try_recv().is_err());
}

#[tokio::test]
async fn superseded_retirement_keeps_the_older_incarnations_endpoint() {
    retirement_keeps_foreign_endpoint(NEW_INCARNATION, OLD_INCARNATION).await;
}

#[tokio::test]
async fn reclaimed_flow_keeps_the_newer_incarnations_endpoint() {
    retirement_keeps_foreign_endpoint(OLD_INCARNATION, NEW_INCARNATION).await;
}

async fn retirement_keeps_foreign_endpoint(kernel_incarnation: u64, endpoint_incarnation: u64) {
    let mut fixture = Fixture::new();
    let (foreign, sentinel) = (flow_key(40000), flow_key(40001));
    let _stale = fixture
        .serve(
            foreign,
            OLD_TOKEN,
            endpoint_incarnation,
            kernel_conn(UdpDecisionState::Aborted, OLD_TOKEN, kernel_incarnation),
        )
        .await;
    let _reclaimed = fixture
        .serve(
            sentinel,
            31,
            9,
            kernel_conn(UdpDecisionState::Aborted, 31, 9),
        )
        .await;
    for (key, incarnation) in [(foreign, OLD_INCARNATION), (sentinel, 9)] {
        fixture
            .hints
            .send(FlowExpiryHint {
                key: key.tuples(),
                incarnation,
            })
            .await
            .unwrap();
    }
    // Hints settle in order, so the sentinel's retirement proves the first was handled.
    fixture.wait_until_endpoint_gone(sentinel).await;

    assert!(
        fixture
            .endpoints
            .contains(foreign.client, foreign.destination)
    );
    assert_eq!(
        fixture
            .backend
            .read()
            .await
            .conn_state_lookup(&foreign.tuples())
            .unwrap()
            .is_some(),
        kernel_incarnation != OLD_INCARNATION
    );
    assert!(fixture.fatal.try_recv().is_err());
}
