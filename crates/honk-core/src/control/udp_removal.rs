use super::connection::handoff::{TcpFlowGuard, TcpFlowPins};
use super::udp_endpoint::{EndpointRemoval, RemovalReason};
use super::*;
use crate::ebpf::{
    FlowExpiryHint, RETIRE_BATCH_CAPACITY, RetireKind, RetireRequest, UdpDecisionCommitResult,
};

pub(in crate::control) struct TcpRetirement {
    pub(in crate::control) flow: TcpFlowGuard,
    pub(in crate::control) completion: tokio::sync::oneshot::Sender<bool>,
}

enum Retirement {
    Udp(EndpointRemoval),
    Tcp(TcpRetirement),
    Hint(FlowExpiryHint),
}

/// The worker owns admitted I/O and guards even when a completion waiter leaves.
pub(in crate::control) fn spawn_udp_removal_worker(
    udp_pool: Arc<UdpEndpointPool>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
    tcp_flow_pins: Arc<TcpFlowPins>,
) -> tokio::task::JoinHandle<()> {
    const REMOVAL_QUEUE_CAPACITY: usize = 1024;
    let (remove_tx, mut remove_rx) = mpsc::channel::<EndpointRemoval>(REMOVAL_QUEUE_CAPACITY);
    let (tcp_tx, mut tcp_rx) = mpsc::channel::<TcpRetirement>(REMOVAL_QUEUE_CAPACITY);
    udp_pool.set_remove_sink(remove_tx);
    *tcp_flow_pins.retirement_sink.lock() = Some(tcp_tx);
    #[cfg(feature = "ebpf")]
    {
        *tcp_flow_pins.kernel_pin_errors.lock() = Some(fatal_tx.clone());
    }
    tokio::spawn(async move {
        let mut exit = super::runtime::CriticalTaskExit {
            name: "flow_retirement_worker",
            fatal_tx: fatal_tx.clone(),
            expected: false,
        };
        let retained_hints = tcp_flow_pins.expiry_hints.lock().clone();
        let retained_hints = match retained_hints {
            Some(receiver) => Some(receiver),
            None => {
                let receiver = ebpf
                    .write()
                    .await
                    .take_expiry_hints()
                    .map(|receiver| Arc::new(tokio::sync::Mutex::new(receiver)));
                *tcp_flow_pins.expiry_hints.lock() = receiver.clone();
                receiver
            }
        };
        // Keep the receiver itself across epochs, not a sender that could keep
        // this worker alive after both real producer ingresses have closed.
        let mut hints = match retained_hints {
            Some(receiver) => Some(receiver.lock_owned().await),
            None => None,
        };
        let mut udp_open = true;
        let mut tcp_open = true;
        let mut hints_open = hints.is_some();
        let mut jobs = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        let mut requests = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        loop {
            if remove_rx.is_closed()
                && remove_rx.is_empty()
                && tcp_rx.is_closed()
                && tcp_rx.is_empty()
            {
                break;
            }
            let first = tokio::select! {
                biased;
                removal = remove_rx.recv(), if udp_open => match removal {
                    Some(removal) => Retirement::Udp(removal),
                    None => { udp_open = false; continue; }
                },
                retirement = tcp_rx.recv(), if tcp_open => match retirement {
                    Some(retirement) => Retirement::Tcp(retirement),
                    None => { tcp_open = false; continue; }
                },
                hint = async { hints.as_mut().unwrap().recv().await }, if hints_open => match hint {
                    Some(hint) => Retirement::Hint(hint),
                    None => {
                        hints_open = false;
                        let _ = fatal_tx.send(anyhow::anyhow!("flow expiry hint channel closed while retirement ingress was active"));
                        continue;
                    }
                },
            };
            jobs.push(first);
            while jobs.len() < RETIRE_BATCH_CAPACITY {
                let before = jobs.len();
                if let Ok(removal) = remove_rx.try_recv() {
                    jobs.push(Retirement::Udp(removal));
                }
                if jobs.len() < RETIRE_BATCH_CAPACITY
                    && let Ok(retirement) = tcp_rx.try_recv()
                {
                    jobs.push(Retirement::Tcp(retirement));
                }
                if jobs.len() < RETIRE_BATCH_CAPACITY
                    && hints_open
                    && !(remove_rx.is_closed()
                        && remove_rx.is_empty()
                        && tcp_rx.is_closed()
                        && tcp_rx.is_empty())
                {
                    match hints.as_mut().unwrap().try_recv() {
                        Ok(hint) => jobs.push(Retirement::Hint(hint)),
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            hints_open = false;
                            let _ = fatal_tx.send(anyhow::anyhow!("flow expiry hint channel closed while retirement ingress was active"));
                        }
                        Err(mpsc::error::TryRecvError::Empty) => {}
                    }
                }
                if before == jobs.len() {
                    break;
                }
            }

            let mut confirmed = [true; RETIRE_BATCH_CAPACITY];
            for (index, job) in jobs.iter().enumerate() {
                if let Retirement::Udp(removal) = job
                    && !udp_pool.wait_removal_io(removal).await
                {
                    confirmed[index] = false;
                    let _ = fatal_tx.send(anyhow::anyhow!(
                        "UDP retirement did not complete owned I/O: token={}, generation={}",
                        removal.decision_token,
                        removal.generation
                    ));
                }
            }

            let mut backend = ebpf.write().await;
            // Adoption retains its pin under backendR. Release only this batch's
            // pins under W, then examine current external owners without a gap.
            for (index, job) in jobs.iter_mut().enumerate() {
                if let Retirement::Tcp(retirement) = job
                    && let Err(error) = retirement.flow.release_pin()
                {
                    confirmed[index] = false;
                    let _ = fatal_tx.send(error.context("TCP retirement pin release failed"));
                }
            }
            let mut request_indices = [None; RETIRE_BATCH_CAPACITY];
            let hint_time = if jobs.iter().any(|job| matches!(job, Retirement::Hint(_))) {
                match super::janitor::monotonic_now_ns() {
                    Ok(now) => Some(now),
                    Err(error) => {
                        let _ =
                            fatal_tx.send(error.context("reading flow retirement expiry clock"));
                        None
                    }
                }
            } else {
                None
            };
            for (index, job) in jobs.iter().enumerate() {
                if !confirmed[index] {
                    continue;
                }
                let request = match job {
                    Retirement::Udp(removal)
                        if removal.reason == RemovalReason::UserspaceEndpointRetired =>
                    {
                        Some(RetireRequest {
                            key: connection::build_tuples_key(
                                removal.dst.ip(),
                                removal.dst.port(),
                                removal.client.ip(),
                                removal.client.port(),
                                17,
                            ),
                            kind: RetireKind::Udp {
                                token: removal.decision_token,
                                incarnation: removal.kernel_incarnation,
                                pending_only: false,
                            },
                        })
                    }
                    Retirement::Tcp(retirement)
                        if !tcp_flow_pins.contains(&retirement.flow.tuples) =>
                    {
                        Some(RetireRequest {
                            key: retirement.flow.tuples,
                            kind: RetireKind::Tcp {
                                incarnation: retirement.flow.incarnation,
                            },
                        })
                    }
                    Retirement::Hint(hint) if !tcp_flow_pins.contains(&hint.key) => {
                        hint_time.map(|now_ns| RetireRequest {
                            key: hint.key,
                            kind: RetireKind::ExpiryHint {
                                incarnation: hint.incarnation,
                                now_ns,
                            },
                        })
                    }
                    _ => None,
                };
                if let Some(request) = request {
                    request_indices[index] = Some(requests.len());
                    requests.push(request);
                }
            }
            let mut outcomes = [None; RETIRE_BATCH_CAPACITY];
            let batch_ok = if requests.is_empty() {
                true
            } else {
                let (counts, ok) =
                    match backend.retire_batch(&requests, &mut outcomes[..requests.len()]) {
                        Ok(counts) => (counts, true),
                        Err(error) => {
                            let counts = error.counts;
                            let _ = fatal_tx.send(
                                anyhow::Error::new(error).context("flow retirement batch failed"),
                            );
                            (counts, false)
                        }
                    };
                crate::ebpf::USERSPACE_CONN_STATE_DELETES
                    .fetch_add(counts.conn, std::sync::atomic::Ordering::Relaxed);
                ok
            };
            drop(backend);
            for (index, job) in jobs.drain(..).enumerate() {
                if let Some(request_index) = request_indices[index] {
                    let outcome = outcomes[request_index];
                    confirmed[index] = batch_ok
                        && matches!(
                            outcome,
                            Some(
                                UdpDecisionCommitResult::Applied
                                    | UdpDecisionCommitResult::Missing
                                    | UdpDecisionCommitResult::Superseded
                            )
                        );
                    if batch_ok
                        && !confirmed[index]
                        && (!matches!(&job, Retirement::Hint(_)) || outcome.is_none())
                    {
                        let _ = fatal_tx.send(anyhow::anyhow!(
                            "flow retirement identity mismatch or incomplete outcome: result={outcome:?}, request={:?}",
                            requests[request_index]
                        ));
                    }
                }
                match job {
                    Retirement::Udp(removal) => {
                        if confirmed[index]
                            && let Some(id) = removal.conn_id.as_deref()
                        {
                            tracker.remove(id);
                        }
                        udp_pool.finish_removal(&removal, confirmed[index]);
                    }
                    Retirement::Tcp(TcpRetirement { flow, completion }) => {
                        flow.finish_retirement(confirmed[index]);
                        let _ = completion.send(confirmed[index]);
                    }
                    Retirement::Hint(_) => {}
                }
            }
            requests.clear();
            udp_pool.flush_removal_dirty();
        }
        exit.expected_stop();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_tracker::{
        CloseCompletion, CloseOutcome, CloseRequest, CloseSignal, ConnectionEntry,
    };
    use crate::ebpf::mock::MockEbpfBackend;
    use honk_ebpf_common::conn::{ConnState, TcpState};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn cancelled_admitted_tcp_retirement_keeps_ownership_until_worker_join()
    -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (accepted, peer) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr()?)
        );
        let stream = accepted?.0;
        let mut peer = peer?;
        let client: SocketAddr = "192.0.2.1:50000".parse()?;
        let destination: SocketAddr = "203.0.113.2:443".parse()?;
        let key = connection::build_tuples_key(
            destination.ip(),
            destination.port(),
            client.ip(),
            client.port(),
            6,
        );
        let mut mock = MockEbpfBackend::new();
        mock.tcp_conn_state_store(
            &key,
            &ConnState {
                state: TcpState::TcpStateActive as u8,
                incarnation: 71,
                ..ConnState::default()
            },
        )?;
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
        let pool = Arc::new(UdpEndpointPool::new());
        let pins = Arc::new(TcpFlowPins::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let mut flow = TcpFlowGuard::new(stream, key, 71, Arc::clone(&pins), Arc::clone(&tracker));
        let signal = CloseSignal::new();
        flow.retain_close_completion(Some(CloseCompletion(Arc::clone(&signal))));
        let close = CloseRequest::Pending(signal);
        flow.track(ConnectionEntry {
            id: "admitted-cancellation".to_string(),
            source: client.to_string(),
            destination: destination.to_string(),
            proxy: "direct".to_string(),
            #[cfg(feature = "native-api")]
            routed_outbound: None,
            #[cfg(feature = "native-api")]
            native_flow_id: None,
            rule: "Fallback".to_string(),
            rule_payload: String::new(),
            chains: vec!["direct".to_string()],
            upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
            domain: None,
            network: "tcp".to_string(),
            process: None,
            process_path: None,
        });
        let locked = backend.read().await;
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let worker = spawn_udp_removal_worker(
            Arc::clone(&pool),
            Arc::clone(&backend),
            Arc::clone(&tracker),
            fatal_tx,
            Arc::clone(&pins),
        );
        let sender = pins.retirement_sink.lock().clone().unwrap();
        let mut retiring = Box::pin(flow.retire());
        assert!(futures::poll!(&mut retiring).is_pending());
        assert_eq!(
            sender.capacity(),
            sender.max_capacity() - 1,
            "guard was admitted before cancellation"
        );
        drop(retiring);
        drop(sender);
        let mut confirmation = Box::pin(close.wait());
        assert!(
            futures::poll!(&mut confirmation).is_pending(),
            "cancelled waiter cannot fail admitted close"
        );
        assert!(pins.contains(&key));
        assert_eq!(tracker.snapshot().len(), 1);
        assert!(locked.tcp_conn_state_lookup(&key)?.is_some());
        let mut byte = [0u8; 1];
        let mut reading = Box::pin(peer.read(&mut byte));
        assert!(
            futures::poll!(&mut reading).is_pending(),
            "admitted socket must stay owned"
        );
        drop(reading);
        pins.retirement_sink.lock().take();
        assert!(pool.shutdown().await.joined);
        let mut joining = worker;
        assert!(
            futures::poll!(&mut joining).is_pending(),
            "join must wait for backend exclusion"
        );
        drop(locked);
        tokio::time::timeout(Duration::from_secs(2), joining).await??;
        assert_eq!(confirmation.await, CloseOutcome::Closed);
        assert!(backend.read().await.tcp_conn_state_lookup(&key)?.is_none());
        assert!(!pins.contains(&key));
        assert!(tracker.snapshot().is_empty());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
            0
        );
        assert!(fatal_rx.try_recv().is_err());
        Ok(())
    }
}
