use std::future::Future;

pub(super) async fn exchange_with_retry<Once, Fut, Reset, ResetFut>(
    label: &'static str,
    raw_query: &[u8],
    once: Once,
    reset: Reset,
    feedback: Option<&honk_outbound::group::ScoreFeedback>,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn(Option<honk_outbound::group::ScoreReporter>) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<u8>>>,
    Reset: FnOnce() -> ResetFut,
    ResetFut: Future<Output = ()>,
{
    async fn attempt<Once, Fut>(
        once: &Once,
        feedback: Option<&honk_outbound::group::ScoreFeedback>,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>>
    where
        Once: Fn(Option<honk_outbound::group::ScoreReporter>) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<u8>>>,
    {
        let reporter = feedback.map(honk_outbound::group::ScoreFeedback::start);
        let result = once(reporter.clone()).await;
        if let Some(reporter) = &reporter {
            match &result {
                Ok(response) if super::is_valid_response(raw_query, response) => {
                    reporter.finish(honk_outbound::group::ScoreOutcome::Success)
                }
                Ok(_) => reporter.finish(honk_outbound::group::ScoreOutcome::Other),
                Err(error) => {
                    reporter.finish(honk_outbound::group::ScoreOutcome::from_error(error))
                }
            }
        }
        result
    }

    match attempt(&once, feedback, raw_query).await {
        Ok(response) => Ok(response),
        Err(first) => {
            record_reset(label);
            reset().await;
            attempt(&once, feedback, raw_query).await.map_err(|error| {
                anyhow::anyhow!("{label} failed after retry: {error} (first: {first})")
            })
        }
    }
}

fn record_reset(label: &'static str) {
    crate::stats::record_dns_event(crate::stats::DnsStatEvent::TransportReset);
    tracing::debug!(
        transport = label,
        error_kind = "exchange_failed",
        "DNS transport reset before retry"
    );
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_exchange_records_reset_before_successful_retry() {
        let before = crate::stats::dns_snapshot();
        let calls = AtomicUsize::new(0);
        let resets = AtomicUsize::new(0);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer({
                let captured = Arc::clone(&captured);
                move || Capture(Arc::clone(&captured))
            })
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let response = super::exchange_with_retry(
            "test",
            &[0; 12],
            |_| async {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("secret endpoint value")
                }
                Ok(vec![1, 2, 3])
            },
            || async {
                resets.fetch_add(1, Ordering::SeqCst);
            },
            None,
        )
        .await
        .expect("retry succeeds");

        assert_eq!(response, vec![1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        let log = String::from_utf8(captured.lock().expect("capture").clone()).expect("UTF-8 log");
        assert!(log.contains("error_kind=\"exchange_failed\""));
        assert!(log.contains("transport=\"test\""));
        assert!(!log.contains("secret endpoint value"));
        assert!(crate::stats::dns_snapshot().delta(before).transport_reset >= 1);
    }
}
