struct OrderingNotifier {
    cache: Arc<Mutex<DnsCache>>,
    observed: StdMutex<Option<Vec<u8>>>,
}
impl DomainResolveNotifier for OrderingNotifier {
    fn on_domain_resolved(&self, _: &str, response: &[u8]) {
        assert!(
            self.cache.try_lock().is_ok(),
            "cache guard held at notifier"
        );
        self.observed
            .lock()
            .expect("notifier lock")
            .replace(response.to_vec());
    }
}
