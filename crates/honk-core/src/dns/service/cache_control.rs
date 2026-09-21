use super::DnsService;
#[cfg(feature = "native-api")]
use crate::dns::cache::{CacheInspectionError, CacheKey, ExactCacheEntry};
use crate::dns::cache::{CacheInvalidation, CacheMutation};

impl DnsService {
    #[cfg(feature = "native-api")]
    pub(crate) async fn inspect_cache(
        &self,
        max_bytes: usize,
        now: std::time::Instant,
        select: impl FnMut(&CacheKey, std::time::Instant) -> bool,
    ) -> Result<Vec<ExactCacheEntry>, CacheInspectionError> {
        self.cache()
            .lock()
            .await
            .service()
            .inspect_exact(max_bytes, now, select)
    }

    pub(crate) async fn invalidate_cache(
        &self,
        selection: CacheInvalidation,
    ) -> anyhow::Result<CacheMutation> {
        let cache = self.cache().lock().await.service();
        self.flush_generation
            .send_modify(|generation| *generation = generation.saturating_add(1));
        cache
            .invalidate(selection)
            .await
            .map_err(anyhow::Error::from)
    }
}
