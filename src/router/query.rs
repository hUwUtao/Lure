use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Cached Status response entry
struct CachedEntry {
    status_json: Arc<Vec<u8>>,
    cached_at: Instant,
}

/// In-memory query cache for Status responses, keyed by route ID
pub struct QueryCache {
    entries: Mutex<HashMap<u64, CachedEntry>>,
    ttl: Duration,
}

impl fmt::Debug for QueryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryCache")
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl QueryCache {
    /// Create a new cache with the specified TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Get a cached Status response if it exists and is not stale
    pub async fn get(&self, route_id: u64) -> Option<Arc<Vec<u8>>> {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get(&route_id) {
            if entry.cached_at.elapsed() < self.ttl {
                return Some(Arc::clone(&entry.status_json));
            } else {
                // Entry is stale, remove it
                entries.remove(&route_id);
            }
        }
        None
    }

    /// Store a Status response in the cache
    pub async fn set(&self, route_id: u64, json: Vec<u8>) {
        let mut entries = self.entries.lock().await;
        entries.insert(
            route_id,
            CachedEntry {
                status_json: Arc::new(json),
                cached_at: Instant::now(),
            },
        );
    }

    /// Remove a cache entry for a route (called on route removal)
    pub async fn evict(&self, route_id: u64) {
        let mut entries = self.entries.lock().await;
        entries.remove(&route_id);
    }
}
