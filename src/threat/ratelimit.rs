use std::{hash::Hash, num::NonZeroU32, time::Duration};

use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::keyed::DashMapStateStore,
};
use log::warn;

#[derive(Debug)]
pub enum RateLimitResult {
    Allowed,
    Disallowed { retry_after: Duration },
}

pub struct RateLimiterController<K: Hash + Eq + Clone> {
    limiter: RateLimiter<K, DashMapStateStore<K>, DefaultClock>,
    retry_time: Duration,
}

impl<K> RateLimiterController<K>
where
    K: Hash + Eq + Clone + Send + Sync + std::fmt::Debug,
{
    pub fn new(requests_per_second: u32, retry_time: Duration) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(requests_per_second).unwrap());
        let limiter = RateLimiter::keyed(quota);
        RateLimiterController {
            limiter,
            retry_time,
        }
    }

    pub fn check(&self, key: &K) -> RateLimitResult {
        match self.limiter.check_key(key) {
            Ok(_) => RateLimitResult::Allowed,
            Err(negative) => {
                let calculated_retry = negative.wait_time_from(DefaultClock::default().now());
                let retry_after = calculated_retry.max(self.retry_time);
                warn!("Rate limit exceeded for key: {:?}", key);
                RateLimitResult::Disallowed { retry_after }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::{RateLimitResult, RateLimiterController};

    /// Helper function to run a rate limiter test with a given limit, keys, and expected results.
    fn run_test(limit: u32, keys: Vec<&str>, expected: Vec<bool>) {
        let limiter = RateLimiterController::new(limit, Duration::from_secs(1));
        let results: Vec<bool> = keys
            .iter()
            .map(|k| match limiter.check(&k.to_string()) {
                RateLimitResult::Allowed => true,
                RateLimitResult::Disallowed { .. } => false,
            })
            .collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_example_case() {
        // Matches the example: limit = 3 per second
        // Sequence: ["bob", "bob", "bob", "alice", "alice", "bob", "alice"]
        // Expected: [true, true, true, true, true, false, true]
        let keys = vec!["bob", "bob", "bob", "alice", "alice", "bob", "alice"];
        let expected = vec![true, true, true, true, true, false, true];
        run_test(3, keys, expected);
    }

    #[test]
    fn test_limit_two() {
        // Limit = 2 per second, testing burst limit
        // Sequence: ["a", "a", "a", "b", "b", "a"]
        // Expected: [true, true, false, true, true, false]
        let keys = vec!["a", "a", "a", "b", "b", "a"];
        let expected = vec![true, true, false, true, true, false];
        run_test(2, keys, expected);
    }

    #[test]
    fn test_limit_one() {
        // Limit = 1 per second, each key gets one request
        // Sequence: ["x", "y", "x", "y", "x"]
        // Expected: [true, true, false, false, false]
        let keys = vec!["x", "y", "x", "y", "x"];
        let expected = vec![true, true, false, false, false];
        run_test(1, keys, expected);
    }
}
