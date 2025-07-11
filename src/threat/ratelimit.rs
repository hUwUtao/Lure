use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use std::hash::Hash;
use std::num::NonZeroU32;
use std::time::Duration;

#[derive(Debug)]
pub enum RatelimitResult {
    Allowed,
    Disallowed { retry_after: Duration },
}

pub struct Ratelimiter<K: Hash + Eq + Clone> {
    limiter: RateLimiter<K, DashMapStateStore<K>, DefaultClock>,
    retry_time: Duration,
}

impl<K> Ratelimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync,
{
    pub fn new(requests_per_second: u32, retry_time: Duration) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(requests_per_second).unwrap());
        let limiter = RateLimiter::keyed(quota);
        Ratelimiter { limiter, retry_time }
    }

    pub fn check(&self, key: &K) -> RatelimitResult {
        match self.limiter.check_key(key) {
            Ok(_) => RatelimitResult::Allowed,
            Err(negative) => {
                let calculated_retry = negative.wait_time_from(DefaultClock::default().now());
                let retry_after = calculated_retry.max(self.retry_time);
                RatelimitResult::Disallowed { retry_after }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{RatelimitResult, Ratelimiter};
    use std::time::Duration;

    /// Helper function to run a rate limiter test with a given limit, keys, and expected results.
    fn run_test(limit: u32, keys: Vec<&str>, expected: Vec<bool>) {
        let limiter = Ratelimiter::new(limit, Duration::from_secs(1));
        let results: Vec<bool> = keys
            .iter()
            .map(|k| match limiter.check(&k.to_string()) {
                RatelimitResult::Allowed => true,
                RatelimitResult::Disallowed { .. } => false,
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