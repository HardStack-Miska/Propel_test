//! Exact, bounded in-memory classification cache. No billing decisions or ticket text are stored.

use crate::domain::{Analysis, AnalysisOutcome, AnalysisSource, Ticket, hash_bytes};
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::Instant,
};

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub capacity: usize,
    pub ttl: Duration,
    /// Bounds leaders and waiting followers together; overload never queues.
    pub max_in_flight: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 256,
            ttl: Duration::from_secs(300),
            max_in_flight: 256,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub coalesced: u64,
    pub entries: usize,
}

pub(crate) struct AnalysisCache {
    namespace: String,
    config: CacheConfig,
    callers: Arc<Semaphore>,
    state: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, Entry>,
    flights: HashMap<String, watch::Receiver<Option<AnalysisOutcome>>>,
    statistics: CacheStatistics,
    sequence: u64,
}

struct Entry {
    analysis: Analysis,
    source: AnalysisSource,
    expires: Instant,
    last_used: u64,
}

pub(crate) enum Lookup {
    Hit(AnalysisOutcome),
    Leader(Leader),
    Follower(Follower),
    Busy,
}

pub(crate) struct Leader {
    cache: Arc<AnalysisCache>,
    key: String,
    sender: watch::Sender<Option<AnalysisOutcome>>,
    active: bool,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct Follower {
    receiver: watch::Receiver<Option<AnalysisOutcome>>,
    _permit: OwnedSemaphorePermit,
}

impl AnalysisCache {
    pub(crate) fn new(namespace: &str, config: CacheConfig) -> Result<Arc<Self>> {
        if namespace.trim().is_empty()
            || namespace.len() > 1_024
            || namespace.chars().any(char::is_control)
        {
            bail!("invalid analysis cache namespace");
        }
        if config.capacity == 0
            || config.capacity > 65_536
            || config.max_in_flight == 0
            || config.max_in_flight > 4_096
            || config.ttl.is_zero()
            || Instant::now().checked_add(config.ttl).is_none()
        {
            bail!("invalid analysis cache limits");
        }
        Ok(Arc::new(Self {
            namespace: hash_bytes(namespace.as_bytes()),
            config,
            callers: Arc::new(Semaphore::new(config.max_in_flight)),
            state: Mutex::new(CacheState::default()),
        }))
    }

    fn key(&self, ticket: &Ticket) -> String {
        hash_bytes(
            &serde_json::to_vec(&(&self.namespace, &ticket.subject, &ticket.body))
                .expect("serializable text"),
        )
    }

    pub(crate) fn lookup(self: &Arc<Self>, ticket: &Ticket) -> Lookup {
        let key = self.key(ticket);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        state.entries.retain(|_, entry| entry.expires > now);
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.last_used = sequence;
            let outcome = AnalysisOutcome {
                analysis: entry.analysis.clone(),
                source: entry.source,
                attempts: 0,
                degraded_reason: None,
                usage: Default::default(),
                cached: true,
            };
            state.statistics.hits = state.statistics.hits.saturating_add(1);
            return Lookup::Hit(outcome);
        }
        let Ok(permit) = self.callers.clone().try_acquire_owned() else {
            return Lookup::Busy;
        };
        if let Some(receiver) = state.flights.get(&key).cloned() {
            state.statistics.coalesced = state.statistics.coalesced.saturating_add(1);
            return Lookup::Follower(Follower {
                receiver,
                _permit: permit,
            });
        }
        let (sender, receiver) = watch::channel(None);
        state.flights.insert(key.clone(), receiver);
        state.statistics.misses = state.statistics.misses.saturating_add(1);
        Lookup::Leader(Leader {
            cache: self.clone(),
            key,
            sender,
            active: true,
            _permit: permit,
        })
    }

    pub(crate) fn statistics(&self) -> CacheStatistics {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .entries
            .retain(|_, entry| entry.expires > Instant::now());
        CacheStatistics {
            entries: state.entries.len(),
            ..state.statistics.clone()
        }
    }
}

impl Leader {
    pub(crate) fn finish(mut self, outcome: &AnalysisOutcome) {
        let success = outcome.source != AnalysisSource::Fallback
            && outcome.degraded_reason.is_none()
            && outcome.analysis.validate();
        let mut state = self.cache.state.lock().unwrap_or_else(|e| e.into_inner());
        state.flights.remove(&self.key);
        let now = Instant::now();
        state.entries.retain(|_, entry| entry.expires > now);
        if success {
            if state.entries.len() >= self.cache.config.capacity {
                let oldest = state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    state.entries.remove(&oldest);
                }
            }
            state.sequence = state.sequence.saturating_add(1);
            let last_used = state.sequence;
            state.entries.insert(
                self.key.clone(),
                Entry {
                    analysis: outcome.analysis.clone(),
                    source: outcome.source,
                    expires: now + self.cache.config.ttl,
                    last_used,
                },
            );
        }
        self.active = false;
        drop(state);
        // Current followers share failures too, but failures are never retained
        // in entries. They issue no calls and inherit no billable usage.
        let mut shared = outcome.clone();
        shared.attempts = 0;
        shared.usage = Default::default();
        shared.cached = success;
        self.sender.send_replace(Some(shared));
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if self.active {
            self.cache
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .flights
                .remove(&self.key);
        }
        // Dropping the last sender closes the flight. Followers return a fixed
        // cancellation reason instead of starting more potentially paid work.
    }
}

impl Follower {
    pub(crate) async fn wait(mut self) -> Option<AnalysisOutcome> {
        loop {
            if let Some(outcome) = self.receiver.borrow_and_update().clone() {
                return Some(outcome);
            }
            if self.receiver.changed().await.is_err() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ticket(body: &str) -> Ticket {
        serde_json::from_value(
            json!({"id":"synthetic","received_at":"2030-01-15T12:00:00+00:00",
            "subject":"Synthetic subject","body":body,"purchases":[],"app_opens_since_renewal":0}),
        )
        .unwrap()
    }
    fn outcome() -> AnalysisOutcome {
        serde_json::from_value(json!({"analysis":{"category":"technical","severity":"medium","language":"english",
            "confidence":0.9,"refund_requested":false},"source":"ollama","attempts":1,"degraded_reason":null})).unwrap()
    }
    fn insert(cache: &Arc<AnalysisCache>, input: &Ticket) {
        let Lookup::Leader(leader) = cache.lookup(input) else {
            panic!("expected a cache miss")
        };
        leader.finish(&outcome());
    }

    #[tokio::test]
    async fn expiry_and_lru_eviction_are_bounded() {
        let cache = AnalysisCache::new(
            "synthetic",
            CacheConfig {
                capacity: 2,
                ttl: Duration::from_millis(50),
                ..CacheConfig::default()
            },
        )
        .unwrap();
        insert(&cache, &ticket("a"));
        insert(&cache, &ticket("b"));
        assert!(matches!(cache.lookup(&ticket("a")), Lookup::Hit(_)));
        insert(&cache, &ticket("c"));
        assert!(matches!(cache.lookup(&ticket("b")), Lookup::Leader(_)));
        assert!(matches!(cache.lookup(&ticket("a")), Lookup::Hit(_)));
        assert_eq!(cache.statistics().entries, 2);
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(cache.statistics().entries, 0);
        assert!(matches!(cache.lookup(&ticket("a")), Lookup::Leader(_)));
    }

    #[test]
    fn exact_text_and_namespace_keys_exclude_ticket_and_billing_data() {
        let cache =
            AnalysisCache::new("tenant-a/schema-v2/model-a", CacheConfig::default()).unwrap();
        let other =
            AnalysisCache::new("tenant-b/schema-v2/model-a", CacheConfig::default()).unwrap();
        let original = ticket("a\nb");
        let mut changed = original.clone();
        changed.id = "other-customer".into();
        changed.app_opens_since_renewal = 999;
        assert_eq!(cache.key(&original), cache.key(&changed));
        assert_ne!(cache.key(&original), other.key(&original));
        changed.body = "a\nb ".into();
        assert_ne!(cache.key(&original), cache.key(&changed));
        changed.subject.push_str("\na");
        changed.body = "b".into();
        assert_ne!(cache.key(&original), cache.key(&changed));
    }

    #[tokio::test]
    async fn bounded_followers_share_failure_only_until_the_flight_ends() {
        let cache = AnalysisCache::new(
            "synthetic",
            CacheConfig {
                max_in_flight: 2,
                ..CacheConfig::default()
            },
        )
        .unwrap();
        let input = ticket("same");
        let Lookup::Leader(leader) = cache.lookup(&input) else {
            panic!()
        };
        let Lookup::Follower(follower) = cache.lookup(&input) else {
            panic!()
        };
        assert!(matches!(cache.lookup(&ticket("other")), Lookup::Busy));
        assert!(matches!(cache.lookup(&input), Lookup::Busy));
        let mut failure = outcome();
        failure.source = AnalysisSource::Fallback;
        failure.degraded_reason = Some("model_timeout".into());
        leader.finish(&failure);
        let shared = follower.wait().await.unwrap();
        assert!(!shared.cached);
        assert_eq!(shared.attempts, 0);
        assert_eq!(shared.usage.calls, 0);
        assert_eq!(shared.degraded_reason.as_deref(), Some("model_timeout"));
        assert_eq!(cache.statistics().entries, 0);
        assert!(matches!(cache.lookup(&input), Lookup::Leader(_)));
    }

    #[tokio::test]
    async fn cancellation_unblocks_followers_and_removes_flight_keys() {
        let cache = AnalysisCache::new("synthetic", CacheConfig::default()).unwrap();
        let input = ticket("same");
        let Lookup::Leader(leader) = cache.lookup(&input) else {
            panic!()
        };
        let Lookup::Follower(follower) = cache.lookup(&input) else {
            panic!()
        };
        drop(leader);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), follower.wait())
                .await
                .unwrap()
                .is_none()
        );
        assert!(cache.state.lock().unwrap().flights.is_empty());
        assert!(matches!(cache.lookup(&input), Lookup::Leader(_)));
    }

    #[test]
    fn invalid_successes_are_never_retained() {
        let cache = AnalysisCache::new("synthetic", CacheConfig::default()).unwrap();
        let input = ticket("same");
        let Lookup::Leader(leader) = cache.lookup(&input) else {
            panic!()
        };
        let mut invalid = outcome();
        invalid.analysis.confidence = 2.0;
        leader.finish(&invalid);
        assert_eq!(cache.statistics().entries, 0);
        assert!(matches!(cache.lookup(&input), Lookup::Leader(_)));
    }
}
