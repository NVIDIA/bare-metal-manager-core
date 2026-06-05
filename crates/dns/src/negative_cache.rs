/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! TTL-expiring, LRU-bounded cache of negative DNS responses.
//!
//! Caching negatives keeps repeated lookups for the same name from re-querying
//! the api server. Two classes of negative are cached with different lifetimes:
//!
//! * *authoritative* negatives (NXDomain, Refused) — stable answers, cached for
//!   the full `ttl`; and
//! * *transient* failures (ServFail) — a momentary upstream error, cached only
//!   for the short `transient_ttl` so a client retry storm collapses into one
//!   upstream call per name per window without outliving the api server's
//!   recovery (RFC 2308 §7.1, RFC 9520).
//!
//! Two mechanisms keep memory bounded:
//!
//! * an LRU capacity bound (`max_entries`): inserting into a full cache evicts
//!   the *least-recently-used* entry rather than refusing the newcomer, so a
//!   flood of distinct names keeps the hot working set cached instead of
//!   pinning whichever names happened to arrive first; and
//! * a periodic sweep ([`NegativeCache::evict_expired`]) that drops entries past
//!   their TTL, reclaiming capacity that expired-but-not-yet-re-queried entries
//!   would otherwise hold.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_resolver::proto::op::ResponseCode;
use hickory_server::proto::rr::RecordType;
use lru::LruCache;

/// Identifies a cached negative response: the queried name and record type.
#[derive(Hash, Debug, Eq, PartialEq, Clone)]
pub(crate) struct CacheKey {
    pub qname: String,
    pub qtype: RecordType,
}

#[derive(Debug)]
struct NegativeEntry {
    reason_code: ResponseCode,
    expires_at: Instant,
}

#[derive(Debug)]
pub(crate) struct NegativeCache {
    // A plain `std::sync::Mutex`, not an async one: every critical section is a
    // handful of synchronous map operations and the guard is never held across
    // an `.await`. (`LruCache::get` bumps recency, so even the read path needs
    // `&mut`, ruling out an `RwLock`.) Using the sync mutex also lets the
    // observable metrics gauge read the length from a synchronous callback.
    entries: Mutex<LruCache<CacheKey, NegativeEntry>>,
    /// Lifetime for authoritative negatives (NXDomain, Refused).
    ttl: Duration,
    /// Lifetime for transient failures (ServFail); kept short on purpose.
    transient_ttl: Duration,
}

impl NegativeCache {
    pub(crate) fn new(ttl: Duration, transient_ttl: Duration, max_entries: usize) -> Self {
        // A zero capacity would evict every entry the instant it was inserted,
        // defeating the cache, and `NonZeroUsize::new(0)` is `None` — floor it
        // at 1 rather than panic on a misconfigured bound.
        let capacity = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            entries: Mutex::new(LruCache::new(capacity)),
            ttl,
            transient_ttl,
        }
    }

    /// The lifetime for an entry given whether the negative is `transient`.
    /// Authoritative negatives live for the full `ttl`; a transient failure is
    /// held only for the short `transient_ttl` so it does not outlive the
    /// upstream's recovery. The caller classifies transience (see the DNS
    /// handler), since it cannot be derived from the response code alone.
    // TODO: RFC 9520 RECOMMENDS exponential/linear backoff that lengthens the
    // cached-failure lifetime for *persistent* failures.
    fn ttl_for(&self, transient: bool) -> Duration {
        if transient {
            self.transient_ttl
        } else {
            self.ttl
        }
    }

    /// The number of cache entries currently held, including any that have expired but
    /// not yet been swept. Backs the cache-occupancy metrics gauge.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries
            .lock()
            .expect("negative cache mutex poisoned")
            .len()
    }

    /// Returns the cached response code for `key` if a non-expired entry exists,
    /// marking it most-recently-used.
    ///
    /// An entry that has expired but has not yet been swept is treated as absent
    /// and dropped on the spot, so a stale negative is never served and the
    /// expired entry stops counting against the capacity bound.
    pub(crate) fn get(&self, key: &CacheKey) -> Option<ResponseCode> {
        let mut entries = self.entries.lock().expect("negative cache mutex poisoned");
        let code = entries
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.reason_code);
        // Either the key was absent (no-op) or it was present but expired; in
        // the latter case remove it so it neither serves nor occupies a slot.
        if code.is_none() {
            entries.pop(key);
        }
        code
    }

    /// Records a negative `code` for `key`. `transient` selects the entry's
    /// lifetime (see [`Self::ttl_for`]).
    ///
    /// The cache always admits the entry: inserting into a full cache evicts the
    /// least-recently-used entry. Returns `true` when such a capacity eviction
    /// occurred (a *different* key was pushed out to make room), and `false`
    /// when the entry fit without eviction or merely refreshed an existing key.
    pub(crate) fn record(&self, key: CacheKey, code: ResponseCode, transient: bool) -> bool {
        let entry = NegativeEntry {
            reason_code: code,
            expires_at: Instant::now() + self.ttl_for(transient),
        };
        let mut entries = self.entries.lock().expect("negative cache mutex poisoned");
        // `push` returns the displaced (key, value): the same key on an in-place
        // refresh, or a *different* key when a full cache evicted its LRU entry
        // to admit this one.
        match entries.push(key.clone(), entry) {
            Some((displaced_key, _)) => displaced_key != key,
            None => false,
        }
    }

    /// Removes expired entries and returns the number evicted.
    pub(crate) fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("negative cache mutex poisoned");
        let expired: Vec<CacheKey> = entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            entries.pop(key);
        }
        expired.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(qname: &str) -> CacheKey {
        CacheKey {
            qname: qname.to_string(),
            qtype: RecordType::A,
        }
    }

    #[test]
    fn evicts_least_recently_used_when_full() {
        let cache = NegativeCache::new(Duration::from_secs(120), Duration::from_secs(5), 2);
        cache.record(key("a.example.com."), ResponseCode::NXDomain, false);
        cache.record(key("b.example.com."), ResponseCode::NXDomain, false);

        // Touch `a`, making `b` the least-recently-used entry.
        assert_eq!(
            cache.get(&key("a.example.com.")),
            Some(ResponseCode::NXDomain)
        );

        // Admitting `c` reports an eviction and pushes out `b`, not `a`.
        let evicted = cache.record(key("c.example.com."), ResponseCode::NXDomain, false);
        assert!(evicted);
        assert_eq!(cache.entry_count(), 2);
        assert_eq!(cache.get(&key("b.example.com.")), None);
        assert_eq!(
            cache.get(&key("a.example.com.")),
            Some(ResponseCode::NXDomain)
        );
        assert_eq!(
            cache.get(&key("c.example.com.")),
            Some(ResponseCode::NXDomain)
        );
    }

    #[test]
    fn refreshes_existing_key_without_eviction_when_full() {
        let cache = NegativeCache::new(Duration::from_secs(120), Duration::from_secs(5), 2);
        cache.record(key("a.example.com."), ResponseCode::NXDomain, false);
        cache.record(key("b.example.com."), ResponseCode::NXDomain, false);

        let evicted = cache.record(key("a.example.com."), ResponseCode::NXDomain, false);
        assert!(!evicted);
        assert_eq!(cache.entry_count(), 2);
    }

    #[test]
    fn get_returns_none_for_expired_entry() {
        // A zero TTL means every entry is already expired when read back.
        let cache = NegativeCache::new(Duration::from_secs(0), Duration::from_secs(0), 16);
        cache.record(key("gone.example.com."), ResponseCode::NXDomain, false);
        assert_eq!(cache.get(&key("gone.example.com.")), None);
    }

    #[test]
    fn evict_expired_drops_only_expired_entries() {
        let cache = NegativeCache::new(Duration::from_secs(0), Duration::from_secs(0), 16);
        cache.record(key("a.example.com."), ResponseCode::NXDomain, false);
        cache.record(key("b.example.com."), ResponseCode::Refused, false);

        assert_eq!(cache.evict_expired(), 2);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn servfail_uses_transient_ttl_not_authoritative_ttl() {
        let cache = NegativeCache::new(Duration::from_secs(120), Duration::from_secs(0), 16);

        cache.record(key("fail.example.com."), ResponseCode::ServFail, true);
        assert_eq!(cache.get(&key("fail.example.com.")), None);

        cache.record(key("gone.example.com."), ResponseCode::NXDomain, false);
        assert_eq!(
            cache.get(&key("gone.example.com.")),
            Some(ResponseCode::NXDomain)
        );
    }
}
