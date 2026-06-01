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
// TODO - Change this to LRU Cache - https://docs.rs/lru/latest/lru/
//! TTL-expiring cache of negative DNS responses (NXDomain / Refused).
//!
//! Caching negatives keeps repeated lookups for the same non-existent name from querying
//! the api server.
//! Two mechanisms keep memory bounded:
//!
//! * a hard cap on the number of live entries (`max_entries`): once full, a new
//!   name is refused rather than admitted, so a flood of *distinct* non-existent
//!   names cannot grow the HashMap without limit — the time-based sweep alone cannot
//!   contain this because it only removes *expired* entries; and
//! * a periodic sweep ([`NegativeCache::evict_expired`]) that drops entries past
//!   their TTL and returns the backing allocation after a burst subsides.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_server::proto::rr::RecordType;

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
    entries: RwLock<HashMap<CacheKey, NegativeEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl NegativeCache {
    pub(crate) fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// The configured maximum number of entries possible in the cache
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the cached response code for `key` if a non-expired entry exists.
    ///
    /// An entry that has expired but has not yet been swept is treated as absent, so
    /// a stale negative is never served in the window between expiry and the
    /// next [`Self::evict_expired`].
    pub(crate) async fn get(&self, key: &CacheKey) -> Option<ResponseCode> {
        let entries = self.entries.read().await;
        entries
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.reason_code)
    }

    /// Records a negative `code` for `key`, honoring the entry-count cap.
    ///
    /// Returns `true` if the entry was stored. A *new* key is refused once the
    /// cache holds `max_entries` entries. A key that is *already present* is
    /// always refreshed.
    pub(crate) async fn record(&self, key: CacheKey, code: ResponseCode) -> bool {
        let mut entries = self.entries.write().await;
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            return false;
        }
        entries.insert(
            key,
            NegativeEntry {
                reason_code: code,
                expires_at: Instant::now() + self.ttl,
            },
        );
        true
    }

    /// Removes expired entries and returns the number evicted.
    // `HashMap::retain` removes entries but never shrinks the backing
    // allocation, so without the `shrink_to_fit` the peak capacity reached
    // during a burst would be held indefinitely. Once capacity exceeds 4x the
    // live entry count, the memory is handed back to the allocator.
    pub(crate) async fn evict_expired(&self) -> usize {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > Instant::now());
        let evicted = before - entries.len();

        if entries.capacity() > 4 * entries.len() {
            entries.shrink_to_fit();
        }
        evicted
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.entries.read().await.len()
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

    #[tokio::test]
    async fn refuses_new_keys_once_full() {
        let cache = NegativeCache::new(Duration::from_secs(120), 2);
        assert!(
            cache
                .record(key("a.example.com."), ResponseCode::NXDomain)
                .await
        );
        assert!(
            cache
                .record(key("b.example.com."), ResponseCode::NXDomain)
                .await
        );

        assert!(
            !cache
                .record(key("c.example.com."), ResponseCode::NXDomain)
                .await
        );
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test]
    async fn refreshes_existing_key_when_full() {
        let cache = NegativeCache::new(Duration::from_secs(120), 2);
        cache
            .record(key("a.example.com."), ResponseCode::NXDomain)
            .await;
        cache
            .record(key("b.example.com."), ResponseCode::NXDomain)
            .await;

        assert!(
            cache
                .record(key("a.example.com."), ResponseCode::NXDomain)
                .await
        );
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test]
    async fn get_returns_none_for_expired_entry() {
        // A zero TTL means every entry is already expired when read back.
        let cache = NegativeCache::new(Duration::from_secs(0), 16);
        cache
            .record(key("gone.example.com."), ResponseCode::NXDomain)
            .await;
        assert_eq!(cache.get(&key("gone.example.com.")).await, None);
    }

    #[tokio::test]
    async fn evict_expired_drops_only_expired_entries() {
        let cache = NegativeCache::new(Duration::from_secs(0), 16);
        cache
            .record(key("a.example.com."), ResponseCode::NXDomain)
            .await;
        cache
            .record(key("b.example.com."), ResponseCode::Refused)
            .await;

        assert_eq!(cache.evict_expired().await, 2);
        assert_eq!(cache.len().await, 0);
    }
}
