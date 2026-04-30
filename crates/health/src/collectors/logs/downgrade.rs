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

use std::borrow::Cow;
use std::time::Instant;

use dashmap::DashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeReason {
    SseNotAvailable,
    ConnectFailureBudgetExhausted,
}

impl DowngradeReason {
    fn as_label(self) -> &'static str {
        match self {
            Self::SseNotAvailable => "sse_not_available",
            Self::ConnectFailureBudgetExhausted => "connect_failure_budget",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DowngradeEvent {
    pub reason: DowngradeReason,
    pub at: Instant,
}

#[derive(Debug, Default)]
pub struct LogDowngradeRegistry {
    downgraded: DashMap<Cow<'static, str>, DowngradeEvent>,
}

impl LogDowngradeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_downgraded(&self, key: &str) -> bool {
        self.downgraded.contains_key(key)
    }

    // first call for a key inserts + warns; subsequent calls are no-ops
    pub fn mark_downgraded(&self, key: Cow<'static, str>, reason: DowngradeReason) {
        use dashmap::Entry;
        match self.downgraded.entry(key.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(DowngradeEvent {
                    reason,
                    at: Instant::now(),
                });
                tracing::warn!(
                    endpoint_key = %key,
                    reason = reason.as_label(),
                    "SSE log collector downgraded to periodic polling; restart the \
                     health service to retry SSE once the underlying issue is resolved"
                );
            }
            Entry::Occupied(_) => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.downgraded.len()
    }

    #[cfg(test)]
    pub(crate) fn event_for(&self, key: &str) -> Option<DowngradeEvent> {
        self.downgraded.get(key).map(|entry| *entry.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_registry_has_no_downgrades() {
        let registry = LogDowngradeRegistry::new();
        assert!(!registry.is_downgraded("any-key"));
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_mark_downgraded_records_key_and_reason() {
        let registry = LogDowngradeRegistry::new();
        registry.mark_downgraded(Cow::Borrowed("bmc-1"), DowngradeReason::SseNotAvailable);

        assert!(registry.is_downgraded("bmc-1"));
        assert_eq!(registry.len(), 1);
        let event = registry
            .event_for("bmc-1")
            .expect("event should be recorded");
        assert_eq!(event.reason, DowngradeReason::SseNotAvailable);
    }

    #[test]
    fn test_mark_downgraded_is_idempotent_for_same_key() {
        let registry = LogDowngradeRegistry::new();
        registry.mark_downgraded(Cow::Borrowed("bmc-1"), DowngradeReason::SseNotAvailable);
        let first = registry
            .event_for("bmc-1")
            .expect("first mark should record");

        // second mark is a no-op; original reason and timestamp stick
        std::thread::sleep(std::time::Duration::from_millis(2));
        registry.mark_downgraded(
            Cow::Borrowed("bmc-1"),
            DowngradeReason::ConnectFailureBudgetExhausted,
        );
        let second = registry
            .event_for("bmc-1")
            .expect("second mark should not clear the entry");

        assert_eq!(registry.len(), 1);
        assert_eq!(second.reason, DowngradeReason::SseNotAvailable);
        assert_eq!(second.at, first.at);
    }

    #[test]
    fn test_mark_downgraded_tracks_multiple_endpoints_independently() {
        let registry = LogDowngradeRegistry::new();
        registry.mark_downgraded(Cow::Borrowed("bmc-1"), DowngradeReason::SseNotAvailable);
        registry.mark_downgraded(
            Cow::Borrowed("bmc-2"),
            DowngradeReason::ConnectFailureBudgetExhausted,
        );

        assert!(registry.is_downgraded("bmc-1"));
        assert!(registry.is_downgraded("bmc-2"));
        assert!(!registry.is_downgraded("bmc-3"));
        assert_eq!(registry.len(), 2);
    }
}
