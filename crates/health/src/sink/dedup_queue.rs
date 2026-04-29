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

//! Latest-wins dedup queue.
//!
//! Generic queue keyed by `K` that replaces the value when the same key
//! is pushed again. Used by health report sinks (keyed by machine/rack
//! + report source) and OtlpSink (keyed by event type identity string).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;

use tokio::sync::Notify;

struct QueueState<K: Eq + Hash, V> {
    values: HashMap<K, V>,
    ready: VecDeque<K>,
}

pub(crate) struct DedupQueue<K: Eq + Hash + Clone, V> {
    state: Mutex<QueueState<K, V>>,
    notify: Notify,
}

impl<K: Eq + Hash + Clone, V> DedupQueue<K, V> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(QueueState {
                values: HashMap::new(),
                ready: VecDeque::new(),
            }),
            notify: Notify::new(),
        }
    }

    /// returns true if an existing value was replaced
    pub fn save_latest(&self, key: K, value: V) -> bool {
        let replaced;
        {
            let mut state = self.state.lock().expect("dedup queue mutex poisoned");
            if state.values.contains_key(&key) {
                state.values.insert(key, value);
                replaced = true;
            } else {
                state.values.insert(key.clone(), value);
                state.ready.push_back(key);
                replaced = false;
            }
        }
        self.notify.notify_one();
        replaced
    }

    pub async fn next(&self) -> (K, V) {
        loop {
            if let Some(pair) = self.pop() {
                return pair;
            }
            self.notify.notified().await;
        }
    }

    pub fn pop(&self) -> Option<(K, V)> {
        let mut state = self.state.lock().expect("dedup queue mutex poisoned");
        while let Some(key) = state.ready.pop_front() {
            if let Some(value) = state.values.remove(&key) {
                return Some((key, value));
            }
        }
        None
    }

    #[allow(dead_code)] // used by OtlpDrainTask in the next commit
    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_by_key() {
        let queue = DedupQueue::<String, i32>::new();

        queue.save_latest("a".into(), 1);
        queue.save_latest("a".into(), 2);
        queue.save_latest("b".into(), 3);

        let mut count = 0;
        while queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn different_keys_are_separate() {
        let queue = DedupQueue::<String, i32>::new();

        queue.save_latest("a".into(), 1);
        queue.save_latest("b".into(), 2);

        let mut count = 0;
        while queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn preserves_fifo_order() {
        let queue = DedupQueue::<String, i32>::new();

        queue.save_latest("first".into(), 1);
        queue.save_latest("second".into(), 2);

        assert_eq!(queue.pop().unwrap().0, "first");
        assert_eq!(queue.pop().unwrap().0, "second");
        assert!(queue.pop().is_none());
    }

    #[test]
    fn update_replaces_value_but_keeps_position() {
        let queue = DedupQueue::<String, i32>::new();

        queue.save_latest("a".into(), 1);
        queue.save_latest("b".into(), 2);
        queue.save_latest("a".into(), 99);

        let (key_a, val_a) = queue.pop().unwrap();
        assert_eq!(key_a, "a");
        assert_eq!(val_a, 99);
        assert_eq!(queue.pop().unwrap().0, "b");
    }
}
