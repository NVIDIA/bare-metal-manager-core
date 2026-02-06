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

use crate::api_client::BmcAddr;

pub struct ShardManager {
    shard: usize,
    shards_count: usize,
}

impl ShardManager {
    pub fn new(shard: usize, shards_count: usize) -> Self {
        Self {
            shard,
            shards_count,
        }
    }

    pub fn should_monitor(&self, endpoint: &BmcAddr) -> bool {
        if self.shards_count == 1 {
            return true;
        }

        let hash = self.hash_endpoint(endpoint);
        let assigned_pod = hash % self.shards_count;
        assigned_pod == self.shard
    }

    /// FNV-1a 64-bit
    fn hash_endpoint(&self, endpoint: &BmcAddr) -> usize {
        const FNV_PRIME: u64 = 1099511628211;
        const FNV_OFFSET_BASIS: u64 = 14695981039346656037;

        let mut hash = FNV_OFFSET_BASIS;
        let key = endpoint.hash_key();

        for byte in key.as_bytes() {
            hash = hash.wrapping_mul(FNV_PRIME);
            hash ^= *byte as u64;
        }

        hash as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_shard() {
        let manager = ShardManager::new(0, 1);
        let endpoint = BmcAddr {
            ip: "10.0.0.1".parse().unwrap(),
            port: Some(443),
            mac: "42:9e:b1:bd:9d:dd".into(),
        };
        assert!(manager.should_monitor(&endpoint));
    }

    #[test]
    fn test_consistent_hashing() {
        let endpoint1 = BmcAddr {
            ip: "10.0.0.1".parse().unwrap(),
            port: Some(443),
            mac: "42:9e:b1:bd:9d:dd".into(),
        };
        let endpoint2 = BmcAddr {
            ip: "10.0.0.2".parse().unwrap(),
            port: Some(443),
            mac: "42:9e:b2:bd:9d:dd".into(),
        };

        let manager0 = ShardManager::new(0, 3);
        let manager1 = ShardManager::new(1, 3);
        let manager2 = ShardManager::new(2, 3);

        // Each endpoint should be assigned to exactly one pod
        let mut count1 = 0;
        let mut count2 = 0;
        if manager0.should_monitor(&endpoint1) {
            count1 += 1;
        }
        if manager1.should_monitor(&endpoint1) {
            count1 += 1;
        }
        if manager2.should_monitor(&endpoint1) {
            count1 += 1;
        }
        assert_eq!(
            count1, 1,
            "endpoint1 should be monitored by exactly one pod"
        );

        if manager0.should_monitor(&endpoint2) {
            count2 += 1;
        }
        if manager1.should_monitor(&endpoint2) {
            count2 += 1;
        }
        if manager2.should_monitor(&endpoint2) {
            count2 += 1;
        }
        assert_eq!(
            count2, 1,
            "endpoint2 should be monitored by exactly one pod"
        );
    }
}
