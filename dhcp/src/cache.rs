/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/// Cache DHCP responses from API server
///
/// We usually get about four DHCP requests from the same host in rapid succession, so this
/// prevents us asking the API server every time. Cache is optional, and contents should
/// be short lived.
///
/// The cache is a static because we are called from Kea's hooks, potentially from multiple threads.
///
use std::{
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use lazy_static::lazy_static;
use lru::LruCache;
use mac_address::MacAddress;

use crate::machine::Machine;

/// Data in cache is only valid this long
const MACHINE_CACHE_TIMEOUT: Duration = Duration::from_secs(60);
/// How many entries to keep. After that we evict the entry used the longest ago.
const MACHINE_CACHE_SIZE: usize = 1000;
/// If the cache key comes out shorter than this something went wrong, don't use it.
const MIN_KEY_LEN: usize = 10;

lazy_static! {
    static ref MACHINE_CACHE: Mutex<LruCache<String, CacheEntry>> = Mutex::new(LruCache::new(
        std::num::NonZeroUsize::new(MACHINE_CACHE_SIZE).unwrap()
    ));
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub machine: Machine,
    pub timestamp: Instant,
    pub link_address: IpAddr,
    pub circuit_id: Option<String>,
}

/// Fetch an entry from the cache.
///
/// Result is owned by the caller, it is a clone of cached item.
/// Takes a global lock on the cache.
/// Returns None if we don't have that item in cache, or if we did but
/// it's no longer valid (e.g. too old).
pub fn get(
    mac_address: MacAddress,
    link_address: IpAddr,
    circuit_id: &Option<String>,
    remote_id: &Option<String>,
    vendor_id: &str,
) -> Option<CacheEntry> {
    let key = &key(mac_address, link_address, circuit_id, remote_id, vendor_id);
    if key.len() < MIN_KEY_LEN {
        log::debug!("Unexpected cache key, skipping: '{key}'");
        return None;
    }
    let mut cache = MACHINE_CACHE.lock().unwrap();
    if let Some(entry) = cache.get(key) {
        if !entry.has_expired() {
            return Some(entry.clone());
        } else {
            log::debug!("removed expired cached response for {mac_address:?}");
            let _removed = cache.pop_entry(key);
        }
    }
    None
}

/// Insert or update an item in the cache
pub fn put(
    mac_address: MacAddress,
    link_address: IpAddr,
    circuit_id: Option<String>,
    remote_id: Option<String>,
    machine: Machine,
    vendor_id: &str,
) {
    let key = key(
        mac_address,
        link_address,
        &circuit_id,
        &remote_id,
        vendor_id,
    );
    let new_entry = CacheEntry {
        timestamp: Instant::now(),
        machine,
        link_address,
        circuit_id,
    };
    MACHINE_CACHE.lock().unwrap().put(key, new_entry);
}

//
// Internals
//

// Unique identifier for this entry
fn key(
    mac_address: MacAddress,
    link_address: IpAddr,
    circuit_id: &Option<String>,
    remote_id: &Option<String>,
    vendor_id: &str,
) -> String {
    format!(
        "{}_{}_{}_{}_{}",
        mac_address,
        link_address,
        match circuit_id {
            Some(cid) => cid.as_str(),
            None => "",
        },
        match remote_id {
            Some(rid) => rid.as_str(),
            None => "",
        },
        vendor_id,
    )
}

impl CacheEntry {
    fn has_expired(&self) -> bool {
        self.timestamp.elapsed() >= MACHINE_CACHE_TIMEOUT
    }
}
