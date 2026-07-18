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

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use carbide_secrets::credentials::Credentials;
use carbide_utils::HostPortPair;
pub use nv_redfish::bmc_http::reqwest::BmcError;
use nv_redfish::bmc_http::reqwest::{
    Client as RedfishReqwestClient, ClientParams as RedfishReqwestClientParams,
};
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use nv_redfish::oem::hpe::ilo_service_ext::ManagerType as HpeManagerType;
use nv_redfish::{Error as NvError, ServiceRoot as NvServiceRoot};
use reqwest::header::HeaderMap;

pub type RedfishBmc = HttpBmc<RedfishReqwestClient>;
pub type ServiceRoot = NvServiceRoot<RedfishBmc>;
pub type Error = NvError<RedfishBmc>;

/// Service roots are refreshed hourly so long-running processes eventually
/// observe BMC replacements, upgrades, and configuration changes.
const DEFAULT_SERVICE_ROOT_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

pub fn new_pool(proxy_address: Arc<ArcSwap<Option<HostPortPair>>>) -> Arc<NvRedfishClientPool> {
    NvRedfishClientPool::new(proxy_address).into()
}

pub struct NvRedfishClientPool {
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    cache: Arc<Mutex<ServiceRootCache>>,
    cache_ttl: Duration,
}

#[derive(Default)]
struct ServiceRootCache {
    roots: HashMap<PoolKey, CachedServiceRoot>,
    expirations: BinaryHeap<Reverse<CacheExpiration>>,
    next_generation: u64,
}

impl ServiceRootCache {
    fn allocate_generation(&mut self) -> u64 {
        if self.next_generation == u64::MAX {
            self.roots.clear();
            self.expirations.clear();
            self.next_generation = 0;
        }

        let generation = self.next_generation;
        self.next_generation += 1;
        generation
    }
}

struct CachedServiceRoot {
    root: Arc<ServiceRoot>,
    generation: u64,
}

struct CacheExpiration {
    expires_at: Instant,
    generation: u64,
    key: PoolKey,
}

impl PartialEq for CacheExpiration {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.generation == other.generation
    }
}

impl Eq for CacheExpiration {}

impl PartialOrd for CacheExpiration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CacheExpiration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct PoolKey {
    proxy_address: Arc<Option<HostPortPair>>,
    bmc_address: SocketAddr,
    credentials: BmcCredentials,
}

impl NvRedfishClientPool {
    pub fn new(proxy_address: Arc<ArcSwap<Option<HostPortPair>>>) -> Self {
        Self::with_cache_ttl(proxy_address, DEFAULT_SERVICE_ROOT_CACHE_TTL)
    }

    /// Creates a client pool with an explicit service-root cache lifetime.
    ///
    /// This is primarily useful for tests that need deterministic expiration
    /// without sleeping.
    pub fn with_cache_ttl(
        proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            proxy_address,
            cache: Default::default(),
            cache_ttl,
        }
    }

    pub async fn service_root(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Arc<ServiceRoot>, Error> {
        self.service_root_with_cache_predicate(bmc_address, credentials, |_| true)
            .await
    }

    /// Same as [`Self::service_root`], but a freshly fetched root is cached
    /// only when `should_cache` returns true for it.
    pub async fn service_root_with_cache_predicate(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
        should_cache: impl FnOnce(&ServiceRoot) -> bool,
    ) -> Result<Arc<ServiceRoot>, Error> {
        self.remove_expired(Instant::now());

        let Credentials::UsernamePassword { username, password } = credentials;
        let bmc_credentials = BmcCredentials::new(username, password);

        if let Some(sevice_root) = self.cached_root(bmc_address, bmc_credentials.clone()) {
            Ok(sevice_root)
        } else {
            let bmc = self.create_bmc(bmc_address, bmc_credentials.clone(), false)?;
            let service_root = ServiceRoot::new(bmc).await?;
            let service_root = if service_root.vendor()
                == Some(nv_redfish::service_root::Vendor::new("HPE"))
                && let Some(HpeManagerType::Ilo(version)) = service_root
                    .oem_hpe_ilo_service_ext()
                    .ok()
                    .as_ref()
                    .and_then(|v| v.as_ref())
                    .and_then(|v| v.manager_type())
                && version < 7
            {
                // Handle HPE BMC that closing connection right after
                // response. In this case, we add Connection: Close
                // HTTP header to prevent trying to reuse this
                // connection. Otherwise, race condition may happen
                // when reqwest thinks that connection is alive but it
                // is about to close by server. Reusing such
                // connections causes errors.
                let bmc = self.create_bmc(bmc_address, bmc_credentials.clone(), true)?;
                service_root.replace_bmc(bmc.clone())
            } else {
                service_root
            };
            let service_root = Arc::new(service_root);
            if should_cache(&service_root) {
                self.update_cache(bmc_address, bmc_credentials, service_root.clone());
            }
            Ok(service_root)
        }
    }

    fn cached_root(
        &self,
        bmc_address: SocketAddr,
        credentials: BmcCredentials,
    ) -> Option<Arc<ServiceRoot>> {
        let proxy_address = self.proxy_address.load();
        let key = PoolKey {
            proxy_address: proxy_address.clone(),
            bmc_address,
            credentials,
        };
        self.cache
            .lock()
            .expect("nv-redfish client cache mutex poisoned")
            .roots
            .get(&key)
            .map(|entry| entry.root.clone())
    }

    fn update_cache(
        &self,
        bmc_address: SocketAddr,
        credentials: BmcCredentials,
        root: Arc<ServiceRoot>,
    ) {
        let proxy_address = self.proxy_address.load();
        let key = PoolKey {
            proxy_address: proxy_address.clone(),
            bmc_address,
            credentials,
        };
        let mut cache = self
            .cache
            .lock()
            .expect("nv-redfish client cache mutex poisoned");
        let expires_at = Instant::now() + self.cache_ttl;
        let generation = cache.allocate_generation();
        cache
            .roots
            .insert(key.clone(), CachedServiceRoot { root, generation });
        cache.expirations.push(Reverse(CacheExpiration {
            expires_at,
            generation,
            key,
        }));
    }

    fn remove_expired(&self, now: Instant) {
        let mut cache = self
            .cache
            .lock()
            .expect("nv-redfish client cache mutex poisoned");

        while cache
            .expirations
            .peek()
            .is_some_and(|expiration| expiration.0.expires_at <= now)
        {
            let Some(Reverse(expiration)) = cache.expirations.pop() else {
                break;
            };
            if cache
                .roots
                .get(&expiration.key)
                .is_some_and(|entry| entry.generation == expiration.generation)
            {
                cache.roots.remove(&expiration.key);
            }
        }
    }

    pub fn create_bmc(
        &self,
        bmc_address: SocketAddr,
        credentials: BmcCredentials,
        connection_close: bool,
    ) -> Result<Arc<RedfishBmc>, Error> {
        let proxy_address = self.proxy_address.load();
        let bmc_url = match proxy_address.as_ref() {
            // No override
            None => format!("https://{bmc_address}"),
            Some(HostPortPair::HostAndPort(h, p)) => format!("https://{h}:{p}"),
            Some(HostPortPair::HostOnly(h)) => format!("https://{h}:{}", bmc_address.port()),
            Some(HostPortPair::PortOnly(p)) => format!("https://{}:{p}", bmc_address.ip()),
        }
        .parse::<url::Url>()
        .expect("Generated URI is expected to be valid");

        let mut headers = HeaderMap::new();
        if proxy_address.is_some() {
            headers.insert(
                reqwest::header::FORWARDED,
                format!("host={}", bmc_address.ip())
                    .parse()
                    .expect("Generated header is expected to be valid"),
            );
        }
        if connection_close {
            headers.insert(
                reqwest::header::CONNECTION,
                reqwest::header::HeaderValue::from_static("Close"),
            );
        }

        let client = RedfishReqwestClient::with_params(
            RedfishReqwestClientParams::new().accept_invalid_certs(true),
        )
        .map_err(|err| Error::Bmc(err.into()))?;
        Ok(Arc::new(RedfishBmc::with_custom_headers(
            client,
            bmc_url,
            credentials,
            CacheSettings::with_capacity(10),
            headers,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_overflow_clears_expirations_and_restarts_from_zero() {
        let key = PoolKey {
            proxy_address: Arc::new(None),
            bmc_address: "127.0.0.1:443".parse().unwrap(),
            credentials: BmcCredentials::new("root".to_string(), "password".to_string()),
        };
        let mut cache = ServiceRootCache {
            expirations: BinaryHeap::from([Reverse(CacheExpiration {
                expires_at: Instant::now(),
                generation: u64::MAX - 1,
                key,
            })]),
            next_generation: u64::MAX,
            ..Default::default()
        };

        assert_eq!(cache.allocate_generation(), 0);
        assert!(cache.roots.is_empty());
        assert!(cache.expirations.is_empty());
        assert_eq!(cache.next_generation, 1);
    }
}
