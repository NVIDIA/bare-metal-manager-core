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
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use carbide_secrets::credentials::Credentials;
use carbide_utils::HostPortPair;
use carbide_utils::redfish::format_forwarded_host_parameter;
pub use nv_redfish::bmc_http::reqwest::BmcError;
use nv_redfish::bmc_http::reqwest::{
    Client as RedfishReqwestClient, ClientParams as RedfishReqwestClientParams,
};
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use nv_redfish::oem::hpe::ilo_service_ext::ManagerType as HpeManagerType;
use nv_redfish::{Error as NvError, ServiceRoot as NvServiceRoot};
use reqwest::header::HeaderMap;
use url::Url;

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
        let bmc_url = build_bmc_url(proxy_address.as_ref(), bmc_address)
            .map_err(|e| Error::Bmc(BmcError::InvalidRequest(format!("invalid BMC URL: {e}"))))?;

        let mut headers = HeaderMap::new();
        if proxy_address.is_some() {
            headers.insert(
                reqwest::header::FORWARDED,
                format_forwarded_host_parameter(&bmc_address.ip().to_string())
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

/// Builds the BMC base URL, applying any configured proxy override.
///
/// Mirrors `health::BmcAddr::to_url()`: IPv6 hosts are bracketed so the URL
/// authority parses — a bare `IpAddr` Display leaves IPv6 unbracketed
/// (e.g. `2001:db8::1`), which `Url::parse` rejects.
fn build_bmc_url(
    proxy_address: &Option<HostPortPair>,
    bmc_address: SocketAddr,
) -> Result<Url, url::ParseError> {
    // Bracket the BMC's own IP if IPv6; IPv4 renders unchanged.
    let bmc_host = match bmc_address.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let (host, port) = match proxy_address {
        // No override: the BMC's own IP and port.
        None => (bmc_host, bmc_address.port()),
        // An operator-supplied override may replace the host, the port, or
        // both; `url_host()` brackets an IPv6 literal proxy host.
        Some(proxy) => (
            proxy.url_host().map_or(bmc_host, Cow::into_owned),
            proxy.port().unwrap_or_else(|| bmc_address.port()),
        ),
    };
    let mut url = Url::parse(&format!("https://{host}"))?;
    let _ = url.set_port(Some(port));
    Ok(url)
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

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("valid socket addr")
    }

    // Regression: an IPv6 BMC behind a port-only proxy must yield a bracketed
    // authority. Pre-fix the manual format produced `https://2001:db8::1:8443`,
    // which `Url::parse` rejects — and `create_bmc` `.expect()`s the parse, so it
    // panicked.
    #[test]
    fn port_only_proxy_brackets_ipv6_bmc() {
        let url = build_bmc_url(
            &Some(HostPortPair::PortOnly(8443)),
            sock("[2001:db8::1]:443"),
        )
        .expect("url should build");
        assert_eq!(url.host_str(), Some("[2001:db8::1]"));
        assert_eq!(url.port(), Some(8443));
        assert_eq!(url.as_str(), "https://[2001:db8::1]:8443/");
    }

    // IPv4 BMCs keep their unbracketed authority.
    #[test]
    fn port_only_proxy_leaves_ipv4_unchanged() {
        let url = build_bmc_url(&Some(HostPortPair::PortOnly(8443)), sock("10.0.0.5:443"))
            .expect("url should build");
        assert_eq!(url.host_str(), Some("10.0.0.5"));
        assert_eq!(url.port(), Some(8443));
    }

    // No proxy: the BMC's own IP and port form the authority; IPv6 is bracketed.
    // 443 is the https default, so the url crate canonicalizes it out of the
    // explicit port (as it always did when the old string was parsed).
    #[test]
    fn no_proxy_brackets_ipv6_bmc() {
        let url = build_bmc_url(&None, sock("[2001:db8::1]:443")).expect("url should build");
        assert_eq!(url.host_str(), Some("[2001:db8::1]"));
        assert_eq!(url.port_or_known_default(), Some(443));
        assert_eq!(url.as_str(), "https://[2001:db8::1]/");
    }

    // A proxy host supplied as a bare IPv6 literal is bracketed too.
    #[test]
    fn proxy_host_ipv6_literal_is_bracketed() {
        let host_only = build_bmc_url(
            &Some(HostPortPair::HostOnly("2001:db8::2".to_string())),
            sock("10.0.0.5:443"),
        )
        .expect("url should build");
        assert_eq!(host_only.host_str(), Some("[2001:db8::2]"));
        assert_eq!(host_only.port_or_known_default(), Some(443));

        let host_and_port = build_bmc_url(
            &Some(HostPortPair::HostAndPort("2001:db8::2".to_string(), 8443)),
            sock("10.0.0.5:443"),
        )
        .expect("url should build");
        assert_eq!(host_and_port.host_str(), Some("[2001:db8::2]"));
        assert_eq!(host_and_port.port(), Some(8443));
    }

    // A hostname proxy is passed through untouched.
    #[test]
    fn proxy_hostname_unchanged() {
        let url = build_bmc_url(
            &Some(HostPortPair::HostAndPort(
                "bmc-proxy.example".to_string(),
                8443,
            )),
            sock("10.0.0.5:443"),
        )
        .expect("url should build");
        assert_eq!(url.host_str(), Some("bmc-proxy.example"));
        assert_eq!(url.port(), Some(8443));
    }

    // Regression (#3008 review): the `Forwarded` `host` parameter that
    // `create_bmc` sends must bracket an IPv6 BMC per RFC 7239; IPv4 and
    // hostnames keep the bare token form, and the result must be a valid
    // header value (create_bmc `.expect()`s the parse).
    #[test]
    fn forwarded_host_parameter_brackets_ipv6_bmc() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let v4: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            format_forwarded_host_parameter(&v6.to_string()),
            "host=\"[2001:db8::1]\""
        );
        assert_eq!(
            format_forwarded_host_parameter(&v4.to_string()),
            "host=10.0.0.5"
        );
        for ip in [v6, v4] {
            reqwest::header::HeaderValue::from_str(&format_forwarded_host_parameter(
                &ip.to_string(),
            ))
            .expect("valid Forwarded header value");
        }
    }
}
