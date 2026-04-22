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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use forge_secrets::credentials::Credentials;
pub use nv_redfish::bmc_http::reqwest::BmcError;
use nv_redfish::bmc_http::reqwest::{
    Client as RedfishReqwestClient, ClientParams as RedfishReqwestClientParams,
};
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use nv_redfish::oem::hpe::ilo_service_ext::ManagerType as HpeManagerType;
use nv_redfish::{Error as NvError, ServiceRoot as NvServiceRoot};
use reqwest::header::HeaderMap;
use utils::HostPortPair;

pub type RedfishBmc = HttpBmc<RedfishReqwestClient>;
pub type ServiceRoot = NvServiceRoot<RedfishBmc>;
pub type Error = NvError<RedfishBmc>;

pub fn new_pool(proxy_address: Arc<ArcSwap<Option<HostPortPair>>>) -> Arc<NvRedfishClientPool> {
    NvRedfishClientPool::new(proxy_address).into()
}

pub struct NvRedfishClientPool {
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    cache: Arc<Mutex<HashMap<PoolKey, Arc<ServiceRoot>>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PoolKey {
    proxy_address: Arc<Option<HostPortPair>>,
    bmc_address: SocketAddr,
    credentials: Credentials,
}

impl NvRedfishClientPool {
    pub fn new(proxy_address: Arc<ArcSwap<Option<HostPortPair>>>) -> Self {
        Self {
            proxy_address,
            cache: Default::default(),
        }
    }

    pub async fn service_root(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Arc<ServiceRoot>, Error> {
        if let Some(sevice_root) = self.cached_root(bmc_address, credentials.clone()) {
            Ok(sevice_root)
        } else {
            let bmc = self.create_bmc(bmc_address, credentials.clone(), false)?;
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
                let bmc = self.create_bmc(bmc_address, credentials.clone(), true)?;
                service_root.replace_bmc(bmc.clone())
            } else {
                service_root
            };
            let service_root = Arc::new(service_root);
            self.update_cache(bmc_address, credentials, service_root.clone());
            Ok(service_root)
        }
    }

    pub fn cached_root(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Option<Arc<ServiceRoot>> {
        let proxy_address = self.proxy_address.load();
        let key = PoolKey {
            proxy_address: proxy_address.clone(),
            bmc_address,
            credentials,
        };
        self.cache
            .lock()
            .expect("nv-redish client cache mutex poisoned")
            .get(&key)
            .cloned()
    }

    fn update_cache(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
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
            .expect("nv-redish client cache mutex poisoned");
        cache.insert(key, root);
    }

    fn create_bmc(
        &self,
        bmc_address: SocketAddr,
        Credentials::UsernamePassword { username, password }: Credentials,
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
            BmcCredentials::new(username, password),
            CacheSettings::with_capacity(10),
            headers,
        )))
    }
}
