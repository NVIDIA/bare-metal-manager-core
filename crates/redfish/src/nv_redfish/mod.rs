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
use nv_redfish::bmc_http::reqwest::{
    Client as NvRedfishReqwestClient, ClientParams as NvRedfishReqwestClientParams,
};
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use reqwest::header::HeaderMap;
use utils::HostPortPair;

pub type NvRedfishBmc = HttpBmc<NvRedfishReqwestClient>;

pub struct NvRedfishClientPool {
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    cache: Arc<Mutex<HashMap<PoolKey, Arc<NvRedfishBmc>>>>,
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

    pub fn cached_nv_redfish_bmc(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Option<Arc<NvRedfishBmc>> {
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

    pub fn update_cache(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
        bmc: Arc<NvRedfishBmc>,
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
        cache.insert(key, bmc);
    }

    pub fn create_nv_redfish_bmc(
        &self,
        bmc_address: SocketAddr,
        Credentials::UsernamePassword { username, password }: Credentials,
        connection_close: bool,
    ) -> Result<Arc<NvRedfishBmc>, reqwest::Error> {
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

        let client = NvRedfishReqwestClient::with_params(
            NvRedfishReqwestClientParams::new().accept_invalid_certs(true),
        )?;
        Ok(Arc::new(NvRedfishBmc::with_custom_headers(
            client,
            bmc_url,
            BmcCredentials::new(username, password),
            CacheSettings::with_capacity(10),
            headers,
        )))
    }
}
