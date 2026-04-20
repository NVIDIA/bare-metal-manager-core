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

use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use forge_secrets::credentials::{CredentialReader, Credentials};
use libredfish::model::service_root::RedfishVendor;
use libredfish::{Endpoint, Redfish};
use utils::HostPortPair;

use crate::libredfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};

pub struct RedfishClientPoolImpl {
    pool: libredfish::RedfishClientPool,
    credential_reader: Arc<dyn CredentialReader>,
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
}

impl RedfishClientPoolImpl {
    pub fn new(
        credential_reader: Arc<dyn CredentialReader>,
        pool: libredfish::RedfishClientPool,
        proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    ) -> Self {
        RedfishClientPoolImpl {
            credential_reader,
            pool,
            proxy_address,
        }
    }
}

#[async_trait]
impl RedfishClientPool for RedfishClientPoolImpl {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        vendor: Option<RedfishVendor>,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let original_host = host;

        // Allow globally overriding the bmc port via site-config. We read this on every call to
        // create_client, because self.proxy_address is a dynamic setting.
        let proxy_address = self.proxy_address.load();
        let (host, port, add_custom_header) = match proxy_address.as_ref() {
            // No override
            None => (host, port, false),
            // Override the host and port
            Some(HostPortPair::HostAndPort(h, p)) => (h.as_str(), Some(*p), true),
            // Only override the host
            Some(HostPortPair::HostOnly(h)) => (h.as_str(), port, true),
            // Only override the port
            Some(HostPortPair::PortOnly(p)) => (host, Some(*p), false),
        };

        let (username, password) = match auth {
            RedfishAuth::Anonymous => (None, None), // anonymous login, usually to get service root Vendor info
            RedfishAuth::Direct(username, password) => (Some(username), Some(password)),
            RedfishAuth::Key(credential_key) => {
                let credentials = self
                    .credential_reader
                    .get_credentials(&credential_key)
                    .await?
                    .ok_or_else(|| RedfishClientCreationError::MissingCredentials {
                        key: credential_key.to_key_str().to_string(),
                    })?;

                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => {
                        (Some(username), Some(password))
                    }
                };

                (username, password)
            }
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: username,
            password,
        };

        let custom_headers = if add_custom_header {
            // If we're overriding the host, inject a header indicating the IP address we were
            // originally going to use, using the HTTP "Forwarded" header:
            // https://datatracker.ietf.org/doc/html/rfc7239

            // Override host only if host value is provided in config.
            vec![(
                http::HeaderName::from_str("forwarded")
                    .map_err(|err| RedfishClientCreationError::InvalidHeader(err.to_string()))?,
                format!("host={original_host}"),
            )]
        } else {
            Vec::default()
        };

        match vendor {
            // Auto-detect vendor from the service root.
            None => self
                .pool
                .create_client_with_custom_headers(endpoint, custom_headers)
                .await
                .map_err(RedfishClientCreationError::RedfishError),
            // Unknown means "no vendor" — return a standard client without
            // making any HTTP calls (used by the anonymous probe client).
            // This restores the behavior of the old `initialize: false` path
            // which called create_standard_client. The full initialization
            // path (create_client_with_vendor) makes HTTP calls to /Systems,
            // /Managers, etc. that fail with 401 on BMCs requiring auth.
            Some(RedfishVendor::Unknown) => self
                .pool
                .create_standard_client_with_custom_headers(endpoint, custom_headers)
                .map_err(RedfishClientCreationError::RedfishError)
                .map(|c| c as Box<dyn Redfish>),
            // Use the provided vendor directly.
            Some(vendor) => self
                .pool
                .create_client_with_vendor(endpoint, vendor, custom_headers)
                .await
                .map_err(RedfishClientCreationError::RedfishError),
        }
    }

    fn credential_reader(&self) -> &dyn CredentialReader {
        &*self.credential_reader
    }
}
