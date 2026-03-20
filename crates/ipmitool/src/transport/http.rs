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

//! IPMI-over-HTTPS transport for testing against bmc-mock.
//!
//! POSTs a JSON-serialized [`IpmiRequest`] to `{proxy_url}/ipmi` with a
//! `Forwarded: host={bmc_host}` header so the proxy can route to the correct
//! BMC. Deserializes the JSON [`IpmiResponse`]. HTTPS is just a carrier — the
//! endpoint always returns 200, with the IPMI completion code in the body as
//! the real error signal.

use reqwest::{header, Client};

use crate::error::{IpmitoolError, Result};
use crate::types::{IpmiRequest, IpmiResponse};

use super::IpmiTransport;

/// Configuration for [`HttpTransport`].
pub struct HttpTransportConfig {
    /// The actual BMC hostname/IP (used in `Forwarded` header).
    pub bmc_host: String,
    /// Proxy base URL (e.g. `"https://127.0.0.1:1266"`).
    pub proxy_url: String,
}

/// IPMI-over-HTTPS transport for integration testing against bmc-mock.
pub struct HttpTransport {
    client: Client,
    endpoint: String,
}

impl HttpTransport {
    /// Create a new HTTPS transport.
    ///
    /// Unlike real IPMI transports, this doesn't establish a session —
    /// it's stateless and intended for testing only.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTPS client cannot be built.
    pub fn connect(config: HttpTransportConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .default_headers({
                let mut headers = header::HeaderMap::new();
                headers.insert(
                    header::FORWARDED,
                    format!("host={}", config.bmc_host)
                        .parse()
                        .expect("valid header value"),
                );
                headers.insert(
                    header::CONTENT_TYPE,
                    "application/json".parse().expect("valid header value"),
                );
                headers
            })
            .build()
            .map_err(|e| IpmitoolError::Transport(format!("build HTTPS client: {e}")))?;

        let endpoint = format!("{}/ipmi", config.proxy_url.trim_end_matches('/'));

        Ok(Self { client, endpoint })
    }
}

impl IpmiTransport for HttpTransport {
    async fn send_recv(&mut self, req: &IpmiRequest) -> Result<IpmiResponse> {
        let response = self
            .client
            .post(&self.endpoint)
            .json(req)
            .send()
            .await
            .map_err(|e| IpmitoolError::Transport(e.to_string()))?;

        response
            .json::<IpmiResponse>()
            .await
            .map_err(|e| IpmitoolError::Transport(e.to_string()))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
