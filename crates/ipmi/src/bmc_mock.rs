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

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use eyre::eyre;
use forge_secrets::credentials::CredentialKey;
use utils::HostPortPair;

use crate::IPMITool;

/// HTTP-based IPMI implementation for testing with bmc-mock.
/// Sends JSON requests to bmc_proxy which routes to appropriate machine.
pub struct IPMIToolHttpImpl {
    bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,
}

impl IPMIToolHttpImpl {
    pub fn new(bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>) -> Self {
        Self { bmc_proxy }
    }

    async fn execute_action(&self, action: &str, bmc_ip: IpAddr) -> Result<(), eyre::Report> {
        let proxy = self.bmc_proxy.load();

        // Determine the target URL and headers based on whether a proxy is configured
        let (url, forwarded_header) = match proxy.as_ref() {
            Some(proxy) => {
                // Use proxy - send to proxy with Forwarded header containing BMC IP
                let proxy_url = match proxy {
                    HostPortPair::HostAndPort(h, p) => format!("https://{}:{}", h, p),
                    HostPortPair::HostOnly(h) => format!("https://{}:443", h),
                    HostPortPair::PortOnly(p) => format!("https://127.0.0.1:{}", p),
                };
                (
                    format!("{}/ipmi", proxy_url),
                    Some(format!("host={}", bmc_ip)),
                )
            }
            None => {
                // No proxy - send directly to BMC
                (format!("https://{}/ipmi", bmc_ip), None)
            }
        };

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| eyre!("failed to create HTTP client: {}", e))?;

        let mut request = client
            .post(&url)
            .json(&serde_json::json!({"action": action}));

        if let Some(header) = forwarded_header {
            request = request.header("Forwarded", header);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| eyre!("HTTP request to {} failed: {}", url, e))?;

        if !resp.status().is_success() {
            return Err(eyre!("HTTP error: {}", resp.status()));
        }

        #[derive(serde::Deserialize)]
        struct IpmiHttpResponse {
            success: bool,
            error: Option<String>,
        }

        let body: IpmiHttpResponse = resp
            .json()
            .await
            .map_err(|e| eyre!("failed to parse response: {}", e))?;

        if !body.success {
            return Err(eyre!(
                "IPMI action failed: {}",
                body.error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl IPMITool for IPMIToolHttpImpl {
    async fn bmc_cold_reset(
        &self,
        bmc_ip: IpAddr,
        _credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        self.execute_action("bmc_cold_reset", bmc_ip).await
    }

    async fn restart(
        &self,
        _machine_id: &MachineId,
        bmc_ip: IpAddr,
        legacy_boot: bool,
        _credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        if legacy_boot && self.execute_action("dpu_legacy_boot", bmc_ip).await.is_ok() {
            return Ok(());
        }
        // Fall through to chassis_power_reset if legacy_boot fails or is false
        self.execute_action("chassis_power_reset", bmc_ip).await
    }
}
