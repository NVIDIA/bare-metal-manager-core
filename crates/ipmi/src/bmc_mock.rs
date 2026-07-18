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
use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use carbide_utils::HostPortPair;
use carbide_uuid::machine::MachineId;
use eyre::eyre;

use crate::IPMITool;
use crate::metrics::{IpmiCommand, count_ipmi_command};

/// HTTP-based IPMI implementation for testing with bmc-mock.
/// Sends JSON requests to bmc_proxy which routes to appropriate machine.
pub struct IPMIToolHttpImpl {
    bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,
    credential_reader: Arc<dyn CredentialReader>,
}

impl IPMIToolHttpImpl {
    pub fn new(
        bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,
        credential_reader: Arc<dyn CredentialReader>,
    ) -> Self {
        Self {
            bmc_proxy,
            credential_reader,
        }
    }

    /// The wire action string bmc-mock's `/ipmi` endpoint expects for each
    /// command -- the counterpart of the real runner's `command_args`.
    fn wire_action(command: IpmiCommand) -> &'static str {
        match command {
            IpmiCommand::ChassisPowerReset => "chassis_power_reset",
            IpmiCommand::DpuLegacyPowerReset => "dpu_legacy_boot",
            IpmiCommand::BmcColdReset => "bmc_cold_reset",
        }
    }

    async fn execute_action(
        &self,
        command: IpmiCommand,
        bmc_ip: IpAddr,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        let action = Self::wire_action(command);
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

        let credentials = self
            .credential_reader
            .get_credentials(credential_key)
            .await
            .map_err(|e| {
                eyre!("secret engine getting credentials for key {credential_key:#?}: {e:#?}")
            })?
            .ok_or_else(|| eyre!("no credentials for key {credential_key:#?} found"))?;
        let Credentials::UsernamePassword { username, password } = credentials;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| eyre!("failed to create HTTP client: {}", e))?;

        let mut request = client
            .post(&url)
            .basic_auth(username, Some(password))
            .json(&serde_json::json!({"action": action}));

        if let Some(header) = forwarded_header {
            request = request.header("Forwarded", header);
        }

        // Everything from here on is a dispatched command: the counter covers
        // the wire attempt and its response, not the credential lookup or
        // client construction above (a command that was never sent must not
        // move the metric).
        let result = async {
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
        .await;
        count_ipmi_command(command, &result);
        result
    }
}

#[async_trait]
impl IPMITool for IPMIToolHttpImpl {
    async fn bmc_cold_reset(
        &self,
        bmc_ip: IpAddr,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        self.execute_action(IpmiCommand::BmcColdReset, bmc_ip, credential_key)
            .await
    }

    async fn restart(
        &self,
        _machine_id: &MachineId,
        bmc_ip: IpAddr,
        legacy_boot: bool,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        if legacy_boot
            && self
                .execute_action(IpmiCommand::DpuLegacyPowerReset, bmc_ip, credential_key)
                .await
                .is_ok()
        {
            return Ok(());
        }
        // Fall through to chassis_power_reset if legacy_boot fails or is false
        self.execute_action(IpmiCommand::ChassisPowerReset, bmc_ip, credential_key)
            .await
    }
}
