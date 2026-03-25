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
use forge_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use utils::HostPortPair;
use utils::cmd::{CmdError, CmdResult, TokioCmd};

#[async_trait]
pub trait IPMITool: Send + Sync + 'static {
    async fn bmc_cold_reset(
        &self,
        bmc_ip: IpAddr,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report>;

    async fn restart(
        &self,
        machine_id: &MachineId,
        bmc_ip: IpAddr,
        legacy_boot: bool,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report>;
}

pub struct IPMIToolImpl {
    credential_reader: Arc<dyn CredentialReader>,
    attempts: u32,
}

impl IPMIToolImpl {
    const IPMITOOL_COMMAND_ARGS: &'static str = "-I lanplus -C 17 chassis power reset";
    const IPMITOOL_BMC_RESET_COMMAND_ARGS: &'static str = "-I lanplus -C 17 bmc reset cold";
    const DPU_LEGACY_IPMITOOL_COMMAND_ARGS: &'static str = "-I lanplus -C 17 raw 0x32 0xA1 0x01";

    pub fn new(credential_reader: Arc<dyn CredentialReader>, attempts: &Option<u32>) -> Self {
        IPMIToolImpl {
            credential_reader,
            attempts: attempts.unwrap_or(3),
        }
    }
}

#[async_trait]
impl IPMITool for IPMIToolImpl {
    async fn bmc_cold_reset(
        &self,
        bmc_ip: IpAddr,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        let credentials = self
            .credential_reader
            .get_credentials(credential_key)
            .await
            .map_err(|e| {
                eyre!("Secret engine getting credentilas for key {credential_key:#?}: {e:#?}")
            })?
            .ok_or_else(|| eyre!("No credentials for key {credential_key:#?} found"))?;

        match self
            .execute_ipmitool_command(Self::IPMITOOL_BMC_RESET_COMMAND_ARGS, bmc_ip, &credentials)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(eyre::eyre!("{}", e.to_string())),
        }
    }

    async fn restart(
        &self,
        machine_id: &MachineId,
        bmc_ip: IpAddr,
        legacy_boot: bool,
        credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        let credentials: Credentials = self
            .credential_reader
            .get_credentials(credential_key)
            .await
            .map_err(|e| {
                eyre!(
                    "Secret engine error for machine {}: {e}",
                    machine_id.clone(),
                )
            })?
            .ok_or_else(|| eyre!("No credentials for machine {} found", machine_id.clone()))?;

        let mut errors: Vec<CmdError> = Vec::default();

        if legacy_boot {
            match self
                .execute_ipmitool_command(
                    Self::DPU_LEGACY_IPMITOOL_COMMAND_ARGS,
                    bmc_ip,
                    &credentials,
                )
                .await
            {
                Ok(_) => return Ok(()),   // return early if we get a successful response
                Err(e) => errors.push(e), // add error and move on if not
            }
        }
        match self
            .execute_ipmitool_command(Self::IPMITOOL_COMMAND_ARGS, bmc_ip, &credentials)
            .await
        {
            Ok(_) => return Ok(()),   // return early if we get a successful response
            Err(e) => errors.push(e), // add error and move on if not
        }

        let result = errors.pop();
        /*
        for e in errors.iter() {
            tracing::warn!("ipmitool error restarting machine {machine_id}: {e}");
        }
        */

        Err(match result {
            None => {
                // This should be impossible, right? We always call execute_ipmitool_command.
                eyre::eyre!("No commands were successful and no error reported")
            }
            Some(err) => err.into(),
        })
    }
}

impl IPMIToolImpl {
    async fn execute_ipmitool_command(
        &self,
        command: &str,
        bmc_ip: IpAddr,
        credentials: &Credentials,
    ) -> CmdResult<String> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // cmd line args that are filled in from the db
        let prefix_args: Vec<String> =
            vec!["-H", bmc_ip.to_string().as_str(), "-U", username, "-E"]
                .into_iter()
                .map(str::to_owned)
                .collect();

        let mut args = prefix_args.to_owned();
        args.extend(command.split(' ').map(str::to_owned));
        let cmd = TokioCmd::new("/usr/bin/ipmitool")
            .args(&args)
            .attempts(self.attempts);

        tracing::info!("Running command: {:?}", cmd);
        cmd.env("IPMITOOL_PASSWORD", password).output().await
    }
}

pub struct IPMIToolTestImpl {}

#[async_trait]
impl IPMITool for IPMIToolTestImpl {
    async fn restart(
        &self,
        _machine_id: &MachineId,
        _bmc_ip: IpAddr,
        _legacy_boot: bool,
        _credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        Ok(())
    }

    async fn bmc_cold_reset(
        &self,
        _bmc_ip: IpAddr,
        _credential_key: &CredentialKey,
    ) -> Result<(), eyre::Report> {
        Ok(())
    }
}

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
#[cfg(test)]
mod test {
    use std::sync::Arc;

    use forge_secrets::credentials::{Credentials, TestCredentialManager};

    #[test]
    pub fn test_ipmitool_new() {
        let cp = Arc::new(TestCredentialManager::new(Credentials::UsernamePassword {
            username: "user".to_string(),
            password: "password".to_string(),
        }));
        let tool = super::IPMIToolImpl::new(cp, &Some(1));

        assert_eq!(tool.attempts, 1);
    }
}
