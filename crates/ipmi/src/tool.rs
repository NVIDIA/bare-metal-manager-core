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

use async_trait::async_trait;
use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use carbide_utils::cmd::{CmdError, CmdResult, TokioCmd};
use carbide_uuid::machine::MachineId;
use eyre::eyre;

use crate::IPMITool;
use crate::metrics::{IpmiCommand, count_ipmi_command};

pub struct IPMIToolImpl {
    credential_reader: Arc<dyn CredentialReader>,
    attempts: u32,
}

impl IPMIToolImpl {
    pub fn new(credential_reader: Arc<dyn CredentialReader>, attempts: Option<u32>) -> Self {
        IPMIToolImpl {
            credential_reader,
            attempts: attempts.unwrap_or(3),
        }
    }

    /// The `ipmitool` argument tail that runs `command`.
    fn command_args(command: IpmiCommand) -> &'static str {
        match command {
            IpmiCommand::ChassisPowerReset => "-I lanplus -C 17 chassis power reset",
            IpmiCommand::DpuLegacyPowerReset => "-I lanplus -C 17 raw 0x32 0xA1 0x01",
            IpmiCommand::BmcColdReset => "-I lanplus -C 17 bmc reset cold",
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
                eyre!("secret engine getting credentilas for key {credential_key:#?}: {e:#?}")
            })?
            .ok_or_else(|| eyre!("no credentials for key {credential_key:#?} found"))?;

        match self
            .execute_ipmitool_command(IpmiCommand::BmcColdReset, bmc_ip, &credentials)
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
                    "secret engine error for machine {}: {e}",
                    machine_id.clone(),
                )
            })?
            .ok_or_else(|| eyre!("no credentials for machine {} found", machine_id.clone()))?;

        let mut errors: Vec<CmdError> = Vec::default();

        if legacy_boot {
            match self
                .execute_ipmitool_command(IpmiCommand::DpuLegacyPowerReset, bmc_ip, &credentials)
                .await
            {
                Ok(_) => return Ok(()),   // return early if we get a successful response
                Err(e) => errors.push(e), // add error and move on if not
            }
        }
        match self
            .execute_ipmitool_command(IpmiCommand::ChassisPowerReset, bmc_ip, &credentials)
            .await
        {
            Ok(_) => return Ok(()),   // return early if we get a successful response
            Err(e) => errors.push(e), // add error and move on if not
        }

        // Only the last error survives as the returned failure; the earlier
        // attempts' failures have already been counted where they happened.
        let result = errors.pop();

        Err(match result {
            None => {
                // This should be impossible, right? We always call execute_ipmitool_command.
                eyre::eyre!("no commands were successful and no error reported")
            }
            Some(err) => err.into(),
        })
    }
}

impl IPMIToolImpl {
    async fn execute_ipmitool_command(
        &self,
        command: IpmiCommand,
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
        args.extend(Self::command_args(command).split(' ').map(str::to_owned));
        let cmd = TokioCmd::new("/usr/bin/ipmitool")
            .args(&args)
            .attempts(self.attempts);

        tracing::info!(command = ?cmd, "Running IPMI command");
        let result = cmd.env("IPMITOOL_PASSWORD", password).output().await;
        count_ipmi_command(command, &result);
        result
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use carbide_secrets::credentials::Credentials;
    use carbide_secrets::test_support::credentials::TestCredentialManager;

    #[test]
    pub fn test_ipmitool_new() {
        let cp = Arc::new(TestCredentialManager::new(Credentials::UsernamePassword {
            username: "user".to_string(),
            password: "password".to_string(),
        }));
        let tool = super::IPMIToolImpl::new(cp, Some(1));

        assert_eq!(tool.attempts, 1);
    }
}
