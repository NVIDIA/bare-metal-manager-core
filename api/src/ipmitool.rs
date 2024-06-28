/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use async_trait::async_trait;
use eyre::eyre;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use utils::cmd::{CmdError, CmdResult, TokioCmd};

use crate::{db::bmc_metadata::UserRoles, model::machine::machine_id::MachineId};

#[async_trait]
pub trait IPMITool: Send + Sync + 'static {
    async fn restart(
        &self,
        machine_id: &MachineId,
        bmc_ip: String,
        legacy_boot: bool,
    ) -> Result<(), eyre::Report>;
}

pub struct IPMIToolImpl {
    credential_provider: Arc<dyn CredentialProvider>,
    attempts: u32,
}

impl IPMIToolImpl {
    const IPMITOOL_COMMAND_ARGS: &'static str = "-I lanplus -C 17 chassis power reset";
    const DPU_LEGACY_IPMITOOL_COMMAND_ARGS: &'static str = "-I lanplus -C 17 raw 0x32 0xA1 0x01";

    pub fn new(credential_provider: Arc<dyn CredentialProvider>, attempts: &Option<u32>) -> Self {
        IPMIToolImpl {
            credential_provider,
            attempts: attempts.unwrap_or(3),
        }
    }
}

#[async_trait]
impl IPMITool for IPMIToolImpl {
    async fn restart(
        &self,
        machine_id: &MachineId,
        bmc_ip: String,
        legacy_boot: bool,
    ) -> Result<(), eyre::Report> {
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::Bmc {
                machine_id: machine_id.to_string(),
                user_role: UserRoles::Administrator.to_string(),
            })
            .await
            .map_err(|e| {
                eyre!(
                    "Error getting credentials for machine {}: {}",
                    machine_id.clone(),
                    e
                )
            })?;

        let mut errors: Vec<CmdError> = Vec::default();

        if legacy_boot {
            match self
                .execute_ipmitool_command(
                    Self::DPU_LEGACY_IPMITOOL_COMMAND_ARGS,
                    &bmc_ip,
                    &credentials,
                )
                .await
            {
                Ok(_) => return Ok(()),   // return early if we get a successful response
                Err(e) => errors.push(e), // add error and move on if not
            }
        }
        match self
            .execute_ipmitool_command(Self::IPMITOOL_COMMAND_ARGS, &bmc_ip, &credentials)
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
        bmc_ip: &str,
        credentials: &Credentials,
    ) -> CmdResult<String> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // cmd line args that are filled in from the db
        let prefix_args: Vec<String> = vec!["-H", bmc_ip, "-U", username, "-E"]
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
        _bmc_ip: String,
        _legacy_boot: bool,
    ) -> Result<(), eyre::Report> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use async_trait::async_trait;
    use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};

    struct TestCredentialProvider {}

    #[async_trait]
    impl CredentialProvider for TestCredentialProvider {
        async fn get_credentials(&self, _key: CredentialKey) -> Result<Credentials, eyre::Report> {
            Ok(Credentials::UsernamePassword {
                username: "user".to_owned(),
                password: "password".to_owned(),
            })
        }

        async fn set_credentials(
            &self,
            _key: CredentialKey,
            _credentials: Credentials,
        ) -> Result<(), eyre::Report> {
            Ok(())
        }
    }

    #[test]
    pub fn test_ipmitool_new() {
        let cp = Arc::new(TestCredentialProvider {});
        let tool = super::IPMIToolImpl::new(cp, &Some(1));

        assert_eq!(tool.attempts, 1);
    }
}
