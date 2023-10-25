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
use utils::cmd::{Cmd, CmdError};

use crate::{db::bmc_metadata::UserRoles, model::machine::machine_id::MachineId};

#[async_trait]
pub trait IPMITool: Send + Sync + 'static {
    async fn restart(&self, machine_id: &MachineId, bmc_ip: String) -> Result<(), eyre::Report>;
}

pub struct IPMIToolImpl<C: CredentialProvider> {
    credential_provider: Arc<C>,
    ipmi_reboot_commands: Vec<Vec<String>>,
    attempts: u32,
}

impl<C: CredentialProvider> IPMIToolImpl<C> {
    const DPU_IPMITOOL_COMMAND_ARGS: &str = "-I lanplus -C 17 chassis power cycle";
    const DPU_LEGACY_IPMITOOL_COMMAND_ARGS: &str = "-I lanplus -C 17 raw 0x32 0xA1 0x01";

    pub fn new(
        credential_provider: Arc<C>,
        ipmi_reboot_args: &Option<Vec<String>>,
        attempts: &Option<u32>,
    ) -> Self {
        let ipmi_reboot_args = match ipmi_reboot_args {
            Some(commands) => commands.to_owned(),
            None => vec![
                Self::DPU_IPMITOOL_COMMAND_ARGS.to_owned(),
                Self::DPU_LEGACY_IPMITOOL_COMMAND_ARGS.to_owned(),
            ],
        };

        let ipmi_reboot_args: Vec<Vec<String>> = ipmi_reboot_args
            .into_iter()
            .map(|s| s.split(' ').map(str::to_owned).collect())
            .collect();

        IPMIToolImpl {
            credential_provider,
            ipmi_reboot_commands: ipmi_reboot_args,
            attempts: attempts.unwrap_or(3),
        }
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> IPMITool for IPMIToolImpl<C> {
    async fn restart(&self, machine_id: &MachineId, bmc_ip: String) -> Result<(), eyre::Report> {
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

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // cmd line args that are filled in from the db
        let prefix_args: Vec<String> = vec!["-H", &bmc_ip, "-U", &username, "-E"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        let mut success_count = 0;
        let mut errors: Vec<CmdError> = Vec::default();
        for command in self.ipmi_reboot_commands.iter() {
            let mut args = prefix_args.clone();
            args.extend(command.clone());

            match Cmd::new("/usr/bin/ipmitool")
                .env("IPMITOOL_PASSWORD", &password)
                .args(&args)
                .attempts(self.attempts)
                .output()
            {
                Ok(_) => {
                    success_count += 1;
                }
                Err(e) => errors.push(e),
            }
        }

        // if none of the commands worked, return the last error and log the others.  otherwise log all the errors and return Ok.
        let result = errors.pop();
        for e in errors.iter() {
            tracing::warn!("ipmitool error restarting machine {machine_id}: {e}");
        }

        if success_count == 0 {
            result.map_or(
                Err(CmdError::Generic(
                    "No commands were successful and no error reported".to_owned(),
                )),
                |e| Err(e),
            )?;
        }
        Ok(())
    }
}

pub struct IPMIToolTestImpl {}

#[async_trait]
impl IPMITool for IPMIToolTestImpl {
    async fn restart(&self, _machine_id: &MachineId, _bmc_ip: String) -> Result<(), eyre::Report> {
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
        let tool = super::IPMIToolImpl::new(cp, &None, &Some(1));

        let first_command: Vec<&str> =
            super::IPMIToolImpl::<TestCredentialProvider>::DPU_IPMITOOL_COMMAND_ARGS
                .split(' ')
                .collect();
        assert!(first_command.iter().eq(tool.ipmi_reboot_commands[0].iter()));

        let second_command: Vec<&str> =
            super::IPMIToolImpl::<TestCredentialProvider>::DPU_LEGACY_IPMITOOL_COMMAND_ARGS
                .split(' ')
                .collect();
        assert!(second_command
            .iter()
            .eq(tool.ipmi_reboot_commands[1].iter()));

        assert!(tool.ipmi_reboot_commands.get(2).is_none());
    }
}
