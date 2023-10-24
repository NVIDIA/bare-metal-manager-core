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
use utils::cmd::Cmd;

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

        for command in self.ipmi_reboot_commands.iter() {
            let mut args = prefix_args.clone();
            args.extend(command.clone());

            Cmd::new("/usr/bin/ipmitool")
                .env("IPMITOOL_PASSWORD", &password)
                .args(&args)
                .attempts(self.attempts)
                .output()
                .map_err(|e| eyre!("ipmitool error: {}", e))?;
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
