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

use ::rpc::admin_cli::CarbideCliError;
use carbide_uuid::rack::RackId;
use clap::{ArgGroup, Parser};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"switch_serial_number",
"nvos_mac_addresses",
"nvos_username",
"nvos_password",
])))]
pub struct Args {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected switch")]
    pub bmc_mac_address: Option<MacAddress>,

    #[clap(long = "id", help = "ID (UUID) of the expected switch to update.")]
    #[serde(skip)]
    pub id: Option<Uuid>,
    #[clap(
        short = 'u',
        long,
        group = "group",
        requires("bmc_password"),
        help = "BMC username of the expected switch"
    )]
    pub bmc_username: Option<String>,
    #[clap(
        short = 'p',
        long,
        group = "group",
        requires("bmc_username"),
        help = "BMC password of the expected switch"
    )]
    pub bmc_password: Option<String>,
    #[clap(
        short = 's',
        long,
        group = "group",
        help = "Switch serial number of the expected switch"
    )]
    pub switch_serial_number: Option<String>,

    #[clap(
        long = "nvos-mac-address",
        group = "group",
        help = "NVOS MAC address(es) of the expected switch",
        action = clap::ArgAction::Append
    )]
    pub nvos_mac_addresses: Vec<MacAddress>,
    #[clap(long, group = "group", help = "NVOS username of the expected switch")]
    pub nvos_username: Option<String>,
    #[clap(long, group = "group", help = "NVOS password of the expected switch")]
    pub nvos_password: Option<String>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Switches. If empty, the SwitchId will be used"
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Machines"
    )]
    pub meta_description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A label that will be added as metadata for the newly created Machine. The labels key and value must be separated by a : character",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long = "rack_id",
        value_name = "RACK_ID",
        help = "Rack ID for this switch",
        action = clap::ArgAction::Append
    )]
    pub rack_id: Option<RackId>,

    #[clap(
        long = "bmc-ip-address",
        value_name = "BMC_IP_ADDRESS",
        help = "BMC IP address of the expected switch"
    )]
    pub bmc_ip_address: Option<IpAddr>,

    #[clap(
        long = "bmc-retain-credentials",
        value_name = "BMC_RETAIN_CREDENTIALS",
        help = "When true, site-explorer skips BMC password rotation and stores factory-default credentials in Vault as-is"
    )]
    pub bmc_retain_credentials: Option<bool>,
}

impl TryFrom<Args> for rpc::forge::ExpectedSwitch {
    type Error = CarbideCliError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        match (&args.bmc_mac_address, &args.id) {
            (Some(_), Some(_)) => {
                return Err(CarbideCliError::ChooseOneError("--bmc-mac-address", "--id"));
            }
            (None, None) => {
                return Err(CarbideCliError::RequireOneError(
                    "--bmc-mac-address",
                    "--id",
                ));
            }
            _ => {}
        }
        if args.bmc_username.is_none()
            && args.bmc_password.is_none()
            && args.switch_serial_number.is_none()
            && args.nvos_username.is_none()
            && args.nvos_password.is_none()
        {
            return Err(CarbideCliError::GenericError(
                "One of the following options must be specified: bmc-user-name and bmc-password or switch-serial-number or nvos-username and nvos-password".to_string(),
            ));
        }
        Ok(rpc::forge::ExpectedSwitch {
            expected_switch_id: args.id.map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            }),
            bmc_mac_address: args
                .bmc_mac_address
                .map(|m| m.to_string())
                .unwrap_or_default(),
            bmc_username: args.bmc_username.unwrap_or_default(),
            bmc_password: args.bmc_password.unwrap_or_default(),
            switch_serial_number: args.switch_serial_number.unwrap_or_default(),
            nvos_username: args.nvos_username,
            nvos_password: args.nvos_password,
            metadata: Some(rpc::forge::Metadata {
                name: args.meta_name.unwrap_or_default(),
                description: args.meta_description.unwrap_or_default(),
                labels: crate::metadata::parse_rpc_labels(args.labels.unwrap_or_default()),
            }),
            rack_id: args.rack_id,
            nvos_mac_addresses: args
                .nvos_mac_addresses
                .iter()
                .map(|m| m.to_string())
                .collect(),
            bmc_ip_address: args
                .bmc_ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            bmc_retain_credentials: args.bmc_retain_credentials,
        })
    }
}
