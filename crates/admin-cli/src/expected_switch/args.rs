/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::rack::RackId;
use clap::{ArgGroup, Parser};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::metadata::parse_rpc_labels;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show expected switch")]
    Show(ShowExpectedSwitchQuery),
    #[clap(about = "Add expected switch")]
    Add(AddExpectedSwitch),
    #[clap(about = "Delete expected switch")]
    Delete(DeleteExpectedSwitch),
    #[clap(about = "Update expected switch")]
    Update(UpdateExpectedSwitch),
    #[clap(about = "Replace all expected switches")]
    ReplaceAll(ReplaceAllExpectedSwitch),
    #[clap(about = "Erase all expected switches")]
    Erase,
}

#[derive(Parser, Debug)]
pub struct ShowExpectedSwitchQuery {
    #[clap(
        default_value(None),
        help = "BMC MAC address of the expected switch to show. Leave unset for all."
    )]
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct AddExpectedSwitch {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected switch")]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected switch")]
    pub bmc_username: String,
    #[clap(short = 'p', long, help = "BMC password of the expected switch")]
    pub bmc_password: String,
    #[clap(
        short = 's',
        long,
        help = "Chassis serial number of the expected switch"
    )]
    pub switch_serial_number: String,

    #[clap(long, help = "NVOS username of the expected switch")]
    pub nvos_username: Option<String>,
    #[clap(long, help = "NVOS password of the expected switch")]
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
        help = "A label that will be added as metadata for the newly created Machine. The labels key and value must be separated by a : character. E.g. DATACENTER:XYZ",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long = "rack_id",
        value_name = "RACK_ID",
        help = "Rack ID for this machine",
        action = clap::ArgAction::Append
    )]
    pub rack_id: Option<RackId>,
}

impl From<AddExpectedSwitch> for rpc::forge::ExpectedSwitch {
    fn from(value: AddExpectedSwitch) -> Self {
        let labels = parse_rpc_labels(value.labels.unwrap_or_default());
        let metadata = rpc::forge::Metadata {
            name: value.meta_name.unwrap_or_default(),
            description: value.meta_description.unwrap_or_default(),
            labels,
        };
        Self {
            bmc_mac_address: value.bmc_mac_address.to_string(),
            bmc_username: value.bmc_username,
            bmc_password: value.bmc_password,
            switch_serial_number: value.switch_serial_number,
            metadata: Some(metadata),
            rack_id: value.rack_id,
            nvos_username: value.nvos_username,
            nvos_password: value.nvos_password,
        }
    }
}

#[derive(Parser, Debug)]
pub struct DeleteExpectedSwitch {
    #[clap(help = "BMC MAC address of expected switch to delete.")]
    pub bmc_mac_address: MacAddress,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"switch_serial_number",
])))]
pub struct UpdateExpectedSwitch {
    #[clap(
        short = 'a',
        required = true,
        long,
        help = "BMC MAC Address of the expected switch"
    )]
    pub bmc_mac_address: MacAddress,
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
}

impl UpdateExpectedSwitch {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.switch_serial_number.is_none()
            && self.nvos_username.is_none()
            && self.nvos_password.is_none()
        {
            return Err("One of the following options must be specified: bmc-user-name and bmc-password or switch-serial-number or nvos-username and nvos-password".to_string());
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ReplaceAllExpectedSwitch {
    #[clap(short, long)]
    pub filename: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedSwitchJson {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub switch_serial_number: String,
    pub nvos_username: Option<String>,
    pub nvos_password: Option<String>,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub rack_id: Option<RackId>,
}
