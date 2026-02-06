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

use carbide_uuid::rack::RackId;
use clap::{ArgGroup, Parser};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::metadata::parse_rpc_labels;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show expected power shelf")]
    Show(ShowExpectedPowerShelfQuery),
    #[clap(about = "Add expected power shelf")]
    Add(AddExpectedPowerShelf),
    #[clap(about = "Delete expected power shelf")]
    Delete(DeleteExpectedPowerShelf),
    #[clap(about = "Update expected power shelf")]
    Update(UpdateExpectedPowerShelf),
    #[clap(about = "Replace all expected power shelves")]
    ReplaceAll(ReplaceAllExpectedPowerShelf),
    #[clap(about = "Erase all expected power shelves")]
    Erase,
}

#[derive(Parser, Debug)]
pub struct ShowExpectedPowerShelfQuery {
    #[clap(
        default_value(None),
        help = "BMC MAC address of the expected power shelf to show. Leave unset for all."
    )]
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct AddExpectedPowerShelf {
    #[clap(
        short = 'a',
        long,
        help = "BMC MAC Address of the expected power shelf"
    )]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected power shelf")]
    pub bmc_username: String,
    #[clap(short = 'p', long, help = "BMC password of the expected power shelf")]
    pub bmc_password: String,
    #[clap(short = 's', long, help = "Serial number of the expected power shelf")]
    pub shelf_serial_number: String,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Power Shelf. If empty, the Power Shelf Id will be used"
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Power Shelf"
    )]
    pub meta_description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A label that will be added as metadata for the newly created Power Shelf. The labels key and value must be separated by a : character. E.g. DATACENTER:XYZ",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long = "host_name",
        value_name = "HOST_NAME",
        help = "Host name of the power shelf",
        action = clap::ArgAction::Append
    )]
    pub host_name: Option<String>,

    #[clap(
        long = "rack_id",
        value_name = "RACK_ID",
        help = "Rack ID for this machine",
        action = clap::ArgAction::Append
    )]
    pub rack_id: Option<RackId>,

    #[clap(
        long = "ip_address",
        value_name = "IP_ADDRESS",
        help = "IP address of the power shelf",
        action = clap::ArgAction::Append
    )]
    pub ip_address: Option<String>,
}

impl From<AddExpectedPowerShelf> for rpc::forge::ExpectedPowerShelf {
    fn from(value: AddExpectedPowerShelf) -> Self {
        let labels = parse_rpc_labels(value.labels.unwrap_or_default());
        let metadata = rpc::forge::Metadata {
            name: value.meta_name.unwrap_or_default(),
            description: value.meta_description.unwrap_or_default(),
            labels,
        };
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: value.bmc_mac_address.to_string(),
            bmc_username: value.bmc_username,
            bmc_password: value.bmc_password,
            shelf_serial_number: value.shelf_serial_number,
            ip_address: value.ip_address.unwrap_or_default(),
            rack_id: value.rack_id,
            metadata: Some(metadata),
        }
    }
}

#[derive(Parser, Debug)]
pub struct DeleteExpectedPowerShelf {
    #[clap(help = "BMC MAC address of expected power shelf to delete.")]
    pub bmc_mac_address: MacAddress,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"shelf_serial_number",
])))]
pub struct UpdateExpectedPowerShelf {
    #[clap(
        short = 'a',
        required = true,
        long,
        help = "BMC MAC Address of the expected power shelf"
    )]
    pub bmc_mac_address: MacAddress,
    #[clap(
        short = 'u',
        long,
        group = "group",
        requires("bmc_password"),
        help = "BMC username of the expected power shelf"
    )]
    pub bmc_username: Option<String>,
    #[clap(
        short = 'p',
        long,
        group = "group",
        requires("bmc_username"),
        help = "BMC password of the expected power shelf"
    )]
    pub bmc_password: Option<String>,
    #[clap(
        short = 's',
        long,
        group = "group",
        help = "Chassis serial number of the expected power shelf"
    )]
    pub shelf_serial_number: Option<String>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Power Shelves. If empty, the Power Shelf Id will be used"
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Power Shelves"
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
        long = "host_name",
        value_name = "HOST_NAME",
        help = "Host name of the power shelf",
        action = clap::ArgAction::Append
    )]
    pub host_name: Option<String>,

    #[clap(
        long = "rack_id",
        value_name = "RACK_ID",
        help = "Rack ID for this power shelf",
        action = clap::ArgAction::Append
    )]
    pub rack_id: Option<RackId>,

    #[clap(
        long = "ip_address",
        value_name = "IP_ADDRESS",
        help = "IP address of the power shelf",
        action = clap::ArgAction::Append
    )]
    pub ip_address: Option<String>,
}

impl UpdateExpectedPowerShelf {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.shelf_serial_number.is_none()
        {
            return Err("One of the following options must be specified: bmc-user-name and bmc-password or shelf-serial-number".to_string());
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ReplaceAllExpectedPowerShelf {
    #[clap(short, long)]
    pub filename: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedPowerShelfJson {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub shelf_serial_number: String,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub host_name: Option<String>,
    pub rack_id: Option<RackId>,
    pub ip_address: Option<String>,
}
