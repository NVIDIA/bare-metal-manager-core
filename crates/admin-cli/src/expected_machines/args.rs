/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;

use clap::{ArgGroup, Parser};
use mac_address::MacAddress;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use serde::{Deserialize, Serialize};
use utils::has_duplicates;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show expected machine data")]
    Show(ShowExpectedMachineQuery),
    #[clap(about = "Add expected machine")]
    Add(ExpectedMachine),
    #[clap(about = "Delete expected machine")]
    Delete(DeleteExpectedMachine),
    /// Patch expected machine (partial update, preserves unprovided fields).
    ///
    /// Only the fields provided in the command will be updated. All other fields remain unchanged.
    ///
    /// Examples:
    ///   # Update only SKU, preserve all other fields including metadata
    ///   forge-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f --sku-id new_sku
    ///
    ///   # Update only labels, preserve name and description
    ///   forge-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f \
    ///     --sku-id sku123 --label env:prod --label team:platform
    #[clap(verbatim_doc_comment)]
    Patch(PatchExpectedMachine),
    /// Update expected machine from JSON file (full replacement, consistent with API).
    ///
    /// All fields from the JSON file will completely replace the existing record.
    /// This allows clearing metadata fields by providing empty values.
    ///
    /// Example json file:
    ///    {
    ///        "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///        "bmc_username": "user",
    ///        "bmc_password": "pass",
    ///        "chassis_serial_number": "sample_serial-1",
    ///        "fallback_dpu_serial_numbers": ["MT020100000003"],
    ///        "metadata": {
    ///            "name": "MyMachine",
    ///            "description": "My Machine",
    ///            "labels": [{"key": "ABC", "value": "DEF"}]
    ///        },
    ///        "sku_id": "sku_id_123"
    ///    }
    ///
    /// Usage:
    ///   forge-admin-cli expected-machine update --filename machine.json
    #[clap(verbatim_doc_comment)]
    Update(UpdateExpectedMachine),
    /// Replace all entries in the expected machines table with the entries from an inputted json file.
    ///
    /// Example json file:
    ///    {
    ///        "expected_machines":
    ///        [
    ///            {
    ///                "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-1"
    ///            },
    ///            {
    ///                "bmc_mac_address": "2a:2b:2c:2d:2e:2f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-2",
    ///                "fallback_dpu_serial_numbers": ["MT020100000003"],
    ///                "metadata": {
    ///                    "name": "MyMachine",
    ///                    "description": "My Machine",
    ///                    "labels": [{"key": "ABC", "value": "DEF"}]
    ///                }
    ///            }
    ///        ]
    ///    }
    #[clap(verbatim_doc_comment)]
    ReplaceAll(ExpectedMachineReplaceAllRequest),
    #[clap(about = "Erase all expected machines")]
    Erase,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct ExpectedMachine {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected machine")]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected machine")]
    pub bmc_username: String,
    #[clap(short = 'p', long, help = "BMC password of the expected machine")]
    pub bmc_password: String,
    #[clap(
        short = 's',
        long,
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: String,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Machines. If empty, the MachineId will be used"
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
        long = "sku-id",
        value_name = "SKU_ID",
        help = "A SKU ID that will be added for the newly created Machine."
    )]
    pub sku_id: Option<String>,

    #[clap(
        long = "id",
        value_name = "UUID",
        help = "Optional unique ID to assign to the ExpectedMachine on create"
    )]
    pub id: Option<String>,

    #[clap(
        long = "host_nics",
        value_name = "HOST_NICS",
        help = "Host NICs MAC addresses as JSON",
        action = clap::ArgAction::Append
    )]
    pub host_nics: Option<String>,

    #[clap(
        long = "rack_id",
        value_name = "RACK_ID",
        help = "Rack ID for this machine",
        action = clap::ArgAction::Append
    )]
    pub rack_id: Option<String>,

    #[clap(
        long = "default_pause_ingestion_and_poweron",
        value_name = "DEFAULT_PAUSE_INGESTION_AND_POWERON",
        help = "Optional flag to pause machine's ingestion and power on. False - don't pause, true - will pause it. The actual mutable state is stored in explored_endpoints."
    )]
    pub default_pause_ingestion_and_poweron: Option<bool>,

    #[clap(
        long,
        action = clap::ArgAction::Set,
        value_name = "DPF_ENABLED",
        help = "DPF enable/disable for this machine. Default is updated as true.",
        default_value_t = true
    )]
    pub dpf_enabled: bool,
}

impl ExpectedMachine {
    pub fn has_duplicate_dpu_serials(&self) -> bool {
        self.fallback_dpu_serial_numbers
            .as_ref()
            .is_some_and(has_duplicates)
    }
}

impl TryFrom<ExpectedMachine> for rpc::forge::ExpectedMachine {
    type Error = CarbideCliError;
    fn try_from(value: ExpectedMachine) -> CarbideCliResult<Self> {
        let labels = crate::metadata::parse_rpc_labels(value.labels.unwrap_or_default());
        let metadata = rpc::Metadata {
            name: value.meta_name.unwrap_or_default(),
            description: value.meta_description.unwrap_or_default(),
            labels,
        };
        let host_nics = value
            .host_nics
            .map(|s| serde_json::from_str::<Vec<MacAddress>>(&s))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|mac| rpc::forge::ExpectedHostNic {
                mac_address: mac.to_string(),
                nic_type: None,
                fixed_ip: None,
                fixed_mask: None,
                fixed_gateway: None,
            })
            .collect();

        Ok(rpc::forge::ExpectedMachine {
            bmc_mac_address: value.bmc_mac_address.to_string(),
            bmc_username: value.bmc_username,
            bmc_password: value.bmc_password,
            chassis_serial_number: value.chassis_serial_number,
            fallback_dpu_serial_numbers: value.fallback_dpu_serial_numbers.unwrap_or_default(),
            metadata: Some(metadata),
            sku_id: value.sku_id,
            id: value.id.map(Into::into),
            host_nics,
            rack_id: value.rack_id,
            default_pause_ingestion_and_poweron: value.default_pause_ingestion_and_poweron,
            dpf_enabled: value.dpf_enabled,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedMachineJson {
    #[serde(default)]
    pub id: Option<String>,
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub chassis_serial_number: String,
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub sku_id: Option<String>,
    #[serde(default)]
    pub host_nics: Vec<rpc::forge::ExpectedHostNic>,
    pub rack_id: Option<String>,
    pub default_pause_ingestion_and_poweron: Option<bool>,
    pub dpf_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct _ExpectedMachineMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub labels: HashMap<String, Option<String>>,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"chassis_serial_number",
"fallback_dpu_serial_numbers",
"sku_id",
])))]
pub struct PatchExpectedMachine {
    #[clap(
        short = 'a',
        required = true,
        long,
        help = "BMC MAC Address of the expected machine"
    )]
    pub bmc_mac_address: MacAddress,
    #[clap(
        short = 'u',
        long,
        group = "group",
        requires("bmc_password"),
        help = "BMC username of the expected machine"
    )]
    pub bmc_username: Option<String>,
    #[clap(
        short = 'p',
        long,
        group = "group",
        requires("bmc_username"),
        help = "BMC password of the expected machine"
    )]
    pub bmc_password: Option<String>,
    #[clap(
        short = 's',
        long,
        group = "group",
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: Option<String>,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        group = "group",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Machines. If empty, the MachineId will be used"
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
        long,
        value_name = "SKU_ID",
        group = "group",
        help = "A SKU ID that will be added for the newly created Machine."
    )]
    pub sku_id: Option<String>,

    #[clap(
        long,
        value_name = "RACK_ID",
        group = "group",
        help = "A RACK ID that will be added for the newly created Machine."
    )]
    pub rack_id: Option<String>,

    #[clap(
        long = "default_pause_ingestion_and_poweron",
        value_name = "DEFAULT_PAUSE_INGESTION_AND_POWERON",
        help = "Optional flag to pause machine's ingestion and power on. False - don't pause, true - will pause it. The actual mutable state is stored in explored_endpoints."
    )]
    pub default_pause_ingestion_and_poweron: Option<bool>,

    #[clap(
        long,
        action = clap::ArgAction::Set,
        value_name = "DPF_ENABLED",
        help = "DPF enable/disable for this machine. Default is updated as true.",
        default_value_t = true
    )]
    pub dpf_enabled: bool,
}

impl PatchExpectedMachine {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.chassis_serial_number.is_none()
            && self.fallback_dpu_serial_numbers.is_none()
            && self.sku_id.is_none()
            && self.rack_id.is_none()
        {
            return Err("One of the following options must be specified: bmc-user-name and bmc-password or chassis-serial-number or fallback-dpu-serial-number".to_string());
        }
        if self
            .fallback_dpu_serial_numbers
            .as_ref()
            .is_some_and(has_duplicates)
        {
            return Err("Duplicate dpu serial numbers found".to_string());
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DeleteExpectedMachine {
    #[clap(help = "BMC MAC address of the expected machine to delete.")]
    pub bmc_mac_address: MacAddress,
}

#[derive(Parser, Debug)]
pub struct UpdateExpectedMachine {
    #[clap(
        short,
        long,
        help = "Path to JSON file containing the expected machine data"
    )]
    pub filename: String,
}

#[derive(Parser, Debug)]
pub struct ShowExpectedMachineQuery {
    #[clap(
        default_value(None),
        help = "BMC MAC address of the expected machine to show. Leave unset for all."
    )]
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct ExpectedMachineReplaceAllRequest {
    #[clap(short, long)]
    pub filename: String,
}
