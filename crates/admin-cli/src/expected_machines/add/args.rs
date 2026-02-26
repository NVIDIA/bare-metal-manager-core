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
use clap::Parser;
use mac_address::MacAddress;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use serde::{Deserialize, Serialize};
use utils::has_duplicates;

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct Args {
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
    pub rack_id: Option<RackId>,

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

impl Args {
    pub fn has_duplicate_dpu_serials(&self) -> bool {
        self.fallback_dpu_serial_numbers
            .as_ref()
            .is_some_and(has_duplicates)
    }
}

impl TryFrom<Args> for rpc::forge::ExpectedMachine {
    type Error = CarbideCliError;
    fn try_from(value: Args) -> CarbideCliResult<Self> {
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
