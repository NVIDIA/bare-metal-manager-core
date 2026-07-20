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

use carbide_utils::has_duplicates;
use carbide_uuid::rack::RackId;
use clap::Parser;
use mac_address::MacAddress;
use rpc::forge::{BmcIpAllocationType, ExpectedHostNic};
use serde::{Deserialize, Serialize};

use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::expected_machines::common::HostDpuPolicy;

/// `nico-admin-cli expected-machine add` — mirrors expected switch flags; optional
/// `--bmc-ip-address` forwards to the API static-BMC pre-allocation path.
#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(after_long_help = "\
EXAMPLES:

Add an expected machine with the required identifiers:
    $ nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1

Add a machine with metadata and a SKU:
    $ nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 \
    --meta-name MyMachine --label DATACENTER:XYZ --sku-id DGX-H100-640GB

Pre-allocate a static BMC IP (site-explorer path, like expected switches):
    $ nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 \
    --bmc-ip-address 192.0.2.20

Add a host whose DPU should be treated as a plain NIC:
    $ nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 \
    --dpu-policy nic

Retain the BMC's auto-allocated DHCP address as a static one (never expires):
    $ nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 \
    --bmc-ip-allocation retained

")]
pub struct Args {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected machine")]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected machine")]
    pub bmc_username: String,
    #[clap(
        short = 'p',
        long,
        help = "BMC password of the expected machine (optional; defaults to empty string if not provided)"
    )]
    pub bmc_password: Option<String>,
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
        help = "Host NICs as a JSON array of ExpectedHostNic objects (fields: mac_address, network_segment_type, fixed_ip, fixed_mask, fixed_gateway, primary; legacy: nic_type)",
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
    )]
    pub dpf_enabled: Option<bool>,

    #[clap(
        long = "bmc-ip-address",
        value_name = "BMC_IP_ADDRESS",
        help = "Static BMC IP (pre-allocates machine_interface for site explorer, same as expected switches)"
    )]
    pub bmc_ip_address: Option<IpAddr>,

    #[clap(
        long = "bmc-retain-credentials",
        value_name = "BMC_RETAIN_CREDENTIALS",
        help = "When true, site-explorer skips BMC password rotation and stores factory-default credentials in Vault as-is"
    )]
    pub bmc_retain_credentials: Option<bool>,

    #[clap(
        long = "dpu-policy",
        visible_alias = "dpu-mode",
        value_name = "DPU_POLICY",
        value_enum,
        help = "Per-host DPU policy. `manage` (default): inherit the site policy, which defaults to managing DPUs; `nic`: configure DPU hardware as plain NICs; `ignore`: do not configure or attach DPU hardware. Unset defers to the site-wide `[site_explorer] dpu_policy` setting. The previous `use-as-nic` value remains accepted as an alias. The legacy `--dpu-mode` flag also remains accepted: `dpu-mode` maps to `manage`, `nic-mode` to `nic`, and `no-dpu` to `ignore`."
    )]
    pub dpu_policy: Option<HostDpuPolicy>,

    #[clap(
        long = "bmc-ip-allocation",
        value_name = "BMC_IP_ALLOCATION",
        value_enum,
        help = "Per-host control over how this BMC's IP is assigned and retained. `auto` (default): infer from `--bmc-ip-address` -- a configured address is `fixed`, no address is `retained`; `dynamic`: a normal DHCP lease that may expire and change; `fixed`: the operator-specified `--bmc-ip-address` (static); `retained`: an auto-allocated address pinned as static (never expires). Unset defers to the server default (`auto`)."
    )]
    pub bmc_ip_allocation: Option<BmcIpAllocationType>,

    #[clap(
        long = "disable-lockdown",
        value_name = "DISABLE_LOCKDOWN",
        help = "If true, do not lock down the server as part of lifecycle management within the state machine. If unset or false, preserve the default behavior of locking down the server after configuring the BIOS."
    )]
    pub disable_lockdown: Option<bool>,
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
            .map(|s| serde_json::from_str::<Vec<ExpectedHostNic>>(&s))
            .transpose()?
            .unwrap_or_default();

        Ok(rpc::forge::ExpectedMachine {
            bmc_mac_address: value.bmc_mac_address.to_string(),
            bmc_username: value.bmc_username,
            bmc_password: value.bmc_password.unwrap_or_default(),
            chassis_serial_number: value.chassis_serial_number,
            fallback_dpu_serial_numbers: value.fallback_dpu_serial_numbers.unwrap_or_default(),
            metadata: Some(metadata),
            sku_id: value.sku_id,
            id: value.id.map(Into::into),
            host_nics,
            rack_id: value.rack_id,
            default_pause_ingestion_and_poweron: value.default_pause_ingestion_and_poweron,
            #[allow(deprecated)]
            dpf_enabled: value.dpf_enabled.unwrap_or(true),
            is_dpf_enabled: value.dpf_enabled,
            bmc_ip_address: value.bmc_ip_address.map(|ip| ip.to_string()),
            bmc_retain_credentials: value.bmc_retain_credentials,
            dpu_mode: value
                .dpu_policy
                .map(|policy| rpc::forge::DpuMode::from(policy) as i32),
            bmc_ip_allocation: value.bmc_ip_allocation.map(|m| m as i32),
            host_lifecycle_profile: value.disable_lockdown.map(|dl| {
                rpc::forge::HostLifecycleProfile {
                    disable_lockdown: Some(dl),
                }
            }),
        })
    }
}
