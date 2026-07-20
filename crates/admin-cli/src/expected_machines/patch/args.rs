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

use carbide_utils::has_duplicates;
use carbide_uuid::rack::RackId;
use clap::{ArgGroup, Parser};
use mac_address::MacAddress;
use rpc::forge::BmcIpAllocationType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::CarbideCliError;
use crate::expected_machines::common::HostDpuPolicy;

/// Patch expected machine (partial update, preserves unprovided fields).
///
/// Only the fields provided in the command will be updated. All other fields remain unchanged.
/// When `--bmc-ip-address` is used, the merged RPC update runs the same static BMC interface logic
/// as a full `update_expected_machine` call.
///
/// Examples:
///   # Update only SKU, preserve all other fields including metadata
///   nico-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f --sku-id new_sku
///
///   # Update only labels, preserve name and description
///   nico-admin-cli expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f \
///     --sku-id sku123 --label env:prod --label team:platform
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(verbatim_doc_comment)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"chassis_serial_number",
"fallback_dpu_serial_numbers",
"sku_id",
"bmc_ip_address",
"dpu_policy",
"bmc_ip_allocation",
"dpf_enabled",
"host_nics",
])))]
#[command(after_long_help = "\
EXAMPLES:

Patch only the SKU of a machine, selected by BMC MAC address:
    $ nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 \
    --sku-id DGX-H100-640GB

Patch a machine selected by id:
    $ nico-admin-cli expected-machine patch --id 12345678-1234-5678-90ab-cdef01234567 \
    --sku-id DGX-H100-640GB

Rotate the BMC credentials (username and password must be set together):
    $ nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-username admin --bmc-password mynewpassword

Change the per-host DPU policy:
    $ nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 \
    --dpu-policy ignore

Retain the BMC's auto-allocated DHCP address as a static one (never expires):
    $ nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 \
    --bmc-ip-allocation retained

")]
pub struct Args {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected machine")]
    pub bmc_mac_address: Option<MacAddress>,

    #[clap(long = "id", help = "ID (UUID) of the expected machine to patch.")]
    #[serde(skip)]
    pub id: Option<Uuid>,
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
        group = "group",
        help = "Static BMC IP (updates pre-allocated machine_interface when safe, same as expected switches)"
    )]
    pub bmc_ip_address: Option<String>,

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
        group = "group",
        help = "Per-host DPU policy. `manage`: inherit the site policy, which defaults to managing DPUs; `nic`: configure DPU hardware as plain NICs; `ignore`: do not configure or attach DPU hardware. Unset preserves the existing per-host value. The previous `use-as-nic` value remains accepted as an alias. The legacy `--dpu-mode` flag also remains accepted: `dpu-mode` maps to `manage`, `nic-mode` to `nic`, and `no-dpu` to `ignore`."
    )]
    pub dpu_policy: Option<HostDpuPolicy>,

    #[clap(
        long = "bmc-ip-allocation",
        value_name = "BMC_IP_ALLOCATION",
        value_enum,
        group = "group",
        help = "Per-host control over how this BMC's IP is assigned and retained. `auto` (default): infer from `--bmc-ip-address` -- a configured address is `fixed`, no address is `retained`; `dynamic`: a normal DHCP lease that may expire and change; `fixed`: the operator-specified `--bmc-ip-address` (static); `retained`: an auto-allocated address pinned as static (never expires). Unset preserves the existing per-host value."
    )]
    pub bmc_ip_allocation: Option<BmcIpAllocationType>,

    #[clap(
        long = "host_nics",
        value_name = "HOST_NICS",
        group = "group",
        help = "Host NICs as a JSON array of ExpectedHostNic objects (fields: mac_address, network_segment_type, fixed_ip, fixed_mask, fixed_gateway, primary; legacy: nic_type). Replaces the machine's full host NIC list."
    )]
    pub host_nics: Option<String>,

    #[clap(
        long = "disable-lockdown",
        value_name = "DISABLE_LOCKDOWN",
        help = "If true, do not lock down the server as part of lifecycle management within the state machine. If unset or false, preserve the default behavior of locking down the server after configuring the BIOS."
    )]
    pub disable_lockdown: Option<bool>,
}

impl Args {
    pub fn validate(&self) -> Result<(), CarbideCliError> {
        match (&self.bmc_mac_address, &self.id) {
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
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.chassis_serial_number.is_none()
            && self.fallback_dpu_serial_numbers.is_none()
            && self.sku_id.is_none()
            && self.rack_id.is_none()
            && self.dpf_enabled.is_none()
            && self.bmc_ip_address.is_none()
            && self.dpu_policy.is_none()
            && self.bmc_ip_allocation.is_none()
            && self.host_nics.is_none()
        {
            return Err(CarbideCliError::GenericError("One of the following options must be specified: bmc-username and bmc-password or chassis-serial-number or fallback-dpu-serial-number or bmc-ip-address or dpu-policy or bmc-ip-allocation or dpf-enabled or host_nics".to_string()));
        }
        if self
            .fallback_dpu_serial_numbers
            .as_ref()
            .is_some_and(has_duplicates)
        {
            return Err(CarbideCliError::GenericError(
                "Duplicate dpu serial numbers found".to_string(),
            ));
        }
        Ok(())
    }
}
