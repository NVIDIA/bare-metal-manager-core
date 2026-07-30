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

use ::rpc::forge::BmcCredentialRotationRequest;
use ::rpc::forge::bmc_credential_rotation_request::{DeviceId, Mode};
use carbide_uuid::machine::MachineId;
use carbide_uuid::switch::SwitchId;
use clap::Parser;
use mac_address::MacAddress;

/// Build the request's `device_id` oneof from the mutually-exclusive `--id` /
/// `--switch-id` selectors (clap enforces at most one is present). Returns
/// `None` when the target is addressed by `--bmc-mac` alone.
fn device_id(id: Option<MachineId>, switch_id: Option<SwitchId>) -> Option<DeviceId> {
    match (id, switch_id) {
        (Some(id), _) => Some(DeviceId::MachineId(id)),
        (None, Some(switch_id)) => Some(DeviceId::SwitchId(switch_id)),
        (None, None) => None,
    }
}

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Force an immediate credential rotation by machine ID:
    $ nico-admin-cli credential force-bmc set --id 12345678-1234-5678-90ab-cdef01234567

Force a switch BMC by switch ID:
    $ nico-admin-cli credential force-bmc set --switch-id 12345678-1234-5678-90ab-cdef01234567

Force it by BMC MAC instead (machine or switch):
    $ nico-admin-cli credential force-bmc set --bmc-mac 00:11:22:33:44:55

Clear a pending force-converge request:
    $ nico-admin-cli credential force-bmc clear --id 12345678-1234-5678-90ab-cdef01234567

")]
pub enum Args {
    #[clap(
        about = "Request an immediate credential rotation of a device's BMC (machine or switch)."
    )]
    Set(ForceSet),
    #[clap(about = "Clear a pending BMC force-converge request for a device (machine or switch).")]
    Clear(ForceClear),
}

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Force-converge a machine BMC now by machine ID:
    $ nico-admin-cli credential force-bmc set --id 12345678-1234-5678-90ab-cdef01234567

Force-converge a switch BMC now by switch ID:
    $ nico-admin-cli credential force-bmc set --switch-id 12345678-1234-5678-90ab-cdef01234567

Force-converge a BMC now by BMC MAC (machine or switch):
    $ nico-admin-cli credential force-bmc set --bmc-mac 00:11:22:33:44:55

")]
pub struct ForceSet {
    #[clap(
        short,
        long,
        required_unless_present_any = ["bmc_mac", "switch_id"],
        conflicts_with = "switch_id",
        help = "Machine ID that owns the BMC (a host machine or a DPU machine). \
                Provide this, --switch-id, or --bmc-mac."
    )]
    pub id: Option<MachineId>,

    #[clap(
        long,
        help = "Switch ID that owns the BMC. Provide this, --id, or --bmc-mac."
    )]
    pub switch_id: Option<SwitchId>,

    #[clap(
        long,
        help = "MAC of the BMC to target (machine or switch). Provide this, --id, \
                or --switch-id; if an id is also given they must identify the same device."
    )]
    pub bmc_mac: Option<MacAddress>,
}

impl From<ForceSet> for BmcCredentialRotationRequest {
    fn from(args: ForceSet) -> Self {
        Self {
            device_id: device_id(args.id, args.switch_id),
            mode: Mode::Set as i32,
            bmc_mac: args.bmc_mac.map(|mac| mac.to_string()),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Clear a pending force-converge request by machine ID:
    $ nico-admin-cli credential force-bmc clear --id 12345678-1234-5678-90ab-cdef01234567

Clear a pending force-converge request by switch ID:
    $ nico-admin-cli credential force-bmc clear --switch-id 12345678-1234-5678-90ab-cdef01234567

Clear a pending force-converge request by BMC MAC:
    $ nico-admin-cli credential force-bmc clear --bmc-mac 00:11:22:33:44:55

")]
pub struct ForceClear {
    #[clap(
        short,
        long,
        required_unless_present_any = ["bmc_mac", "switch_id"],
        conflicts_with = "switch_id",
        help = "Machine ID whose pending BMC force-converge request should be cleared. \
                Provide this, --switch-id, or --bmc-mac."
    )]
    pub id: Option<MachineId>,

    #[clap(
        long,
        help = "Switch ID whose pending BMC force-converge request should be cleared. \
                Provide this, --id, or --bmc-mac."
    )]
    pub switch_id: Option<SwitchId>,

    #[clap(long, help = "MAC of the BMC whose pending request should be cleared.")]
    pub bmc_mac: Option<MacAddress>,
}

impl From<ForceClear> for BmcCredentialRotationRequest {
    fn from(args: ForceClear) -> Self {
        Self {
            device_id: device_id(args.id, args.switch_id),
            mode: Mode::Clear as i32,
            bmc_mac: args.bmc_mac.map(|mac| mac.to_string()),
        }
    }
}
