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
use ::rpc::forge as rpc;
use ::rpc::forge::bmc_credential_rotation_request::Mode;
use carbide_uuid::device::DeviceId;
use mac_address::MacAddress;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

/// Operator force-converge escape hatch: record (or clear) a request to
/// immediately rotate a device's BMC credentials, bypassing the passive
/// site-wide gate and the device's backoff quarantine. The target BMC is
/// addressed by the owning device's id (machine or switch), its BMC MAC, or a
/// combination (see [`resolve_target`]); the flag is written on that device's
/// row. The owning device's state controller consumes the request on its next
/// sweep; this handler only writes the flag (it performs no Redfish work
/// itself).
pub(crate) async fn trigger_bmc_credential_rotation(
    api: &Api,
    request: Request<rpc::BmcCredentialRotationRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let mode = req.mode();
    let device_id = reject_unsupported_device_id(req.device_id)?;

    let mut txn = api.txn_begin().await?;

    let target = resolve_target(&mut txn, device_id, req.bmc_mac).await?;

    match mode {
        Mode::Set => match target {
            DeviceId::Machine(id) => {
                db::machine::set_bmc_credential_rotation_requested(&mut txn, id).await?;
            }
            DeviceId::Switch(id) => {
                db::switch::set_bmc_credential_rotation_requested(&mut txn, id).await?;
            }
            DeviceId::PowerShelf(_) => {
                return Err(CarbideError::InvalidArgument(
                    "power shelf BMC credential rotation is not yet supported".to_string(),
                )
                .into());
            }
        },
        Mode::Clear => match target {
            DeviceId::Machine(id) => {
                db::machine::clear_bmc_credential_rotation_requested(&mut txn, id).await?;
            }
            DeviceId::Switch(id) => {
                db::switch::clear_bmc_credential_rotation_requested(&mut txn, id).await?;
            }
            DeviceId::PowerShelf(_) => {
                return Err(CarbideError::InvalidArgument(
                    "power shelf BMC credential rotation is not yet supported".to_string(),
                )
                .into());
            }
        },
        // An omitted `mode` decodes as `Unspecified`; reject it rather than let
        // a request fall through to an action it did not name.
        Mode::Unspecified => {
            return Err(
                CarbideError::InvalidArgument("mode must be set or clear".to_string()).into(),
            );
        }
    };

    txn.commit().await?;

    Ok(Response::new(()))
}

fn reject_unsupported_device_id(
    device_id: Option<DeviceId>,
) -> Result<Option<DeviceId>, CarbideError> {
    match device_id {
        Some(DeviceId::PowerShelf(_)) => Err(CarbideError::InvalidArgument(
            "power shelf BMC credential rotation is not yet supported".to_string(),
        )),
        device_id => Ok(device_id),
    }
}

/// Resolve the device that owns the target BMC from an operator request that
/// carries a `device_id`, a BMC MAC, or both. A supported device has exactly one
/// BMC, so any single identifier uniquely names it. When a MAC is supplied
/// alongside a `device_id` they must agree, which lets an operator double-check
/// that a MAC pulled from an alert really is the BMC of the device they mean.
/// Power shelf IDs are part of the shared type for forward compatibility but
/// are rejected until power shelf BMC rotation is implemented.
async fn resolve_target(
    txn: &mut PgConnection,
    device_id: Option<DeviceId>,
    bmc_mac: Option<String>,
) -> Result<DeviceId, CarbideError> {
    let bmc_mac = bmc_mac
        .map(|mac| {
            mac.parse::<MacAddress>().map_err(|_| {
                CarbideError::InvalidArgument(format!("bmc_mac '{mac}' is not a valid MAC address"))
            })
        })
        .transpose()?;

    // A MAC uniquely names one BMC device; resolve which device kind owns it.
    let mac_target = match bmc_mac {
        Some(mac) => Some(resolve_mac_owner(txn, mac).await?),
        None => None,
    };

    let target = match (device_id, mac_target) {
        // Explicit machine id, optionally cross-checked against the MAC's owner.
        (Some(DeviceId::Machine(machine_id)), None) => DeviceId::Machine(machine_id),
        (Some(DeviceId::Machine(machine_id)), Some(DeviceId::Machine(mac_machine_id))) => {
            if machine_id != mac_machine_id {
                return Err(CarbideError::InvalidArgument(format!(
                    "bmc {} belongs to machine {mac_machine_id}, not the requested machine {machine_id}",
                    bmc_mac.expect("a mac target implies a parsed mac")
                )));
            }
            DeviceId::Machine(machine_id)
        }
        (Some(DeviceId::Machine(machine_id)), Some(DeviceId::Switch(switch_id))) => {
            return Err(CarbideError::InvalidArgument(format!(
                "bmc {} belongs to switch {switch_id}, not the requested machine {machine_id}",
                bmc_mac.expect("a mac target implies a parsed mac")
            )));
        }
        // Explicit switch id, optionally cross-checked against the MAC's owner.
        (Some(DeviceId::Switch(switch_id)), None) => DeviceId::Switch(switch_id),
        (Some(DeviceId::Switch(switch_id)), Some(DeviceId::Switch(mac_switch_id))) => {
            if switch_id != mac_switch_id {
                return Err(CarbideError::InvalidArgument(format!(
                    "bmc {} belongs to switch {mac_switch_id}, not the requested switch {switch_id}",
                    bmc_mac.expect("a mac target implies a parsed mac")
                )));
            }
            DeviceId::Switch(switch_id)
        }
        (Some(DeviceId::Switch(switch_id)), Some(DeviceId::Machine(machine_id))) => {
            return Err(CarbideError::InvalidArgument(format!(
                "bmc {} belongs to machine {machine_id}, not the requested switch {switch_id}",
                bmc_mac.expect("a mac target implies a parsed mac")
            )));
        }
        // MAC only: the owner the MAC resolved to.
        (None, Some(target)) => target,
        (Some(DeviceId::PowerShelf(_)), _) | (_, Some(DeviceId::PowerShelf(_))) => {
            return Err(CarbideError::InvalidArgument(
                "power shelf BMC credential rotation is not yet supported".to_string(),
            ));
        }
        (None, None) => {
            return Err(CarbideError::InvalidArgument(
                "one of device_id or bmc_mac must be provided".to_string(),
            ));
        }
    };

    if let DeviceId::Machine(machine_id) = &target {
        log_machine_id(machine_id);
    }
    Ok(target)
}

/// Resolve which device kind owns a BMC MAC. A physical BMC MAC lives on exactly
/// one interface row, keyed to a machine *or* a switch, so try the machine
/// resolver first (its `machine_id`-keyed BMC interface) then the switch one.
async fn resolve_mac_owner(
    txn: &mut PgConnection,
    mac: MacAddress,
) -> Result<DeviceId, CarbideError> {
    if let Some(machine_id) = db::machine_topology::find_machine_id_by_bmc_mac(txn, mac).await? {
        return Ok(DeviceId::Machine(machine_id));
    }
    if let Some(switch_id) = db::switch::find_switch_id_by_bmc_mac(txn, mac).await? {
        return Ok(DeviceId::Switch(switch_id));
    }
    Err(CarbideError::NotFoundError {
        kind: "BMC",
        id: mac.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;
    use carbide_uuid::machine::MachineId;
    use carbide_uuid::power_shelf::PowerShelfId;
    use carbide_uuid::switch::SwitchId;

    use super::*;

    const MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
    const SWITCH_ID: &str = "sw100nt038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
    const POWER_SHELF_ID: &str = "ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

    #[test]
    fn rejects_only_power_shelf_device_ids() {
        let machine_id = MachineId::from_str(MACHINE_ID).unwrap();
        let switch_id = SwitchId::from_str(SWITCH_ID).unwrap();
        let power_shelf_id = PowerShelfId::from_str(POWER_SHELF_ID).unwrap();

        scenarios!(
            run = |device_id| reject_unsupported_device_id(device_id).map_err(drop);
            "supported targets" {
                Some(DeviceId::Machine(machine_id)) => Yields(Some(DeviceId::Machine(machine_id))),
                Some(DeviceId::Switch(switch_id)) => Yields(Some(DeviceId::Switch(switch_id))),
                None => Yields(None),
            }

            "future target" {
                Some(DeviceId::PowerShelf(power_shelf_id)) => Fails,
            }
        );
    }
}
