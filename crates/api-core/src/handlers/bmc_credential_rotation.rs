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
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

/// Operator force-converge escape hatch: record (or clear) a request to
/// immediately rotate a machine's BMC credentials, bypassing the passive
/// site-wide gate and the device's backoff quarantine. The target BMC is
/// addressed by the owning machine's id, its BMC MAC, or both (see
/// [`resolve_target_machine`]); the flag is written on that machine's row. The
/// machine state controller consumes the request on its next sweep; this
/// handler only writes the flag (it performs no Redfish work itself).
pub(crate) async fn trigger_bmc_credential_rotation(
    api: &Api,
    request: Request<rpc::BmcCredentialRotationRequest>,
) -> Result<Response<()>, Status> {
    use ::rpc::forge::bmc_credential_rotation_request::Mode;

    log_request_data(&request);
    let req = request.into_inner();
    let mode = req.mode();

    let mut txn = api.txn_begin().await?;

    let machine_id = resolve_target_machine(&mut txn, req.machine_id, req.bmc_mac).await?;

    match mode {
        Mode::Set => {
            db::machine::set_bmc_credential_rotation_requested(&mut txn, machine_id).await?;
        }
        Mode::Clear => {
            db::machine::clear_bmc_credential_rotation_requested(&mut txn, machine_id).await?;
        }
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

/// Resolve the machine that owns the target BMC from an operator request that
/// may carry the machine id, the BMC MAC, or both. A machine (host or DPU) has
/// exactly one BMC, so either identifier alone uniquely names the device. When
/// both are supplied they must agree, which lets an operator double-check that a
/// MAC they pulled from an alert really is the BMC of the machine they mean.
async fn resolve_target_machine(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    bmc_mac: Option<String>,
) -> Result<MachineId, CarbideError> {
    let bmc_mac = bmc_mac
        .map(|mac| {
            mac.parse::<MacAddress>().map_err(|_| {
                CarbideError::InvalidArgument(format!("bmc_mac '{mac}' is not a valid MAC address"))
            })
        })
        .transpose()?;

    let resolved = match (machine_id, bmc_mac) {
        (machine_id, Some(mac)) => {
            let mac_machine_id = db::machine_topology::find_machine_id_by_bmc_mac(txn, mac)
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "BMC",
                    id: mac.to_string(),
                })?;
            if let Some(machine_id) = machine_id
                && machine_id != mac_machine_id
            {
                return Err(CarbideError::InvalidArgument(format!(
                    "bmc {mac} belongs to machine {mac_machine_id}, not the requested machine {machine_id}"
                )));
            }
            mac_machine_id
        }
        (Some(machine_id), None) => machine_id,
        (None, None) => {
            return Err(CarbideError::InvalidArgument(
                "either machine_id or bmc_mac must be provided".to_string(),
            ));
        }
    };

    log_machine_id(&resolved);
    Ok(resolved)
}
