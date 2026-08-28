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
use ::rpc::forge::nic_lockdown_credential_rotation_request::Mode;
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

/// Operator force-converge escape hatch for SuperNIC lockdown keys: record (or
/// clear) a request to rekey a host's SuperNICs to the site-wide `lockdown_ikm`
/// target, bypassing the passive site-wide gate and each card's backoff
/// quarantine. The target host is addressed by its machine id, by one of its
/// SuperNIC (SVPC) NIC MACs, or a combination (see [`resolve_target`]); the
/// one-shot flag is written on that host's `machines` row. The host's state
/// controller consumes the request on its next *idle* sweep -- a lockdown rekey
/// never runs under active tenancy, so a request against a host that currently
/// has an instance is recorded and honored on its next idle window, not
/// immediately. This handler only writes the flag (it performs no rekey itself).
pub(crate) async fn trigger_nic_lockdown_credential_rotation(
    api: &Api,
    request: Request<rpc::NicLockdownCredentialRotationRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let mode = req.mode();

    let mut txn = api.txn_begin().await?;

    let machine_id = resolve_target(&mut txn, req.machine_id, req.nic_mac).await?;

    match mode {
        Mode::Set => {
            db::machine::set_lockdown_ikm_credential_rotation_requested(&mut txn, machine_id)
                .await?;
        }
        Mode::Clear => {
            db::machine::clear_lockdown_ikm_credential_rotation_requested(&mut txn, machine_id)
                .await?;
        }
        // An omitted `mode` decodes as `Unspecified`; reject it rather than let a
        // request fall through to an action it did not name.
        Mode::Unspecified => {
            return Err(
                CarbideError::InvalidArgument("mode must be set or clear".to_string()).into(),
            );
        }
    };

    txn.commit().await?;

    Ok(Response::new(()))
}

/// Resolve the host machine that owns the target SuperNICs from an operator
/// request carrying a `machine_id`, a NIC MAC, or both. The rekey cycle is
/// host-level, so any single identifier names the host. A NIC MAC is resolved to
/// its owning host via the `dpa_interfaces` table. When a MAC is supplied
/// alongside a `machine_id` they must agree, which lets an operator double-check
/// that a NIC MAC pulled from an alert really belongs to the host they mean.
async fn resolve_target(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    nic_mac: Option<String>,
) -> Result<MachineId, CarbideError> {
    let nic_mac = nic_mac
        .map(|mac| {
            mac.parse::<MacAddress>().map_err(|_| {
                CarbideError::InvalidArgument(format!("nic_mac '{mac}' is not a valid MAC address"))
            })
        })
        .transpose()?;

    // A NIC MAC uniquely names one SuperNIC (SVPC) interface, which belongs to
    // exactly one host machine; resolve which host owns it.
    let mac_machine_id = match nic_mac {
        Some(mac) => {
            let interfaces = db::dpa_interface::find_by_mac_addr(&mut *txn, &mac).await?;
            let interface = interfaces.into_iter().next().ok_or(CarbideError::NotFoundError {
                kind: "SuperNIC",
                id: mac.to_string(),
            })?;
            Some(interface.machine_id)
        }
        None => None,
    };

    let machine_id = match (machine_id, mac_machine_id) {
        (Some(id), None) => id,
        (Some(id), Some(mac_id)) => {
            if id != mac_id {
                return Err(CarbideError::InvalidArgument(format!(
                    "nic {} belongs to machine {mac_id}, not the requested machine {id}",
                    nic_mac.expect("a mac target implies a parsed mac")
                )));
            }
            id
        }
        (None, Some(mac_id)) => mac_id,
        (None, None) => {
            return Err(CarbideError::InvalidArgument(
                "one of machine_id or nic_mac must be provided".to_string(),
            ));
        }
    };

    log_machine_id(&machine_id);
    Ok(machine_id)
}
