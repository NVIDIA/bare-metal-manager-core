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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge::{DpuReprovisioningRequest, UpdateInitiator};
use carbide_uuid::machine::{MachineId, MachineType};
use prettytable::{Table, row};

use super::args::Args;
use crate::machine::{HealthOverrideTemplates, get_health_report};
use crate::rpc::ApiClient;

pub async fn reprovision(api_client: &ApiClient, reprov: Args) -> CarbideCliResult<()> {
    match reprov {
        Args::Set(data) => {
            trigger_reprovisioning(
                data.id,
                Mode::Set,
                data.update_firmware,
                api_client,
                data.update_message,
            )
            .await
        }
        Args::Clear(data) => {
            trigger_reprovisioning(data.id, Mode::Clear, data.update_firmware, api_client, None)
                .await
        }
        Args::List => list_dpus_pending(api_client).await,
        Args::Restart(data) => {
            trigger_reprovisioning(
                data.id,
                Mode::Restart,
                data.update_firmware,
                api_client,
                None,
            )
            .await
        }
    }
}

pub async fn trigger_reprovisioning(
    id: MachineId,
    mode: Mode,
    update_firmware: bool,
    api_client: &ApiClient,
    update_message: Option<String>,
) -> CarbideCliResult<()> {
    if let (Mode::Set, Some(update_message)) = (mode, update_message) {
        // Set a HostUpdateInProgress health override on the Host
        let host_id = match id.machine_type() {
            MachineType::Host => Some(id),
            MachineType::Dpu => {
                let machine = api_client
                    .get_machines_by_ids(&[id])
                    .await?
                    .machines
                    .into_iter()
                    .next();

                if let Some(host_id) = machine.map(|x| x.associated_host_machine_id) {
                    host_id
                } else {
                    return Err(CarbideCliError::GenericError(format!(
                        "Could not find host attached with dpu {id}",
                    )));
                }
            }
            _ => {
                return Err(CarbideCliError::GenericError(format!(
                    "Invalid machine ID for reprevisioning, only Hosts and DPUs are supported: {update_message}"
                )));
            }
        };

        // Check host must not have host-update override
        if let Some(host_machine_id) = &host_id {
            let host_machine = api_client
                .get_machines_by_ids(&[*host_machine_id])
                .await?
                .machines
                .into_iter()
                .next();

            if let Some(host_machine) = host_machine
                && host_machine
                    .health_overrides
                    .iter()
                    .any(|or| or.source == "host-update")
            {
                return Err(CarbideCliError::GenericError(format!(
                    "Host machine: {:?} already has a \"host-update\" override.",
                    host_machine.id,
                )));
            }

            let report =
                get_health_report(HealthOverrideTemplates::HostUpdate, Some(update_message));

            api_client
                .machine_insert_health_report_override(*host_machine_id, report.into(), false)
                .await?;
        }
    }
    api_client
        .0
        .trigger_dpu_reprovisioning(DpuReprovisioningRequest {
            dpu_id: Some(id),
            machine_id: Some(id),
            mode: mode as i32,
            initiator: UpdateInitiator::AdminCli as i32,
            update_firmware,
        })
        .await?;

    Ok(())
}

pub async fn list_dpus_pending(api_client: &ApiClient) -> CarbideCliResult<()> {
    let response = api_client.0.list_dpu_waiting_for_reprovisioning().await?;
    print_pending_dpus(response);
    Ok(())
}

fn print_pending_dpus(dpus: ::rpc::forge::DpuReprovisioningListResponse) {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "State",
        "Initiator",
        "Requested At",
        "Initiated At",
        "Update Firmware",
        "User Approved"
    ]);

    for dpu in dpus.dpus {
        let user_approval = if dpu.user_approval_received {
            "Yes"
        } else if dpu.state.contains("Assigned") {
            "No"
        } else {
            "NA"
        };
        table.add_row(row![
            dpu.id.unwrap_or_default().to_string(),
            dpu.state,
            dpu.initiator,
            dpu.requested_at.unwrap_or_default(),
            dpu.initiated_at
                .map(|x| x.to_string())
                .unwrap_or_else(|| "Not Started".to_string()),
            dpu.update_firmware,
            user_approval
        ]);
    }

    table.printstd();
}
