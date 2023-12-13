/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::{forge::MachineType, Machine, MachineId};
use prettytable::{row, Row, Table};
use serde::Serialize;

use super::{rpc, CarbideCliResult};
use crate::{
    cfg::carbide_options::{AgentUpgradePolicyChoice, OutputFormat},
    Config,
};

pub async fn trigger_reprovisioning(
    id: String,
    set: bool,
    update_firmware: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    rpc::trigger_dpu_reprovisioning(id, set, update_firmware, api_config).await
}

pub async fn list_dpus_pending(api_config: Config) -> CarbideCliResult<()> {
    let response = rpc::list_dpu_pending_for_reprovisioning(api_config).await?;
    print_pending_dpus(response);
    Ok(())
}

fn print_pending_dpus(dpus: ::rpc::forge::DpuReprovisioningListResponse) {
    let mut table = Table::new();

    table.add_row(row![
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

pub async fn handle_agent_upgrade_policy(
    api_config: Config,
    action: Option<::rpc::forge::AgentUpgradePolicy>,
) -> CarbideCliResult<()> {
    match action {
        None => {
            let resp = rpc::dpu_agent_upgrade_policy_action(&api_config, None).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!("{policy}");
        }
        Some(choice) => {
            let resp = rpc::dpu_agent_upgrade_policy_action(&api_config, Some(choice)).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!(
                "Policy is now: {policy}. Update succeeded? {}.",
                resp.did_change,
            );
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct DpuFirmwareStatus {
    id: Option<MachineId>,
    dpu_type: Option<String>,
    is_healthy: Option<bool>,
    state: String,
    maintenance: Option<String>,
    firmware_version: Option<String>,
    bmc_version: Option<String>,
    bios_version: Option<String>,
}

impl From<Machine> for DpuFirmwareStatus {
    fn from(machine: Machine) -> Self {
        let state = match machine.state.split_once(' ') {
            Some((state, _)) => state.to_owned(),
            None => machine.state,
        };

        DpuFirmwareStatus {
            id: machine.id,
            dpu_type: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dmi_data.as_ref())
                .map(|dmi_data| dmi_data.product_name.clone()),
            is_healthy: machine.network_health.as_ref().map(|h| h.is_healthy),
            state: state.to_owned(),
            maintenance: machine.maintenance_reference,
            firmware_version: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dpu_info.as_ref())
                .map(|dpu| dpu.firmware_version.clone()),
            bmc_version: machine
                .bmc_info
                .as_ref()
                .and_then(|bmc| bmc.firmware_version.clone()),
            bios_version: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dmi_data.as_ref())
                .map(|dmi_data| dmi_data.bios_version.clone()),
        }
    }
}

impl From<DpuFirmwareStatus> for Row {
    fn from(value: DpuFirmwareStatus) -> Self {
        Row::from(vec![
            value.id.unwrap_or_default().to_string(),
            value.dpu_type.unwrap_or_default(),
            value.is_healthy.unwrap_or_default().to_string(),
            value.state,
            value.maintenance.unwrap_or_default(),
            value.firmware_version.unwrap_or_default(),
            value.bmc_version.unwrap_or_default(),
            value.bios_version.unwrap_or_default(),
        ])
    }
}

pub fn generate_firmware_status_json(machines: Vec<Machine>) -> CarbideCliResult<String> {
    let machines: Vec<DpuFirmwareStatus> =
        machines.into_iter().map(DpuFirmwareStatus::from).collect();
    Ok(serde_json::to_string(&machines)?)
}

pub fn generate_firmware_status_table(machines: Vec<Machine>) -> Box<Table> {
    let mut table = Table::new();

    let headers = vec![
        "DPU Id",
        "DPU Type",
        "Healthy",
        "State",
        "Maintenance",
        "NIC FW Version",
        "BMC Version",
        "BIOS Version",
    ];

    table.add_row(Row::from(headers));

    machines
        .into_iter()
        .map(DpuFirmwareStatus::from)
        .for_each(|f| {
            table.add_row(f.into());
        });

    Box::new(table)
}

pub async fn handle_dpu_versions(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    api_config: Config,
    updates_only: bool,
) -> CarbideCliResult<()> {
    let expected_versions: HashMap<String, String> = if updates_only {
        let bi = rpc::version(&api_config, true).await?;
        let rc = bi.runtime_config.unwrap_or_default();
        rc.dpu_nic_firmware_update_version
    } else {
        HashMap::default()
    };

    let dpus = rpc::get_all_machines(api_config, false)
        .await?
        .machines
        .into_iter()
        .filter(|m| m.machine_type() == MachineType::Dpu)
        .filter(|m| {
            if updates_only {
                let product_name = m
                    .discovery_info
                    .as_ref()
                    .and_then(|di| di.dmi_data.as_ref())
                    .map(|dmi_data| dmi_data.product_name.clone())
                    .unwrap_or_default();

                if let Some(expected_version) = expected_versions.get(&product_name) {
                    expected_version
                        != m.discovery_info
                            .as_ref()
                            .and_then(|di| di.dpu_info.as_ref())
                            .map(|dpu| dpu.firmware_version.as_str())
                            .unwrap_or("")
                } else {
                    true
                }
            } else {
                true
            }
        })
        .collect();

    match output_format {
        OutputFormat::Json => {
            let json_output = generate_firmware_status_json(dpus)?;

            write!(output, "{}", json_output)?;
        }
        OutputFormat::Csv => {
            let result = generate_firmware_status_table(dpus);

            if let Err(error) = result.to_csv(output) {
                tracing::warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            let result = generate_firmware_status_table(dpus);
            if let Err(error) = result.print(output) {
                tracing::warn!("Error writing table data: {}", error);
            }
        }
    }
    Ok(())
}
