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

use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge::BuildInfo;
use ::rpc::forge_tls_client::ApiConfig;
use ::rpc::{forge::MachineType, Machine, MachineId};
use prettytable::{row, Row, Table};
use serde::Serialize;

use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::{AgentUpgradePolicyChoice, OutputFormat};

pub async fn trigger_reprovisioning(
    id: String,
    mode: Mode,
    update_firmware: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    rpc::trigger_dpu_reprovisioning(id, mode, update_firmware, api_config).await
}

pub async fn list_dpus_pending(api_config: &ApiConfig<'_>) -> CarbideCliResult<()> {
    let response = rpc::list_dpu_pending_for_reprovisioning(api_config).await?;
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

pub async fn handle_agent_upgrade_policy(
    api_config: &ApiConfig<'_>,
    action: Option<::rpc::forge::AgentUpgradePolicy>,
) -> CarbideCliResult<()> {
    match action {
        None => {
            let resp = rpc::dpu_agent_upgrade_policy_action(api_config, None).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!("{policy}");
        }
        Some(choice) => {
            let resp = rpc::dpu_agent_upgrade_policy_action(api_config, Some(choice)).await?;
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
struct DpuVersions {
    id: Option<MachineId>,
    dpu_type: Option<String>,
    state: String,
    firmware_version: Option<String>,
    bmc_version: Option<String>,
    bios_version: Option<String>,
    hbn_version: Option<String>,
    agent_version: Option<String>,
}

impl From<Machine> for DpuVersions {
    fn from(machine: Machine) -> Self {
        let state = match machine.state.split_once(' ') {
            Some((state, _)) => state.to_owned(),
            None => machine.state,
        };

        let dpu_type = machine
            .discovery_info
            .as_ref()
            .and_then(|di| di.dmi_data.as_ref())
            .map(|dmi_data| {
                let dpu_type = dmi_data.product_name.clone();
                let mut dpu_type = dpu_type.split(' ').collect::<Vec<&str>>();
                dpu_type.truncate(2);
                dpu_type.join(" ")
            });

        DpuVersions {
            id: machine.id,
            dpu_type,
            state,
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
            hbn_version: machine.inventory.and_then(|inv| {
                inv.components
                    .iter()
                    .find(|c| c.name == "doca_hbn")
                    .map(|c| c.version.clone())
            }),
            agent_version: machine.dpu_agent_version,
        }
    }
}

impl From<DpuVersions> for Row {
    fn from(value: DpuVersions) -> Self {
        Row::from(vec![
            value.id.unwrap_or_default().to_string(),
            value.dpu_type.unwrap_or_default(),
            value.state,
            value.firmware_version.unwrap_or_default(),
            value.bmc_version.unwrap_or_default(),
            value.bios_version.unwrap_or_default(),
            value.hbn_version.unwrap_or_default(),
            value.agent_version.unwrap_or_default(),
        ])
    }
}

pub fn generate_firmware_status_json(machines: Vec<Machine>) -> CarbideCliResult<String> {
    let machines: Vec<DpuVersions> = machines.into_iter().map(DpuVersions::from).collect();
    Ok(serde_json::to_string(&machines)?)
}

pub fn generate_firmware_status_table(machines: Vec<Machine>) -> Box<Table> {
    let mut table = Table::new();

    let headers = vec![
        "DPU Id", "DPU Type", "State", "NIC FW", "BMC", "BIOS", "HBN", "Agent",
    ];

    table.set_titles(Row::from(headers));

    machines.into_iter().map(DpuVersions::from).for_each(|f| {
        table.add_row(f.into());
    });

    Box::new(table)
}

pub async fn handle_dpu_versions(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    updates_only: bool,
    page_size: usize,
) -> CarbideCliResult<()> {
    let expected_versions: HashMap<String, String> = if updates_only {
        let bi = rpc::version(api_config, true).await?;
        let rc = bi.runtime_config.unwrap_or_default();
        rc.dpu_nic_firmware_update_version
    } else {
        HashMap::default()
    };

    let dpus = rpc::get_all_machines(api_config, Some(MachineType::Dpu), false, page_size)
        .await?
        .machines
        .into_iter()
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

#[derive(Serialize)]
struct DpuStatus {
    id: Option<MachineId>,
    dpu_type: Option<String>,
    state: String,
    healthy: String,
    version_status: Option<String>,
}

impl From<Machine> for DpuStatus {
    fn from(machine: Machine) -> Self {
        let state = match machine.state.split_once(' ') {
            Some((state, _)) => state.to_owned(),
            None => machine.state.clone(),
        };

        let dpu_type = machine
            .discovery_info
            .as_ref()
            .and_then(|di| di.dmi_data.as_ref())
            .map(|dmi_data| {
                let dpu_type = dmi_data.product_name.clone();
                let mut dpu_type = dpu_type.split(' ').collect::<Vec<&str>>();
                dpu_type.truncate(2);
                dpu_type.join(" ")
            });

        DpuStatus {
            id: machine.id,
            dpu_type,
            state,
            healthy: machine
                .network_health
                .map(|x| {
                    if x.is_healthy {
                        "Yes".to_string()
                    } else {
                        x.message.unwrap_or("No message found.".to_string())
                    }
                })
                .unwrap_or("Unknown".to_string()),
            version_status: None,
        }
    }
}

impl From<DpuStatus> for Row {
    fn from(value: DpuStatus) -> Self {
        Row::from(vec![
            value.id.unwrap_or_default().to_string(),
            value.dpu_type.unwrap_or_default(),
            value.state,
            value.healthy,
            value.version_status.unwrap_or_default(),
        ])
    }
}

pub async fn get_dpu_version_status(
    build_info: &BuildInfo,
    machine: &Machine,
) -> CarbideCliResult<String> {
    let mut version_statuses = Vec::default();

    let Some(runtime_config) = build_info.runtime_config.as_ref() else {
        return Ok("No runtime config".to_owned());
    };

    let expected_agent_version = &build_info.build_version;
    if machine.dpu_agent_version() != expected_agent_version {
        version_statuses.push("Agent update needed");
    }

    let expected_nic_versions = &runtime_config.dpu_nic_firmware_update_version;

    let product_name = machine
        .discovery_info
        .as_ref()
        .and_then(|di| di.dmi_data.as_ref())
        .map(|dmi_data| dmi_data.product_name.clone())
        .unwrap_or_default();

    if let Some(expected_version) = expected_nic_versions.get(&product_name) {
        if expected_version
            != machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dpu_info.as_ref())
                .map(|dpu| dpu.firmware_version.as_str())
                .unwrap_or("")
        {
            version_statuses.push("NIC Firmware update needed");
        }
    }

    /* TODO add bmc version check when available
    let expected_bmc_versions: HashMap<String, String> = HashMap::default();
    let bmc_version = machine.bmc_info.as_ref().map(|bi| bi.firmware_version.clone().unwrap_or_default());

    if let Some(bmc_version) = bmc_version {
        if let Some(expected_bmc_version) = expected_bmc_versions.get(&product_name) {
            if expected_bmc_version != &bmc_version {
                version_statuses.push("BMC Firmware update needed");
            }
        } else {
            version_statuses.push("Unknown expected BMC Firmware version");
        }
    } else {
        version_statuses.push("Unknown BMC Firmware version");
    }
    */

    if version_statuses.is_empty() {
        Ok("Up to date".to_owned())
    } else {
        Ok(version_statuses.join("\n"))
    }
}

pub async fn handle_dpu_status(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let dpus = rpc::get_all_machines(api_config, Some(MachineType::Dpu), false, page_size)
        .await?
        .machines;

    match output_format {
        OutputFormat::Json => {
            let machines: Vec<DpuStatus> = generate_dpu_status_data(api_config, dpus).await?;
            write!(output, "{}", serde_json::to_string(&machines).unwrap())?;
        }
        OutputFormat::Csv => {
            let result = generate_dpu_status_table(api_config, dpus).await?;

            if let Err(error) = result.to_csv(output) {
                tracing::warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            let result = generate_dpu_status_table(api_config, dpus).await?;
            if let Err(error) = result.print(output) {
                tracing::warn!("Error writing table data: {}", error);
            }
        }
    }
    Ok(())
}

async fn generate_dpu_status_data(
    api_config: &ApiConfig<'_>,
    machines: Vec<Machine>,
) -> CarbideCliResult<Vec<DpuStatus>> {
    let mut dpu_status = Vec::new();
    let build_info = rpc::version(api_config, true).await?;
    for machine in machines {
        let version_status = get_dpu_version_status(&build_info, &machine).await?;
        let mut status = DpuStatus::from(machine);
        status.version_status = Some(version_status);
        dpu_status.push(status);
    }

    Ok(dpu_status)
}

pub async fn generate_dpu_status_table(
    api_config: &ApiConfig<'_>,
    machines: Vec<Machine>,
) -> CarbideCliResult<Box<Table>> {
    let mut table = Table::new();

    let headers = vec!["DPU Id", "DPU Type", "State", "Healthy", "Version Status"];

    table.set_titles(Row::from(headers));

    generate_dpu_status_data(api_config, machines)
        .await?
        .into_iter()
        .for_each(|status| {
            table.add_row(status.into());
        });

    Ok(Box::new(table))
}

pub async fn trigger_reset(id: String, api_config: &ApiConfig<'_>) -> CarbideCliResult<()> {
    println!("Note this is just an temporary command. It will be removed in future releases.");
    let response = rpc::trigger_dpu_reset(id, api_config).await?;
    println!("{}", response.msg);

    Ok(())
}
