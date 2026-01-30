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
use std::pin::Pin;

use ::rpc::Machine;
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge::{
    BuildInfo, DpuReprovisioningRequest, ManagedHostNetworkConfigResponse, UpdateInitiator,
};
use carbide_uuid::machine::{MachineId, MachineType};
use prettytable::{Row, Table, format, row};
use serde::Serialize;

use super::args::{AgentUpgradePolicyChoice, DpuReprovision, DpuVersionOptions};
use crate::machine::{HealthOverrideTemplates, NetworkCommand, get_health_report};
use crate::rpc::ApiClient;
use crate::{async_write, async_write_table_as_csv};

pub async fn reprovision(api_client: &ApiClient, reprov: DpuReprovision) -> CarbideCliResult<()> {
    match reprov {
        DpuReprovision::Set(data) => {
            trigger_reprovisioning(
                data.id,
                Mode::Set,
                data.update_firmware,
                api_client,
                data.update_message,
            )
            .await
        }
        DpuReprovision::Clear(data) => {
            trigger_reprovisioning(data.id, Mode::Clear, data.update_firmware, api_client, None)
                .await
        }
        DpuReprovision::List => list_dpus_pending(api_client).await,
        DpuReprovision::Restart(data) => {
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

pub async fn agent_upgrade_policy(
    api_client: &ApiClient,
    set: Option<AgentUpgradePolicyChoice>,
) -> CarbideCliResult<()> {
    let rpc_choice = set.map(|cmd_line_policy| match cmd_line_policy {
        AgentUpgradePolicyChoice::Off => rpc::forge::AgentUpgradePolicy::Off,
        AgentUpgradePolicyChoice::UpOnly => rpc::forge::AgentUpgradePolicy::UpOnly,
        AgentUpgradePolicyChoice::UpDown => rpc::forge::AgentUpgradePolicy::UpDown,
    });
    handle_agent_upgrade_policy(api_client, rpc_choice).await
}

pub async fn versions(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: OutputFormat,
    api_client: &ApiClient,
    options: DpuVersionOptions,
    page_size: usize,
) -> CarbideCliResult<()> {
    handle_dpu_versions(
        output_file,
        output_format,
        api_client,
        options.updates_only,
        page_size,
    )
    .await
}

pub async fn status(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    handle_dpu_status(output_file, output_format, api_client, page_size).await
}

pub async fn network(
    api_client: &ApiClient,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    cmd: NetworkCommand,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    match cmd {
        NetworkCommand::Config(query) => {
            show_dpu_network_config(api_client, output_file, query.machine_id, output_format).await
        }
        NetworkCommand::Status => show_dpu_status(api_client, output_file).await,
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

pub async fn handle_agent_upgrade_policy(
    api_client: &ApiClient,
    action: Option<::rpc::forge::AgentUpgradePolicy>,
) -> CarbideCliResult<()> {
    match action {
        None => {
            let resp = api_client
                .0
                .dpu_agent_upgrade_policy_action(rpc::forge::DpuAgentUpgradePolicyRequest {
                    new_policy: None,
                })
                .await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!("{policy}");
        }
        Some(choice) => {
            let resp = api_client.0.dpu_agent_upgrade_policy_action(choice).await?;
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

        let dpu_type;
        let firmware_version;
        let bios_version;

        if let Some(discovery_info) = machine.discovery_info {
            if let Some(dmi_data) = discovery_info.dmi_data {
                dpu_type = Some(
                    dmi_data
                        .product_name
                        .split(' ')
                        .take(2)
                        .collect::<Vec<&str>>()
                        .join(" "),
                );
                bios_version = Some(dmi_data.bios_version);
            } else {
                dpu_type = None;
                bios_version = None;
            }
            firmware_version = discovery_info.dpu_info.map(|d| d.firmware_version);
        } else {
            dpu_type = None;
            firmware_version = None;
            bios_version = None;
        }

        DpuVersions {
            id: machine.id,
            dpu_type,
            state,
            firmware_version,
            bmc_version: machine.bmc_info.and_then(|bmc| bmc.firmware_version),
            bios_version,
            hbn_version: machine.inventory.and_then(|inv| {
                inv.components
                    .into_iter()
                    .find(|c| c.name == "doca_hbn")
                    .map(|c| c.version)
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
    Ok(serde_json::to_string_pretty(&machines)?)
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
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: OutputFormat,
    api_client: &ApiClient,
    updates_only: bool,
    page_size: usize,
) -> CarbideCliResult<()> {
    let expected_versions: HashMap<String, String> = if updates_only {
        let bi = api_client.0.version(true).await?;
        let rc = bi.runtime_config.unwrap_or_default();
        rc.dpu_nic_firmware_update_version
    } else {
        HashMap::default()
    };

    let dpus = api_client
        .get_all_machines(
            rpc::forge::MachineSearchConfig {
                include_dpus: true,
                exclude_hosts: true,
                ..Default::default()
            },
            page_size,
        )
        .await?
        .machines
        .into_iter()
        .filter(|m| {
            if updates_only {
                let product_name = m
                    .discovery_info
                    .as_ref()
                    .and_then(|di| di.dmi_data.as_ref())
                    .map(|dmi_data| dmi_data.product_name.as_str())
                    .unwrap_or_default();

                if let Some(expected_version) = expected_versions.get(product_name) {
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
            async_write!(output_file, "{}", json_output)?;
        }
        OutputFormat::Csv => {
            let result = generate_firmware_status_table(dpus);
            async_write_table_as_csv!(output_file, result)?;
        }
        _ => {
            let result = generate_firmware_status_table(dpus);
            async_write!(output_file, "{}", result)?;
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
            None => machine.state,
        };

        let dpu_type = machine
            .discovery_info
            .and_then(|di| di.dmi_data)
            .map(|dmi_data| {
                dmi_data
                    .product_name
                    .split(' ')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            });

        DpuStatus {
            id: machine.id,
            dpu_type,
            state,
            healthy: machine
                .health
                .map(|health| {
                    if health.alerts.is_empty() {
                        "Yes".to_string()
                    } else {
                        let mut alerts = String::new();
                        for alert in health.alerts.iter() {
                            if !alerts.is_empty() {
                                alerts.push('\n');
                            }
                            if let Some(target) = &alert.target {
                                alerts += &format!("{} [Target: {}]", alert.id, target);
                            } else {
                                alerts += &alert.id.to_string();
                            }
                        }
                        alerts
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

pub fn get_dpu_version_status(build_info: &BuildInfo, machine: &Machine) -> String {
    let mut version_statuses = Vec::default();

    let Some(runtime_config) = build_info.runtime_config.as_ref() else {
        return "No runtime config".to_owned();
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
        .map(|dmi_data| dmi_data.product_name.as_str())
        .unwrap_or_default();

    if let Some(expected_version) = expected_nic_versions.get(product_name)
        && expected_version
            != machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dpu_info.as_ref())
                .map(|dpu| dpu.firmware_version.as_str())
                .unwrap_or_default()
    {
        version_statuses.push("NIC Firmware update needed");
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
        "Up to date".to_owned()
    } else {
        version_statuses.join("\n")
    }
}

pub async fn handle_dpu_status(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let dpus = api_client
        .get_all_machines(
            rpc::forge::MachineSearchConfig {
                include_dpus: true,
                exclude_hosts: true,
                ..Default::default()
            },
            page_size,
        )
        .await?
        .machines;

    match output_format {
        OutputFormat::Json => {
            let machines: Vec<DpuStatus> = generate_dpu_status_data(api_client, dpus).await?;
            async_write!(output_file, "{}", serde_json::to_string(&machines).unwrap())?;
        }
        OutputFormat::Csv => {
            let result = generate_dpu_status_table(api_client, dpus).await?;
            async_write_table_as_csv!(output_file, result)?;
        }
        _ => {
            let result = generate_dpu_status_table(api_client, dpus).await?;
            async_write!(output_file, "{}", result)?;
        }
    }
    Ok(())
}

async fn generate_dpu_status_data(
    api_client: &ApiClient,
    machines: Vec<Machine>,
) -> CarbideCliResult<Vec<DpuStatus>> {
    let mut dpu_status = Vec::new();
    let build_info = api_client.0.version(true).await?;
    for machine in machines {
        let version_status = get_dpu_version_status(&build_info, &machine);
        let mut status = DpuStatus::from(machine);
        status.version_status = Some(version_status);
        dpu_status.push(status);
    }

    Ok(dpu_status)
}

pub async fn generate_dpu_status_table(
    api_client: &ApiClient,
    machines: Vec<Machine>,
) -> CarbideCliResult<Box<Table>> {
    let mut table = Table::new();

    let headers = vec!["DPU Id", "DPU Type", "State", "Healthy", "Version Status"];

    table.set_titles(Row::from(headers));

    generate_dpu_status_data(api_client, machines)
        .await?
        .into_iter()
        .for_each(|status| {
            table.add_row(status.into());
        });

    Ok(Box::new(table))
}

fn deny_prefix(config: &ManagedHostNetworkConfigResponse) -> String {
    let mut deny_prefixes = Vec::new();
    for chunk in config.deny_prefixes.chunks(5) {
        deny_prefixes.push(chunk.join(", "));
    }

    deny_prefixes.join("\n")
}

pub async fn show_dpu_network_config(
    api_client: &ApiClient,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    dpu_id: MachineId,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    if !dpu_id.machine_type().is_dpu() {
        return Err(CarbideCliError::GenericError(
            "Only DPU id is allowed.".to_string(),
        ));
    }
    let config = api_client.0.get_managed_host_network_config(dpu_id).await?;
    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&config)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&config)?);
        }
        OutputFormat::AsciiTable => {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_LINESEP);
            table.add_row(row!["Primary DPU", config.is_primary_dpu]);
            table.add_row(row!["ASN", config.asn]);
            table.add_row(row!["VNI Device", config.vni_device]);
            table.add_row(row![
                "Config Loopback IP",
                config
                    .managed_host_config
                    .as_ref()
                    .map(|x| x.loopback_ip.as_str())
                    .unwrap_or_default()
            ]);
            table.add_row(row!["Config Version", config.managed_host_config_version]);
            table.add_row(row!["Use Admin Network", config.use_admin_network]);
            table.add_row(row![
                "Instance Config Version",
                config.instance_network_config_version
            ]);
            table.add_row(row![
                "Instance ID",
                config
                    .instance_id
                    .map(|x| x.to_string())
                    .unwrap_or_default()
            ]);

            let virt_type = ::rpc::forge::VpcVirtualizationType::try_from(
                config.network_virtualization_type.unwrap_or_default(),
            )
            .unwrap_or_default()
            .as_str_name()
            .to_string();
            table.add_row(row!["Virtualization Type", virt_type]);
            table.add_row(row!["VPC VNI", config.vpc_vni()]);
            table.add_row(row!["Internet L3 VNI", config.internet_l3_vni()]);
            table.add_row(row!["Route Servers", config.route_servers.join(", ")]);
            table.add_row(row!["Deny Prefixes", deny_prefix(&config)]);
            table.add_row(row!["Network Pinger", config.dpu_network_pinger_type()]);
            table.add_row(row!["Host Interface ID", config.host_interface_id()]);
            table.add_row(row![
                "Min Functioning Link",
                config
                    .min_dpu_functioning_links
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "Not Set".to_string())
            ]);
            async_write!(output_file, "{}", table)?;

            println!("Admin Interface:");

            if let Some(aintf) = config.admin_interface.as_ref() {
                let mut table = Table::new();
                table.set_format(*format::consts::FORMAT_NO_LINESEP);
                table.get_format().indent(4);
                table.add_row(row!["Vlan ID", aintf.vlan_id]);
                table.add_row(row!["VNI", aintf.vni]);
                table.add_row(row!["IP", aintf.ip]);
                table.add_row(row!["Gateway", aintf.gateway]);
                table.add_row(row!["Prefix", aintf.prefix]);
                table.add_row(row!["Is L2 Segment", aintf.is_l2_segment]);
                table.add_row(row!["FQDN", aintf.fqdn]);
                table.add_row(row!["VPC Prefixes", aintf.vpc_prefixes.join(", ")]);
                table.add_row(row!["VPC VNI", aintf.vpc_vni]);
                table.add_row(row!["SVI IP", aintf.svi_ip()]);
                table.add_row(row!["Tenant VRF Loopback", aintf.tenant_vrf_loopback_ip()]);
                table.add_row(row!["Boot URL", aintf.booturl()]);

                async_write!(output_file, "{}", table)?;
            }

            println!("Tenant Interfaces:");
            for (idx, tintf) in config.tenant_interfaces.iter().enumerate() {
                println!("    Interface #{idx}");
                let mut table = Table::new();
                table.set_format(*format::consts::FORMAT_NO_LINESEP);
                table.get_format().indent(4);
                table.add_row(row![
                    "Function Type",
                    format!("{:?}", tintf.function_type())
                ]);
                table.add_row(row![
                    "Virtual Function ID",
                    tintf
                        .virtual_function_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "NA".to_string())
                ]);
                table.add_row(row!["Vlan ID", tintf.vlan_id]);
                table.add_row(row!["VNI", tintf.vni]);
                table.add_row(row!["IP", tintf.ip]);
                table.add_row(row!["Gateway", tintf.gateway]);
                table.add_row(row!["Prefix", tintf.prefix]);
                table.add_row(row!["Is L2 Segment", tintf.is_l2_segment]);
                table.add_row(row!["FQDN", tintf.fqdn]);
                table.add_row(row!["VPC Prefixes", tintf.vpc_prefixes.join(", ")]);
                table.add_row(row![
                    "VPC Peer Prefixes",
                    tintf.vpc_peer_prefixes.join(", ")
                ]);
                table.add_row(row![
                    "VPC Peer VNIs",
                    tintf
                        .vpc_peer_vnis
                        .iter()
                        .map(|vni| vni.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                ]);
                table.add_row(row!["VPC VNI", tintf.vpc_vni]);
                table.add_row(row!["SVI IP", tintf.svi_ip()]);
                table.add_row(row!["Tenant VRF Loopback", tintf.tenant_vrf_loopback_ip()]);
                table.add_row(row!["Boot URL", tintf.booturl()]);

                async_write!(output_file, "{}", table)?;
            }
        }
        _ => {
            todo!()
        }
    }

    Ok(())
}

pub async fn show_dpu_status(
    api_client: &ApiClient,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
) -> CarbideCliResult<()> {
    let all_status = api_client
        .0
        .get_all_managed_host_network_status()
        .await?
        .all;
    if all_status.is_empty() {
        println!("No reported network status");
    } else {
        let all_ids: Vec<MachineId> = all_status
            .iter()
            .filter_map(|status| status.dpu_machine_id)
            .collect();
        let all_dpus = api_client.get_machines_by_ids(&all_ids).await?.machines;
        let mut dpus_by_id = HashMap::new();
        for dpu in all_dpus.into_iter() {
            if let Some(id) = dpu.id {
                dpus_by_id.insert(id, dpu);
            }
        }

        let mut table = Table::new();
        table.set_titles(row![
            "Observed at",
            "DPU machine ID",
            "Network config version",
            "Healthy?",
            "Health Probe Alerts",
            "Agent version",
        ]);
        for st in all_status.into_iter() {
            let Some(dpu_id) = st.dpu_machine_id else {
                continue;
            };
            let Some(dpu) = dpus_by_id.get(&dpu_id) else {
                continue;
            };
            let observed_at = st
                .observed_at
                .map(|o| {
                    let dt: chrono::DateTime<chrono::Utc> = o.try_into().unwrap();
                    dt.format("%Y-%m-%d %H:%M:%S.%3f").to_string()
                })
                .unwrap_or_default();
            let mut probe_alerts = String::new();
            if let Some(health) = &dpu.health {
                for alert in health.alerts.iter() {
                    if !probe_alerts.is_empty() {
                        probe_alerts.push('\n');
                    }
                    if let Some(target) = &alert.target {
                        probe_alerts += &format!("{} [Target: {}]", alert.id, target)
                    } else {
                        probe_alerts += &alert.id.to_string();
                    }
                }
            }
            table.add_row(row![
                observed_at,
                st.dpu_machine_id.unwrap(),
                st.network_config_version.unwrap_or_default(),
                dpu.health
                    .as_ref()
                    .map(|health| health.alerts.is_empty().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                probe_alerts,
                st.dpu_agent_version.unwrap_or("".to_string())
            ]);
        }
        async_write!(output_file, "{}", table)?;
    }
    Ok(())
}
