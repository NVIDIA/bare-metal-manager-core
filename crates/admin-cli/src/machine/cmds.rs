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

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use std::fs;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{
    self as forgerpc, AdminForceDeleteMachineRequest, RemoveHealthReportOverrideRequest,
};
use carbide_uuid::machine::MachineId;
use chrono::Utc;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess, HealthReport,
};
use mac_address::MacAddress;
use prettytable::{Row, Table, row};
use rpc::Machine;

use super::args::{
    BMCConfigForReboot, ForceDeleteMachineQuery, HealthOverrideTemplates, MachineAutoupdate,
    MachineHardwareInfoGpus, MachineMetadataCommand, MachineMetadataCommandAddLabel,
    MachineMetadataCommandFromExpectedMachine, MachineMetadataCommandRemoveLabels,
    MachineMetadataCommandSet, MachineMetadataCommandShow, MachineQuery, NetworkCommand,
    NvlinkInfoArgs, NvlinkInfoPopulateArgs, OverrideCommand, Positions, ShowMachine,
};
use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;
use crate::{async_write, async_write_table_as_csv, async_writeln, dpu};

fn convert_machine_to_nice_format(
    machine: forgerpc::Machine,
    history_count: u32,
) -> CarbideCliResult<String> {
    let mut lines = String::new();
    let sku = machine.hw_sku.unwrap_or_default();
    let sku_device_type = machine.hw_sku_device_type.unwrap_or_default();

    let mut data = vec![
        (
            "ID",
            machine.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        ("STATE", machine.state.to_uppercase()),
        ("STATE_VERSION", machine.state_version),
        ("MACHINE TYPE", get_machine_type(machine.id)),
        (
            "FAILURE",
            machine.failure_details.unwrap_or("None".to_string()),
        ),
        ("VERSION", machine.version),
        ("SKU", sku),
        ("SKU DEVICE TYPE", sku_device_type),
    ];
    if let Some(di) = machine.discovery_info
        && let Some(dmi) = di.dmi_data
    {
        data.push(("VENDOR", dmi.sys_vendor));
        data.push(("PRODUCT NAME", dmi.product_name));
        data.push(("PRODUCT SERIAL", dmi.product_serial));
        data.push(("BOARD SERIAL", dmi.board_serial));
        data.push(("CHASSIS SERIAL", dmi.chassis_serial));
        data.push(("BIOS VERSION", dmi.bios_version));
        data.push(("BOARD VERSION", dmi.board_version));
    }
    let autoupdate = if let Some(autoupdate) = machine.firmware_autoupdate {
        autoupdate.to_string()
    } else {
        "Default".to_string()
    };
    data.push(("FIRMWARE AUTOUPDATE", autoupdate));

    let width = 1 + data
        .iter()
        .fold(0, |accum, (key, _value)| std::cmp::max(accum, key.len()));

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    let metadata = machine.metadata.unwrap_or_default();
    writeln!(&mut lines, "METADATA")?;
    writeln!(&mut lines, "\tNAME: {}", metadata.name)?;
    writeln!(&mut lines, "\tDESCRIPTION: {}", metadata.description)?;
    writeln!(&mut lines, "\tLABELS:")?;
    for label in metadata.labels {
        writeln!(
            &mut lines,
            "\t\t{}:{}",
            label.key,
            label.value.unwrap_or_default()
        )?;
    }

    writeln!(&mut lines, "STATE HISTORY: (Latest {history_count} only)")?;
    if machine.events.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        let mut max_state_len = 0;
        let mut max_version_len = 0;
        for x in machine
            .events
            .iter()
            .rev()
            .take(history_count as usize)
            .rev()
        {
            max_state_len = max_state_len.max(x.event.len());
            max_version_len = max_version_len.max(x.version.len());
        }
        let header = format!(
            "{:<max_state_len$} {:<max_version_len$} Time",
            "State", "Version"
        );
        writeln!(&mut lines, "\t{header}")?;
        let mut div = "".to_string();
        for _ in 0..header.len() + 27 {
            div.push('-')
        }
        writeln!(&mut lines, "\t{div}")?;
        for x in machine
            .events
            .iter()
            .rev()
            .take(history_count as usize)
            .rev()
        {
            writeln!(
                &mut lines,
                "\t{:<max_state_len$} {:<max_version_len$} {}",
                x.event,
                x.version,
                x.time.unwrap_or_default()
            )?;
        }
    }

    writeln!(&mut lines, "INTERFACES:")?;
    if machine.interfaces.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, interface) in machine.interfaces.into_iter().enumerate() {
            let data = vec![
                ("SN", i.to_string()),
                ("ID", interface.id.unwrap_or_default().to_string()),
                (
                    "DPU ID",
                    interface
                        .attached_dpu_machine_id
                        .as_ref()
                        .map(MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Machine ID",
                    interface
                        .machine_id
                        .as_ref()
                        .map(MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Segment ID",
                    interface.segment_id.unwrap_or_default().to_string(),
                ),
                (
                    "Domain ID",
                    interface.domain_id.unwrap_or_default().to_string(),
                ),
                ("Hostname", interface.hostname),
                ("Primary", interface.primary_interface.to_string()),
                ("MAC Address", interface.mac_address),
                ("Addresses", interface.address.join(",")),
            ];

            let width = 1 + data
                .iter()
                .fold(0, |accum, (key, _value)| std::cmp::max(accum, key.len()));
            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    if let Some(health) = machine.health
        && !health.alerts.is_empty()
    {
        writeln!(&mut lines, "ALERTS:")?;
        for alert in health.alerts {
            writeln!(&mut lines, "\t- {}", alert.message)?;
        }
    }

    Ok(lines)
}

fn get_machine_type(machine_id: Option<MachineId>) -> String {
    machine_id
        .map(|id| id.machine_type().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> Box<Table> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "",
        "Id",
        "State",
        "State Version",
        "Attached DPUs",
        "Primary Interface",
        "IP Address",
        "MAC Address",
        "Type",
        "Vendor",
        "Labels",
    ]);

    for machine in machines.machines {
        let machine_id_string = machine.id.map(|id| id.to_string()).unwrap_or_default();
        let mut machine_interfaces = machine
            .interfaces
            .into_iter()
            .filter(|x| x.primary_interface)
            .collect::<Vec<forgerpc::MachineInterface>>();

        let (id, address, mac, machine_type, dpu_id) = if machine_interfaces.is_empty() {
            (
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
            )
        } else {
            let mi = machine_interfaces.remove(0);
            let dpu_ids = if !machine.associated_dpu_machine_ids.is_empty() {
                machine
                    .associated_dpu_machine_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
            } else {
                vec![
                    mi.attached_dpu_machine_id
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "NA".to_string()),
                ]
            };

            (
                mi.id.unwrap_or_default().to_string(),
                mi.address.join(","),
                mi.mac_address,
                get_machine_type(machine.id),
                dpu_ids.join("\n"),
            )
        };
        let mut vendor = String::new();
        if let Some(di) = machine.discovery_info
            && let Some(dmi) = di.dmi_data
        {
            vendor = dmi.sys_vendor;
        }

        let labels = crate::metadata::get_nice_labels_from_rpc_metadata(machine.metadata.as_ref());

        let is_unhealthy = machine
            .health
            .map(|x| !x.alerts.is_empty())
            .unwrap_or_default();

        table.add_row(row![
            String::from(if is_unhealthy { "U" } else { "H" }),
            machine_id_string,
            machine.state.to_uppercase(),
            machine.state_version,
            dpu_id,
            id,
            address,
            mac,
            machine_type,
            vendor,
            labels.join(", ")
        ]);
    }

    table
}

async fn show_all_machines(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    api_client: &ApiClient,
    search_config: rpc::forge::MachineSearchConfig,
    page_size: usize,
    sort_by: &SortField,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_all_machines(search_config, page_size)
        .await?;

    match sort_by {
        SortField::PrimaryId => machines.machines.sort_by(|m1, m2| m1.id.cmp(&m2.id)),
        SortField::State => machines.machines.sort_by(|m1, m2| m1.state.cmp(&m2.state)),
    };

    match output_format {
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(&machines)?)?;
        }
        OutputFormat::AsciiTable => {
            let table = convert_machines_to_nice_table(machines);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Csv => {
            let table = convert_machines_to_nice_table(machines);
            async_write_table_as_csv!(output_file, table)?;
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }
    Ok(())
}

async fn show_machine_information(
    machine_id: MachineId,
    args: &ShowMachine,
    output_format: &OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(machine_id).await?;
    match output_format {
        OutputFormat::Json => {
            async_write!(output_file, "{}", serde_json::to_string_pretty(&machine)?)?
        }
        OutputFormat::AsciiTable => async_write!(
            output_file,
            "{}",
            convert_machine_to_nice_format(machine, args.history_count)
                .unwrap_or_else(|x| x.to_string())
        )?,
        OutputFormat::Csv => {
            return Err(CarbideCliError::NotImplemented(
                "CSV formatted output".to_string(),
            ));
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowMachine,
    output_format: &OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    page_size: usize,
    sort_by: &SortField,
) -> CarbideCliResult<()> {
    if let Some(machine_id) = args.machine {
        show_machine_information(machine_id, &args, output_format, output_file, api_client).await?;
    } else {
        // Show both hosts and DPUs if neither flag is specified
        let show_all_types = !args.dpus && !args.hosts;
        let dpus_only = args.dpus && !args.hosts;
        let search_config = rpc::forge::MachineSearchConfig {
            include_dpus: args.dpus || show_all_types,
            exclude_hosts: dpus_only,
            include_predicted_host: args.hosts || show_all_types,
            ..Default::default()
        };
        show_all_machines(
            output_file,
            output_format,
            api_client,
            search_config,
            page_size,
            sort_by,
        )
        .await?;
    }

    Ok(())
}

fn get_empty_template() -> HealthReport {
    HealthReport {
        source: "".to_string(),
        observed_at: Some(Utc::now()),
        successes: vec![HealthProbeSuccess {
            id: HealthProbeId::from_str("test").unwrap(),
            target: Some("".to_string()),
        }],
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("test").unwrap(),
            target: None,
            in_alert_since: None,
            message: "".to_string(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::prevent_host_state_changes(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    }
}

pub fn get_health_report(
    template: HealthOverrideTemplates,
    message: Option<String>,
) -> HealthReport {
    let mut report = HealthReport {
        source: "admin-cli".to_string(),
        observed_at: Some(Utc::now()),
        successes: vec![],
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("Maintenance").unwrap(),
            target: None,
            in_alert_since: None,
            message: message.unwrap_or_default(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    };

    match template {
        HealthOverrideTemplates::HostUpdate => {
            report.source = "host-update".to_string();
            report.alerts[0].id = HealthProbeId::from_str("HostUpdateInProgress").unwrap();
            report.alerts[0].target = Some("admin-cli".to_string());
        }
        HealthOverrideTemplates::InternalMaintenance => {
            report.source = "maintenance".to_string();
        }
        HealthOverrideTemplates::StopRebootForAutomaticRecoveryFromStateMachine => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("admin-cli".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::stop_reboot_for_automatic_recovery_from_state_machine(),
            ];
        }
        HealthOverrideTemplates::OutForRepair => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("OutForRepair".to_string());
        }
        HealthOverrideTemplates::Degraded => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("Degraded".to_string());
        }
        HealthOverrideTemplates::Validation => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("Validation".to_string());
            report.alerts[0].classifications =
                vec![HealthAlertClassification::suppress_external_alerting()];
        }
        HealthOverrideTemplates::SuppressExternalAlerting => {
            report.source = "suppress-paging".to_string();
            report.alerts[0].target = Some("SuppressExternalAlerting".to_string());
            report.alerts[0].classifications =
                vec![HealthAlertClassification::suppress_external_alerting()];
        }
        HealthOverrideTemplates::MarkHealthy => {
            report.source = "admin-cli".to_string();
            report.alerts.clear();
        }
        // Template to indicate that the instance is identified as unhealthy by the tenant and
        // should be fixed before returning to the tenant.
        HealthOverrideTemplates::TenantReportedIssue => {
            report.source = "tenant-reported-issue".to_string();
            report.alerts[0].id = HealthProbeId::from_str("TenantReportedIssue")
                .expect("TenantReportedIssue is a valid non-empty HealthProbeId");
            report.alerts[0].target = Some("tenant-reported".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ];
        }
        // Template to indicate that the instance is identified as unhealthy and
        // is ready to be picked by Repair System for diagnosis and fix.
        HealthOverrideTemplates::RequestRepair => {
            report.source = "repair-request".to_string();
            report.alerts[0].id = HealthProbeId::from_str("RequestRepair")
                .expect("RequestRepair is a valid non-empty HealthProbeId");
            report.alerts[0].target = Some("repair-requested".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ];
        }
    }

    report
}

pub async fn handle_override(
    command: OverrideCommand,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    match command {
        OverrideCommand::Show { machine_id } => {
            let response = api_client
                .0
                .list_health_report_overrides(machine_id)
                .await?;
            let mut rows = vec![];
            for r#override in response.overrides {
                let report = r#override.report.ok_or(CarbideCliError::GenericError(
                    "missing response".to_string(),
                ))?;
                let mode = match ::rpc::forge::OverrideMode::try_from(r#override.mode)
                    .map_err(|_| CarbideCliError::GenericError("invalide response".to_string()))?
                {
                    forgerpc::OverrideMode::Merge => "Merge",
                    forgerpc::OverrideMode::Replace => "Replace",
                };
                rows.push((report, mode));
            }
            match output_format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &rows
                            .into_iter()
                            .map(|r| {
                                serde_json::json!({
                                    "report": r.0,
                                    "mode": r.1,
                                })
                            })
                            .collect::<Vec<_>>(),
                    )?
                ),
                _ => {
                    let mut table = Table::new();
                    table.set_titles(row!["Report", "Mode"]);
                    for row in rows {
                        table.add_row(row![serde_json::to_string(&row.0)?, row.1]);
                    }
                    table.printstd();
                }
            }
        }
        OverrideCommand::Add(options) => {
            let report = if let Some(template) = options.template {
                get_health_report(template, options.message)
            } else if let Some(health_report) = options.health_report {
                serde_json::from_str::<health_report::HealthReport>(&health_report)
                    .map_err(CarbideCliError::JsonError)?
            } else {
                return Err(CarbideCliError::GenericError(
                    "Either health_report or template name must be provided.".to_string(),
                ));
            };

            if options.print_only {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return Ok(());
            }

            api_client
                .machine_insert_health_report_override(
                    options.machine_id,
                    report.into(),
                    options.replace,
                )
                .await?;
        }
        OverrideCommand::Remove {
            machine_id,
            report_source,
        } => {
            api_client
                .0
                .remove_health_report_override(RemoveHealthReportOverrideRequest {
                    machine_id: Some(machine_id),
                    source: report_source,
                })
                .await?;
        }
        OverrideCommand::PrintEmptyTemplate => {
            println!(
                "{}",
                serde_json::to_string_pretty(&get_empty_template()).unwrap()
            );
        }
    }

    Ok(())
}

pub async fn force_delete(
    mut query: ForceDeleteMachineQuery,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    const RETRY_TIME: Duration = Duration::from_secs(5);
    const MAX_WAIT_TIME: Duration = Duration::from_secs(60 * 20);

    let start = std::time::Instant::now();
    let mut dpu_machine_id = String::new();

    if let Ok(id) = MachineId::from_str(&query.machine)
        && api_client
            .0
            .find_instance_by_machine_id(id)
            .await
            .is_ok_and(|i| !i.instances.is_empty())
        && !query.allow_delete_with_instance
    {
        return Err(CarbideCliError::GenericError(
                "Machine has an associated instance, use --allow-delete-with-instance to acknowledge that this machine should be deleted with an instance allocated".to_string(),
            ));
    }

    loop {
        let response = api_client
            .0
            .admin_force_delete_machine(AdminForceDeleteMachineRequest {
                host_query: query.machine.clone(),
                delete_interfaces: query.delete_interfaces,
                delete_bmc_interfaces: query.delete_bmc_interfaces,
                delete_bmc_credentials: query.delete_bmc_credentials,
            })
            .await?;
        println!(
            "Force delete response: {}",
            serde_json::to_string_pretty(&response)?
        );

        if dpu_machine_id.is_empty() && !response.dpu_machine_id.is_empty() {
            dpu_machine_id = response.dpu_machine_id;
        }

        if response.all_done {
            println!("Force delete for {} succeeded", query.machine);

            // If we only searched for a Machine, then the DPU might be left behind
            // since the site controller can't look up the DPU by host machine ID anymore.
            // To also clean up the DPU, we modify our query and continue to delete
            if !dpu_machine_id.is_empty() && query.machine != dpu_machine_id {
                println!("Starting to delete potentially stale DPU machine {dpu_machine_id}");
                query.machine = dpu_machine_id.clone();
            } else {
                // No DPU to delete
                break;
            }
        }

        if start.elapsed() > MAX_WAIT_TIME {
            return Err(CarbideCliError::GenericError(format!(
                "Unable to force delete machine after {}s. Exiting",
                MAX_WAIT_TIME.as_secs()
            )));
        }

        println!(
            "Machine has not been fully deleted. Retrying after {}s",
            RETRY_TIME.as_secs()
        );
        tokio::time::sleep(RETRY_TIME).await;
    }

    Ok(())
}

pub async fn autoupdate(cfg: MachineAutoupdate, api_client: &ApiClient) -> CarbideCliResult<()> {
    let _response = api_client.machine_set_auto_update(cfg).await?;
    Ok(())
}

pub async fn get_next_free_machine(
    api_client: &ApiClient,
    machine_ids: &mut VecDeque<MachineId>,
    min_interface_count: usize,
) -> Option<Machine> {
    while let Some(id) = machine_ids.pop_front() {
        tracing::debug!("Checking {}", id);
        if let Ok(machine) = api_client.get_machine(id).await {
            if machine.state != "Ready" {
                tracing::debug!("Machine is not ready");
                continue;
            }
            if let Some(discovery_info) = &machine.discovery_info {
                let dpu_interfaces = discovery_info
                    .network_interfaces
                    .iter()
                    .filter(|i| {
                        i.pci_properties.as_ref().is_some_and(|pci_properties| {
                            pci_properties
                                .vendor
                                .to_ascii_lowercase()
                                .contains("mellanox")
                        })
                    })
                    .count();

                if dpu_interfaces >= min_interface_count && machine.state == "Ready" {
                    return Some(machine);
                }
            }
        }
    }
    None
}

pub async fn handle_update_machine_hardware_info_gpus(
    api_client: &ApiClient,
    gpus: MachineHardwareInfoGpus,
) -> CarbideCliResult<()> {
    let gpu_file_contents = fs::read_to_string(gpus.gpu_json_file)?;
    let gpus_from_json: Vec<::rpc::machine_discovery::Gpu> =
        serde_json::from_str(&gpu_file_contents)?;
    api_client
        .update_machine_hardware_info(
            gpus.machine,
            forgerpc::MachineHardwareInfoUpdateType::Gpus,
            gpus_from_json,
        )
        .await
}

pub fn handle_show_machine_hardware_info(
    _api_client: &ApiClient,
    _output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    _output_format: &OutputFormat,
    _machine_id: MachineId,
) -> CarbideCliResult<()> {
    Err(CarbideCliError::NotImplemented(
        "machine hardware output".to_string(),
    ))
}

pub async fn handle_metadata_show(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    _extended: bool,
    machine: Machine,
) -> CarbideCliResult<()> {
    let metadata = machine.metadata.ok_or(CarbideCliError::Empty)?;

    match output_format {
        OutputFormat::AsciiTable => {
            async_writeln!(output_file, "Name        : {}", metadata.name)?;
            async_writeln!(output_file, "Description : {}", metadata.description)?;
            let mut table = Table::new();
            table.set_titles(Row::from(vec!["Key", "Value"]));
            for l in &metadata.labels {
                table.add_row(Row::from(vec![&l.key, l.value.as_deref().unwrap_or("")]));
            }
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::NotImplemented(
                "CSV formatted output".to_string(),
            ));
        }
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(&metadata)?)?
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn dpu_ssh_credentials(
    api_client: &ApiClient,
    query: MachineQuery,
    format: OutputFormat,
) -> CarbideCliResult<()> {
    let cred = api_client
        .0
        .get_dpu_ssh_credential(query.query.to_string())
        .await?;
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&cred)?);
    } else {
        println!("{}:{}", cred.username, cred.password);
    }
    Ok(())
}

pub async fn network(
    api_client: &ApiClient,
    cmd: NetworkCommand,
    format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
) -> CarbideCliResult<()> {
    match cmd {
        NetworkCommand::Status => {
            println!(
                "Deprecated: Use dpu network, instead machine network. machine network will be removed in future."
            );
            dpu::cmds::show_dpu_status(api_client, output_file).await?;
        }
        NetworkCommand::Config(query) => {
            println!(
                "Deprecated: Use dpu network, instead of machine network. machine network will be removed in future."
            );
            let network_config = api_client
                .0
                .get_managed_host_network_config(query.machine_id)
                .await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::ser::to_string_pretty(&network_config)?);
            } else {
                // someone might be parsing this output
                println!("{network_config:?}");
            }
        }
    }
    Ok(())
}

pub async fn reboot(api_client: &ApiClient, args: BMCConfigForReboot) -> CarbideCliResult<()> {
    let res = api_client
        .admin_power_control(
            None,
            Some(args.machine),
            ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart,
        )
        .await?;

    if let Some(msg) = res.msg {
        println!("{msg}");
    }
    Ok(())
}

pub async fn metadata(
    api_client: &ApiClient,
    cmd: MachineMetadataCommand,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    format: OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    match cmd {
        MachineMetadataCommand::Show(cmd) => {
            metadata_show(api_client, cmd, output_file, format, extended).await
        }
        MachineMetadataCommand::Set(cmd) => metadata_set(api_client, cmd).await,
        MachineMetadataCommand::AddLabel(cmd) => metadata_add_label(api_client, cmd).await,
        MachineMetadataCommand::RemoveLabels(cmd) => metadata_remove_labels(api_client, cmd).await,
        MachineMetadataCommand::FromExpectedMachine(cmd) => {
            metadata_from_expected_machine(api_client, cmd).await
        }
    }
}

pub async fn metadata_show(
    api_client: &ApiClient,
    cmd: MachineMetadataCommandShow,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    format: OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_machines_by_ids(&[cmd.machine])
        .await?
        .machines;
    let Some(machine) = machines.pop() else {
        return Err(CarbideCliError::GenericError(format!(
            "Machine with ID {} was not found",
            cmd.machine
        )));
    };
    handle_metadata_show(output_file, &format, extended, machine).await
}

pub async fn metadata_set(
    api_client: &ApiClient,
    cmd: MachineMetadataCommandSet,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_machines_by_ids(&[cmd.machine])
        .await?
        .machines;
    if machines.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "Machine with ID {} was not found",
            cmd.machine
        )));
    }
    let machine = machines.remove(0);

    let mut metadata = machine.metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Machine does not carry Metadata that can be patched".into())
    })?;
    if let Some(name) = cmd.name {
        metadata.name = name;
    }
    if let Some(description) = cmd.description {
        metadata.description = description;
    }

    api_client
        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
        .await?;
    Ok(())
}

pub async fn metadata_add_label(
    api_client: &ApiClient,
    cmd: MachineMetadataCommandAddLabel,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_machines_by_ids(&[cmd.machine])
        .await?
        .machines;
    if machines.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "Machine with ID {} was not found",
            cmd.machine
        )));
    }
    let machine = machines.remove(0);

    let mut metadata = machine.metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Machine does not carry Metadata that can be patched".into())
    })?;
    metadata.labels.retain_mut(|l| l.key != cmd.key);
    metadata.labels.push(::rpc::forge::Label {
        key: cmd.key,
        value: cmd.value,
    });

    api_client
        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
        .await?;
    Ok(())
}

pub async fn metadata_remove_labels(
    api_client: &ApiClient,
    cmd: MachineMetadataCommandRemoveLabels,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_machines_by_ids(&[cmd.machine])
        .await?
        .machines;
    if machines.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "Machine with ID {} was not found",
            cmd.machine
        )));
    }
    let machine = machines.remove(0);

    let mut metadata = machine.metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Machine does not carry Metadata that can be patched".into())
    })?;

    // Retain everything that isn't specified as removed
    let removed_labels: HashSet<String> = cmd.keys.into_iter().collect();
    metadata.labels.retain(|l| !removed_labels.contains(&l.key));

    api_client
        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
        .await?;
    Ok(())
}

pub async fn metadata_from_expected_machine(
    api_client: &ApiClient,
    cmd: MachineMetadataCommandFromExpectedMachine,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_machines_by_ids(&[cmd.machine])
        .await?
        .machines;
    if machines.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "Machine with ID {} was not found",
            cmd.machine
        )));
    }
    let machine = machines.remove(0);
    let bmc_mac: MacAddress = machine
        .bmc_info
        .and_then(|bmc_info| bmc_info.mac)
        .map(|mac| mac.parse())
        .transpose()
        .map_or_else(
            |e| {
                Err(CarbideCliError::GenericError(format!(
                    "Invalid BMC MAC address found for Machine with ID {}: {}",
                    cmd.machine, e
                )))
            },
            Ok,
        )?
        .ok_or_else(|| {
            CarbideCliError::GenericError(format!(
                "No BMC MAC address found for Machine with ID {}",
                cmd.machine
            ))
        })?;

    let mut metadata = machine.metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Machine does not carry Metadata that can be patched".into())
    })?;

    let expected_machines = api_client
        .0
        .get_all_expected_machines()
        .await?
        .expected_machines;
    let expected_machine = expected_machines
        .into_iter()
        .find(|em| {
            em.bmc_mac_address
                .parse::<MacAddress>()
                .is_ok_and(|m| m == bmc_mac)
        })
        .ok_or_else(|| {
            CarbideCliError::GenericError(format!(
                "No expected Machine found for Machine with ID {} and BMC Mac address {}",
                cmd.machine, bmc_mac
            ))
        })?;

    let expected_machine_metadata = expected_machine.metadata.ok_or_else(|| {
        CarbideCliError::GenericError(format!(
            "No expected Machine Metadata found for Machine with ID {} and BMC Mac address {}",
            cmd.machine, bmc_mac
        ))
    })?;

    if cmd.replace_all {
        // Configure the Machines metadata in the same way as if the Machine was freshly ingested
        metadata.name = if expected_machine_metadata.name.is_empty() {
            machine.id.map(|id| id.to_string()).unwrap_or_default()
        } else {
            expected_machine_metadata.name
        };
        metadata.description = expected_machine_metadata.description;
        metadata.labels = expected_machine_metadata.labels;
    } else {
        // Add new data from expected-machines, but current values that might have been the
        // result of previous changed to the Machine.
        // This operation is lossless for existing Metadata.
        if !expected_machine_metadata.name.is_empty()
            && (metadata.name.is_empty() || metadata.name == cmd.machine.to_string())
        {
            metadata.name = expected_machine_metadata.name;
        };
        if !expected_machine_metadata.description.is_empty() && metadata.description.is_empty() {
            metadata.description = expected_machine_metadata.description;
        };
        for label in expected_machine_metadata.labels {
            if !metadata.labels.iter().any(|l| l.key == label.key) {
                metadata.labels.push(label);
            }
        }
    }

    api_client
        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
        .await?;
    Ok(())
}

pub async fn positions(args: Positions, api_client: &ApiClient) -> CarbideCliResult<()> {
    let machine_ids = if args.machine.is_empty() {
        // Query all machines if none specified
        api_client
            .0
            .find_machine_ids(forgerpc::MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                ..Default::default()
            })
            .await?
            .machine_ids
    } else {
        args.machine
    };

    let req = forgerpc::MachinePositionQuery { machine_ids };
    let info = api_client.0.get_machine_position_info(req).await?;
    let mut table = Table::new();
    table.set_titles(Row::from(vec![
        "Machine ID",
        "Physical Slot",
        "Compute Tray",
        "Topology",
        "Revision",
        "Switch",
        "Power Shelf",
    ]));
    for x in info.machine_position_info {
        table.add_row(row![
            x.machine_id.unwrap_or_default(),
            x.physical_slot_number
                .map(|x| x.to_string())
                .unwrap_or("---".to_string()),
            x.compute_tray_index
                .map(|x| x.to_string())
                .unwrap_or("---".to_string()),
            x.topology_id
                .map(|x| x.to_string())
                .unwrap_or("---".to_string()),
            x.revision_id
                .map(|x| x.to_string())
                .unwrap_or("---".to_string()),
            x.switch_id
                .map(|id| id.to_string())
                .unwrap_or("---".to_string()),
            x.power_shelf_id
                .map(|id| id.to_string())
                .unwrap_or("---".to_string()),
        ]);
    }
    table.printstd();

    Ok(())
}

pub async fn handle_nvlink_info_show(
    args: NvlinkInfoArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(args.machine_id).await?;

    // Check if this is an MNNVL machine (GB200)
    let is_mnnvl = machine
        .discovery_info
        .as_ref()
        .and_then(|info| info.dmi_data.as_ref())
        .map(|dmi| dmi.product_name.contains("GB200"))
        .unwrap_or(false);

    if !is_mnnvl {
        return Err(CarbideCliError::GenericError(format!(
            "Machine {} is not an MNNVL machine",
            args.machine_id
        )));
    }

    match machine.nvlink_info {
        Some(nvlink_info) => {
            println!("{}", serde_json::to_string_pretty(&nvlink_info)?);
        }
        None => {
            return Err(CarbideCliError::GenericError(format!(
                "Machine {} has no nvlink_info in database",
                args.machine_id
            )));
        }
    }

    Ok(())
}

pub async fn handle_nvlink_info_populate(
    args: NvlinkInfoPopulateArgs,
    _output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(args.machine_id).await?;
    let update_db = args.update_db;

    // Check if this is an MNNVL machine (GB200)
    let is_mnnvl = machine
        .discovery_info
        .as_ref()
        .and_then(|info| info.dmi_data.as_ref())
        .map(|dmi| dmi.product_name.contains("GB200"))
        .unwrap_or(false);

    if !is_mnnvl {
        return Err(CarbideCliError::GenericError(format!(
            "Machine {} is not an MNNVL machine",
            args.machine_id
        )));
    }

    let bmc_ip = machine
        .bmc_info
        .as_ref()
        .and_then(|b| b.ip.clone())
        .ok_or_else(|| CarbideCliError::GenericError("No BMC IP available".to_string()))?;

    // Fetch nmx-m compute nodes and build lookup map by (serial_number, tray_index)
    let nmxm_compute_nodes: HashMap<(String, i32), serde_json::Value> = match api_client
        .0
        .nmxm_browse("nmx/v1/compute-nodes".to_string())
        .await
    {
        Ok(response) => {
            // Check for HTTP error codes
            if response.code < 200 || response.code >= 300 {
                return Err(CarbideCliError::GenericError(format!(
                    "NMX-M compute-nodes request failed with HTTP {}: {}",
                    response.code, response.body
                )));
            }
            if let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&response.body) {
                nodes
                    .into_iter()
                    .filter_map(|node| {
                        let location_info = node.get("LocationInfo")?;
                        let serial = location_info
                            .get("ChassisSerialNumber")?
                            .as_str()?
                            .to_string();
                        let tray_idx = location_info.get("TrayIndex")?.as_i64()? as i32;
                        Some(((serial, tray_idx), node))
                    })
                    .collect()
            } else {
                HashMap::new()
            }
        }
        Err(e) => {
            return Err(CarbideCliError::GenericError(format!(
                "Failed to fetch nmx-m compute nodes: {}",
                e
            )));
        }
    };

    // Fetch Redfish data
    let uri = format!("https://{}/redfish/v1/Chassis/CBC_0", bmc_ip);

    let redfish_response = api_client
        .0
        .redfish_browse(uri.clone())
        .await
        .map_err(|e| CarbideCliError::GenericError(format!("Redfish call failed: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&redfish_response.text).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to parse Redfish response: {}", e))
    })?;

    // Extract Oem.Nvidia.ComputeTrayIndex
    let tray_index = json
        .get("Oem")
        .and_then(|oem| oem.get("Nvidia"))
        .and_then(|nvidia| nvidia.get("ComputeTrayIndex"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .ok_or_else(|| {
            CarbideCliError::GenericError("No tray_index found in Redfish response".to_string())
        })?;

    // Extract SerialNumber
    let serial_number = json
        .get("SerialNumber")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            CarbideCliError::GenericError("No SerialNumber found in Redfish response".to_string())
        })?;

    // Look up matching nmx-m compute node
    let nmxm_node = nmxm_compute_nodes
        .get(&(serial_number.clone(), tray_index))
        .ok_or_else(|| {
            CarbideCliError::GenericError(format!(
                "No NMX-M compute node found for serial={}, tray_index={}",
                serial_number, tray_index
            ))
        })?;

    let domain_uuid = nmxm_node
        .get("DomainUUID")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CarbideCliError::GenericError("No DomainUUID found in NMX-M response".to_string())
        })?;

    let gpu_id_list: Vec<String> = nmxm_node
        .get("GpuIDList")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if gpu_id_list.is_empty() {
        return Err(CarbideCliError::GenericError(
            "No GPUs found in NMX-M compute node".to_string(),
        ));
    }

    // Fetch GPU details from nmx-m for each GPU in the list
    let mut gpus: Vec<forgerpc::NvLinkGpu> = Vec::new();
    for gpu_id in &gpu_id_list {
        let gpu_path = format!("nmx/v1/gpus/{}", gpu_id);
        let gpu_response = api_client
            .0
            .nmxm_browse(gpu_path.clone())
            .await
            .map_err(|e| {
                CarbideCliError::GenericError(format!("Failed to fetch GPU {}: {}", gpu_id, e))
            })?;

        // Check for HTTP error codes
        if gpu_response.code < 200 || gpu_response.code >= 300 {
            return Err(CarbideCliError::GenericError(format!(
                "NMX-M GPU {} request failed with HTTP {}: {}",
                gpu_id, gpu_response.code, gpu_response.body
            )));
        }

        let gpu_json: serde_json::Value =
            serde_json::from_str(&gpu_response.body).map_err(|e| {
                CarbideCliError::GenericError(format!(
                    "Failed to parse GPU {} response: {}",
                    gpu_id, e
                ))
            })?;

        let gpu_nmx_m_id = gpu_json
            .get("ID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let gpu_device_id = gpu_json
            .get("DeviceID")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let gpu_device_uid = gpu_json
            .get("DeviceUID")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let gpu_location = gpu_json.get("LocationInfo");
        let gpu_tray_index = gpu_location
            .and_then(|loc| loc.get("TrayIndex"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let gpu_slot_id = gpu_location
            .and_then(|loc| loc.get("SlotID"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        gpus.push(forgerpc::NvLinkGpu {
            nmx_m_id: gpu_nmx_m_id,
            device_id: gpu_device_id,
            guid: gpu_device_uid,
            tray_index: gpu_tray_index,
            slot_id: gpu_slot_id,
        });
    }

    // Parse domain_uuid as UUID
    let domain_uuid_parsed = uuid::Uuid::parse_str(domain_uuid).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to parse domain_uuid: {}", e))
    })?;

    // Build the nvlink_info structure for RPC
    let nvlink_info_rpc = forgerpc::MachineNvLinkInfo {
        domain_uuid: Some(carbide_uuid::nvlink::NvLinkDomainId::from(
            domain_uuid_parsed,
        )),
        gpus: gpus.clone(),
    };

    // Build the nvlink_info structure as JSON for display
    let nvlink_info = serde_json::json!({
        "domain_uuid": domain_uuid,
        "gpus": gpus.iter().map(|g| serde_json::json!({
            "nmx_m_id": g.nmx_m_id,
            "device_id": g.device_id,
            "guid": g.guid,
            "tray_index": g.tray_index,
            "slot_id": g.slot_id,
        })).collect::<Vec<_>>(),
    });

    if update_db {
        api_client
            .update_machine_nvlink_info(args.machine_id, nvlink_info_rpc)
            .await?;
        println!("Updated nvlink_info in db with the following nvlink-info:");
    } else {
        println!("\n\n Use --update-db option to apply the following nvlink-info:");
    }

    println!("{}", serde_json::to_string_pretty(&nvlink_info)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use health_report::{HealthAlertClassification, HealthProbeId};

    use super::*;

    #[test]
    fn test_tenant_reported_issue_template() {
        let report = get_health_report(
            HealthOverrideTemplates::TenantReportedIssue,
            Some("Customer reported network connectivity issues".to_string()),
        );

        assert_eq!(report.source, "tenant-reported-issue");
        assert_eq!(report.alerts.len(), 1);

        let alert = &report.alerts[0];
        assert_eq!(
            alert.id,
            HealthProbeId::from_str("TenantReportedIssue").unwrap()
        );
        assert_eq!(alert.target, Some("tenant-reported".to_string()));
        assert_eq!(
            alert.message,
            "Customer reported network connectivity issues"
        );
        assert!(alert.tenant_message.is_none());

        // Check classifications
        assert_eq!(alert.classifications.len(), 2);
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::prevent_allocations())
        );
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }

    #[test]
    fn test_request_repair_template() {
        let report = get_health_report(
            HealthOverrideTemplates::RequestRepair,
            Some("Hardware diagnostics indicate memory failure".to_string()),
        );

        assert_eq!(report.source, "repair-request");
        assert_eq!(report.alerts.len(), 1);

        let alert = &report.alerts[0];
        assert_eq!(alert.id, HealthProbeId::from_str("RequestRepair").unwrap());
        assert_eq!(alert.target, Some("repair-requested".to_string()));
        assert_eq!(
            alert.message,
            "Hardware diagnostics indicate memory failure"
        );
        assert!(alert.tenant_message.is_none());

        // Check classifications
        assert_eq!(alert.classifications.len(), 2);
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::prevent_allocations())
        );
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }

    #[test]
    fn test_tenant_reported_issue_template_with_empty_message() {
        let report = get_health_report(HealthOverrideTemplates::TenantReportedIssue, None);

        assert_eq!(report.source, "tenant-reported-issue");
        assert_eq!(report.alerts[0].message, "");
    }

    #[test]
    fn test_request_repair_template_with_empty_message() {
        let report = get_health_report(HealthOverrideTemplates::RequestRepair, None);

        assert_eq!(report.source, "repair-request");
        assert_eq!(report.alerts[0].message, "");
    }

    #[test]
    fn test_new_templates_have_suppress_external_alerting() {
        // Verify both new templates include SuppressExternalAlerting classification
        let tenant_report = get_health_report(
            HealthOverrideTemplates::TenantReportedIssue,
            Some("test".to_string()),
        );
        let repair_report = get_health_report(
            HealthOverrideTemplates::RequestRepair,
            Some("test".to_string()),
        );

        // Both should suppress external alerting
        assert!(
            tenant_report.alerts[0]
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
        assert!(
            repair_report.alerts[0]
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }
}
