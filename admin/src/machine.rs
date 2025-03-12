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
use std::collections::VecDeque;

use super::cfg::cli_options::{HealthOverrideTemplates, MachineHardwareInfoGpus, ShowMachine};
use super::default_uuid;
use crate::cfg::cli_options::{ForceDeleteMachineQuery, MachineAutoupdate, OverrideCommand};
use crate::rpc::ApiClient;
use ::rpc::forge as forgerpc;
use chrono::Utc;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess, HealthReport,
};
use prettytable::{Table, row};
use std::fmt::Write;
use std::fs;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;
use utils::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};

fn convert_machine_to_nice_format(
    machine: forgerpc::Machine,
    history_count: u32,
) -> CarbideCliResult<String> {
    let width = 14;
    let mut lines = String::new();
    let machine_id = machine.id.clone().unwrap_or_default().id;
    let sku = machine.hw_sku.unwrap_or_default();

    let mut data = vec![
        ("ID", machine.id.clone().unwrap_or_default().id),
        ("STATE", machine.state.clone().to_uppercase()),
        ("STATE_VERSION", machine.state_version.clone()),
        ("MACHINE TYPE", get_machine_type(&machine_id)),
        (
            "FAILURE",
            machine
                .failure_details
                .clone()
                .unwrap_or("None".to_string()),
        ),
        ("VERSION", machine.version),
        ("SKU", sku),
    ];
    if let Some(di) = machine.discovery_info.as_ref() {
        if let Some(dmi) = di.dmi_data.as_ref() {
            data.push(("VENDOR", dmi.sys_vendor.clone()));
            data.push(("PRODUCT NAME", dmi.product_name.clone()));
            data.push(("PRODUCT SERIAL", dmi.product_serial.clone()));
            data.push(("BOARD SERIAL", dmi.board_serial.clone()));
            data.push(("CHASSIS SERIAL", dmi.chassis_serial.clone()));
            data.push(("BIOS VERSION", dmi.bios_version.clone()));
            data.push(("BOARD VERSION", dmi.board_version.clone()));
        }
    }
    let autoupdate = if let Some(autoupdate) = machine.firmware_autoupdate {
        autoupdate.to_string()
    } else {
        "Default".to_string()
    };
    data.push(("FIRMWARE AUTOUPDATE", autoupdate));

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
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

    writeln!(&mut lines, "STATE HISTORY: (Latest {} only)", history_count)?;
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
        writeln!(&mut lines, "\t{}", div)?;
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

    let width = 13;
    writeln!(&mut lines, "INTERFACES:")?;
    if machine.interfaces.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, interface) in machine.interfaces.into_iter().enumerate() {
            let data = vec![
                ("SN", i.to_string()),
                ("ID", interface.id.clone().unwrap_or_default().to_string()),
                (
                    "DPU ID",
                    interface
                        .attached_dpu_machine_id
                        .as_ref()
                        .map(::rpc::common::MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Machine ID",
                    interface
                        .machine_id
                        .as_ref()
                        .map(::rpc::common::MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Segment ID",
                    interface
                        .segment_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "Domain ID",
                    interface
                        .domain_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                ("Hostname", interface.hostname.clone()),
                ("Primary", interface.primary_interface.to_string()),
                ("MAC Address", interface.mac_address.clone()),
                ("Addresses", interface.address.join(",")),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    Ok(lines)
}

fn get_machine_type(machine_id: &str) -> String {
    if machine_id.starts_with("fm100p") {
        "Host (Predicted)"
    } else if machine_id.starts_with("fm100h") {
        "Host"
    } else {
        "DPU"
    }
    .to_string()
}

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> Box<Table> {
    let mut table = Box::new(Table::new());
    let default_metadata = Default::default();

    table.set_titles(row![
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
        let machine_id = machine.id.unwrap_or_default().id;
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
                get_machine_type(&machine_id),
                dpu_ids.join("\n"),
            )
        };
        let mut vendor = String::new();
        if let Some(di) = machine.discovery_info.as_ref() {
            if let Some(dmi) = di.dmi_data.as_ref() {
                vendor = dmi.sys_vendor.clone();
            }
        }

        let labels = machine
            .metadata
            .as_ref()
            .unwrap_or(&default_metadata)
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.clone().unwrap_or_default();
                format!("\"{}:{}\"", key, value)
            })
            .collect::<Vec<_>>();

        table.add_row(row![
            machine_id,
            machine.state.to_uppercase(),
            machine.state_version.clone(),
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
    json: bool,
    api_client: &ApiClient,
    machine_type: Option<forgerpc::MachineType>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let machines = api_client
        .get_all_machines(machine_type, false, page_size)
        .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&machines)?);
    } else {
        convert_machines_to_nice_table(machines).printstd();
    }
    Ok(())
}

async fn show_machine_information(
    args: &ShowMachine,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(args.machine.clone()).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&machine)?);
    } else {
        println!(
            "{}",
            convert_machine_to_nice_format(machine, args.history_count)
                .unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowMachine,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if !args.machine.is_empty() {
        show_machine_information(&args, is_json, api_client).await?;
    } else {
        let machine_type = if args.dpus {
            Some(forgerpc::MachineType::Dpu)
        } else if args.hosts {
            Some(forgerpc::MachineType::Host)
        } else {
            None
        };

        show_all_machines(is_json, api_client, machine_type, page_size).await?;
        // TODO(chet): Remove this ~March 2024.
        // Use tracing::warn for this so its both a little more
        // noticeable, and a little more annoying/naggy. If people
        // complain, it means its working.
        if args.all && output_format == OutputFormat::AsciiTable {
            warn!("redundant `--all` with basic `show` is deprecated. just do `machine show`")
        }
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

fn get_health_report(template: HealthOverrideTemplates, message: Option<String>) -> HealthReport {
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
                .machine_list_health_report_overrides(machine_id)
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
                .machine_remove_health_report_override(machine_id, report_source)
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

    if !api_client
        .get_instances_by_machine_id(query.machine.clone())
        .await?
        .instances
        .is_empty()
        && !query.allow_delete_with_instance
    {
        return Err(CarbideCliError::GenericError(
            "Machine has an associated instance, use --allow-delete-with-instance to acknowledge that this machine should be deleted with an instance allocated".to_string(),
        ));
    }

    loop {
        let response = api_client.machine_admin_force_delete(query.clone()).await?;
        println!(
            "Force delete response: {}",
            serde_json::to_string_pretty(&response)?
        );

        if dpu_machine_id.is_empty() && !response.dpu_machine_id.is_empty() {
            dpu_machine_id = response.dpu_machine_id.clone();
        }

        if response.all_done {
            println!("Force delete for {} succeeded", query.machine);

            // If we only searched for a Machine, then the DPU might be left behind
            // since the site controller can't look up the DPU by host machine ID anymore.
            // To also clean up the DPU, we modify our query and continue to delete
            if !dpu_machine_id.is_empty() && query.machine != dpu_machine_id {
                println!(
                    "Starting to delete potentially stale DPU machine {}",
                    dpu_machine_id
                );
                query.machine = dpu_machine_id.clone();
            } else {
                // No DPU to delete
                break;
            }
        }

        if start.elapsed() > MAX_WAIT_TIME {
            return Err(crate::CarbideCliError::GenericError(format!(
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
    machine_ids: &mut VecDeque<String>,
) -> Option<String> {
    while let Some(id) = machine_ids.pop_front() {
        let api_state = api_client
            .get_machine(id.clone())
            .await
            .map_or("<ERROR>".to_owned(), |machine| machine.state);
        if api_state == "Ready" {
            return Some(id.to_string());
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
            gpus.machine.clone(),
            forgerpc::MachineHardwareInfoUpdateType::Gpus,
            gpus_from_json,
        )
        .await
}

pub async fn handle_show_machine_hardware_info(
    _api_client: &ApiClient,
    _machine_id: String,
) -> CarbideCliResult<()> {
    println!("Show hardware info not yet implemented");
    Ok(())
}
