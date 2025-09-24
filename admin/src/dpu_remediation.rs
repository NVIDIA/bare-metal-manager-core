/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{fmt::Write, pin::Pin};

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use forge_uuid::{dpu_remediations::RemediationId, machine::MachineId};
use prettytable::{Table, row};
use rpc::forge::{AppliedRemediationIdList, AppliedRemediationList, Remediation, RemediationList};

use crate::{
    async_write, async_writeln,
    cfg::cli_options::{
        ApproveDpuRemediation, CreateDpuRemediation, DisableDpuRemediation, EnableDpuRemediation,
        ListAppliedRemediations, RevokeDpuRemediation, ShowRemediation,
    },
    rpc::ApiClient,
};

pub async fn create_dpu_remediation(
    create_remediation: CreateDpuRemediation,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let script = tokio::fs::read_to_string(&create_remediation.script_filename)
        .await
        .map_err(|err| {
            tracing::error!("Error reading script file for dpu remediation: {:?}", err);
            CarbideCliError::IOError(err)
        })?;

    let response = api_client
        .create_dpu_remediation(
            script,
            create_remediation.metadata(),
            create_remediation.retries,
        )
        .await?;

    tracing::info!("Created remediation with id: {:?}", response.remediation_id);
    Ok(())
}

pub async fn approve_dpu_remediation(
    approve_remediation: ApproveDpuRemediation,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    api_client
        .approve_dpu_remediation(approve_remediation.id)
        .await?;

    tracing::info!("Approved remediation with id: {:?}", approve_remediation.id);
    Ok(())
}

pub async fn revoke_dpu_remediation(
    revoke_remediation: RevokeDpuRemediation,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    api_client
        .revoke_dpu_remediation(revoke_remediation.id)
        .await?;

    tracing::info!("Revoked remediation with id: {:?}", revoke_remediation.id);
    Ok(())
}

pub async fn enable_dpu_remediation(
    enable_remediation: EnableDpuRemediation,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    api_client
        .enable_dpu_remediation(enable_remediation.id)
        .await?;

    tracing::info!("Enabled remediation with id: {:?}", enable_remediation.id);
    Ok(())
}

pub async fn disable_dpu_remediation(
    disable_remediation: DisableDpuRemediation,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    api_client
        .disable_dpu_remediation(disable_remediation.id)
        .await?;

    tracing::info!("Disabled remediation with id: {:?}", disable_remediation.id);
    Ok(())
}

pub(crate) async fn handle_list_applied(
    args: ListAppliedRemediations,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    match (args.remediation_id, args.machine_id) {
        (Some(remediation_id), Some(machine_id)) => {
            show_applied_remediation_details(
                remediation_id,
                machine_id,
                output_format,
                output_file,
                api_client,
                page_size,
            )
            .await?;
        }
        (Some(remediation_id), None) => {
            show_machines_for_applied_remediation(
                remediation_id,
                output_format,
                output_file,
                api_client,
                page_size,
            )
            .await?;
        }
        (None, Some(machine_id)) => {
            show_applied_remediations_for_machine(
                machine_id,
                output_format,
                output_file,
                api_client,
                page_size,
            )
            .await?;
        }
        (None, None) => {
            return Err(CarbideCliError::GenericError(
                "Invalid arguments, must provide at least one of remediation_id or machine_id"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

async fn show_applied_remediation_details(
    remediation_id: RemediationId,
    machine_id: MachineId,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let applied_remediations = api_client
        .find_applied_remediations(remediation_id, machine_id)
        .await?;
    match output_format {
        OutputFormat::AsciiTable => {
            let table = convert_applied_remediations_to_nice_table(applied_remediations);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Json => {
            async_writeln!(
                output_file,
                "{}",
                serde_json::to_string_pretty(&applied_remediations)?
            )?;
        }
        OutputFormat::Csv | OutputFormat::Yaml => {
            unimplemented!()
        }
    }

    Ok(())
}

async fn show_machines_for_applied_remediation(
    remediation_id: RemediationId,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let applied_remediation_ids = api_client
        .find_applied_remediations_by_remediation_id(remediation_id)
        .await?;
    match output_format {
        OutputFormat::AsciiTable => {
            let table = show_machines_applied_for_remediation(applied_remediation_ids);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Json => {
            async_writeln!(
                output_file,
                "{}",
                serde_json::to_string_pretty(&applied_remediation_ids)?
            )?;
        }
        OutputFormat::Csv | OutputFormat::Yaml => {
            unimplemented!()
        }
    }

    Ok(())
}

async fn show_applied_remediations_for_machine(
    machine_id: MachineId,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let applied_remediation_ids = api_client
        .find_applied_remediations_by_machine_id(machine_id)
        .await?;
    match output_format {
        OutputFormat::AsciiTable => {
            let table = show_remediations_applied_for_machine(applied_remediation_ids);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Json => {
            async_writeln!(
                output_file,
                "{}",
                serde_json::to_string_pretty(&applied_remediation_ids)?
            )?;
        }
        OutputFormat::Csv | OutputFormat::Yaml => {
            unimplemented!()
        }
    }

    Ok(())
}

fn show_machines_applied_for_remediation(
    applied_remediation_ids: AppliedRemediationIdList,
) -> Box<Table> {
    assert_eq!(applied_remediation_ids.remediation_ids.len(), 1);
    let remediation_id = applied_remediation_ids.remediation_ids[0];
    let mut table = Box::new(Table::new());

    table.set_titles(row!["Id", "Machine Id",]);
    if applied_remediation_ids.dpu_machine_ids.is_empty() {
        table.add_row(row![remediation_id.to_string(), "None"]);
    } else {
        for machine_id in applied_remediation_ids.dpu_machine_ids.into_iter() {
            table.add_row(row![remediation_id.to_string(), machine_id.to_string(),]);
        }
    }

    table
}

fn show_remediations_applied_for_machine(
    applied_remediation_ids: AppliedRemediationIdList,
) -> Box<Table> {
    assert_eq!(applied_remediation_ids.dpu_machine_ids.len(), 1);
    let machine_id = applied_remediation_ids.dpu_machine_ids[0];
    let mut table = Box::new(Table::new());

    table.set_titles(row!["Machine Id", "Remediation Id",]);
    if applied_remediation_ids.remediation_ids.is_empty() {
        table.add_row(row![machine_id.to_string(), "None"]);
    } else {
        for remediation_id in applied_remediation_ids.remediation_ids.into_iter() {
            table.add_row(row![machine_id.to_string(), remediation_id.to_string(),]);
        }
    }

    table
}

fn convert_applied_remediations_to_nice_table(
    applied_remediations: AppliedRemediationList,
) -> Box<Table> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Id",
        "Machine Id",
        "Applied Time",
        "Succeeded",
        "Attempt #",
        "Labels",
    ]);

    if applied_remediations.applied_remediations.is_empty() {
        table.add_row(row!["None", "None", "None", "None", "None", "None",]);
    } else {
        for applied_remediations in applied_remediations.applied_remediations.into_iter() {
            let labels =
                crate::metadata::get_nice_labels_from_rpc_metadata(&applied_remediations.metadata);

            table.add_row(row![
                applied_remediations
                    .remediation_id
                    .unwrap_or_default()
                    .to_string(),
                applied_remediations
                    .dpu_machine_id
                    .unwrap_or_default()
                    .to_string(),
                applied_remediations.applied_time.unwrap_or_default(),
                applied_remediations.succeeded,
                applied_remediations.attempt,
                labels.join(", ")
            ]);
        }
    }

    table
}

pub(crate) async fn handle_show(
    args: ShowRemediation,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    if let Some(remediation_id) = args.id {
        show_remediation_information(
            remediation_id,
            output_format,
            output_file,
            args.display_script,
            api_client,
        )
        .await
    } else {
        show_all_remediations(output_format, output_file, api_client, page_size).await
    }
}

fn convert_remediation_to_nice_format(
    remediation: Remediation,
    display_script: bool,
) -> CarbideCliResult<String> {
    let mut lines = String::new();

    let data = vec![
        ("ID", remediation.id.unwrap_or_default().to_string()),
        ("AUTHOR", remediation.script_author),
        (
            "REVIEWER",
            remediation.script_reviewed_by.unwrap_or_default(),
        ),
        (
            "CREATION_TIME",
            remediation.creation_time.unwrap_or_default().to_string(),
        ),
        ("RETRIES", remediation.retries.to_string()),
        ("ENABLED", remediation.enabled.to_string()),
    ];

    let width = 1 + data
        .iter()
        .fold(0, |accum, (key, _value)| std::cmp::max(accum, key.len()));

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    if let Some(metadata) = remediation.metadata {
        writeln!(&mut lines, "METADATA: ")?;
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
    } else {
        writeln!(&mut lines, "{:<width$}: None", "METADATA")?;
    }

    if display_script {
        writeln!(
            &mut lines,
            "{:<width$}:\n***************************************BEGIN-SCRIPT********************************\n{}\n***************************************END-SCRIPT**********************************",
            "SCRIPT", remediation.script
        )?;
    }

    Ok(lines)
}

async fn show_remediation_information(
    remediation_id: RemediationId,
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    display_script: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let remediation = api_client.get_remediation(remediation_id).await?;

    match output_format {
        OutputFormat::AsciiTable => {
            let table = convert_remediation_to_nice_format(remediation, display_script)?;
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Json => {
            async_writeln!(
                output_file,
                "{}",
                serde_json::to_string_pretty(&remediation)?
            )?;
        }
        OutputFormat::Csv | OutputFormat::Yaml => {
            unimplemented!()
        }
    }

    Ok(())
}

async fn show_all_remediations(
    output_format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let remediations = api_client.get_all_remediations(page_size).await?;
    match output_format {
        OutputFormat::AsciiTable => {
            let table = convert_remediations_to_nice_table(remediations);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Json => {
            async_writeln!(
                output_file,
                "{}",
                serde_json::to_string_pretty(&remediations)?
            )?;
        }
        OutputFormat::Csv | OutputFormat::Yaml => {
            unimplemented!()
        }
    }
    Ok(())
}

fn convert_remediations_to_nice_table(remediations: RemediationList) -> Box<Table> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Id",
        "Creation Time",
        "Author",
        "Reviewer",
        "Enabled",
        "Retries",
        "Labels",
    ]);

    if remediations.remediations.is_empty() {
        table.add_row(row!["None", "None", "None", "None", "None", "None", "None"]);
    } else {
        for remediation in remediations.remediations.into_iter() {
            let labels = crate::metadata::get_nice_labels_from_rpc_metadata(&remediation.metadata);

            table.add_row(row![
                remediation.id.unwrap_or_default().to_string(),
                remediation.creation_time.unwrap_or_default(),
                remediation.script_author,
                remediation.script_reviewed_by.unwrap_or_default(),
                remediation.enabled,
                remediation.retries,
                labels.join(", ")
            ]);
        }
    }

    table
}
