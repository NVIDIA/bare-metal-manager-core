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
use std::io::Write;
use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::SkuList;
use prettytable::{Row, Table};
use rpc::forge::{RemoveSkuRequest, SkuIdList, SkuMachinePair};
use tokio::io::AsyncWriteExt;

use super::args::{
    BulkUpdateSkuMetadata, CreateSku, GenerateSku, ShowSku, UnassignSku, UpdateSkuMetadata,
};
use crate::rpc::ApiClient;
use crate::{async_write_table_as_csv, async_writeln};

struct SkuWrapper {
    sku: ::rpc::forge::Sku,
}

struct SkusWrapper {
    skus: Vec<SkuWrapper>,
}

impl From<::rpc::forge::Sku> for SkuWrapper {
    fn from(sku: ::rpc::forge::Sku) -> Self {
        SkuWrapper { sku }
    }
}

impl From<Vec<SkuWrapper>> for SkusWrapper {
    fn from(skus: Vec<SkuWrapper>) -> Self {
        SkusWrapper { skus }
    }
}

impl From<SkuWrapper> for Row {
    fn from(sku: SkuWrapper) -> Self {
        let sku = sku.sku;

        Row::from(vec![
            sku.id,
            sku.description.unwrap_or_default(),
            sku.components
                .unwrap_or_default()
                .chassis
                .unwrap_or_default()
                .model,
            sku.created.map(|id| id.to_string()).unwrap_or_default(),
        ])
    }
}

impl From<SkusWrapper> for Table {
    fn from(skus: SkusWrapper) -> Self {
        let mut table = Table::new();

        table.set_titles(Row::from(vec!["ID", "Description", "Model", "Created"]));

        for sku in skus.skus {
            table.add_row(sku.into());
        }

        table
    }
}

fn create_table(header: Vec<&str>) -> Table {
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(header));
    table
}

fn cpu_table(cpus: Vec<::rpc::forge::SkuComponentCpu>) -> Table {
    let mut table = create_table(vec!["Vendor", "Model", "Threads", "Count"]);

    for cpu in cpus {
        table.add_row(Row::from(vec![
            cpu.vendor,
            cpu.model,
            cpu.thread_count.to_string(),
            cpu.count.to_string(),
        ]));
    }

    table
}

fn gpu_table(gpus: Vec<::rpc::forge::SkuComponentGpu>) -> Table {
    let mut table = create_table(vec!["Vendor", "Total Memory", "Model", "Count"]);
    for gpu in gpus {
        table.add_row(Row::from(vec![
            gpu.vendor,
            gpu.total_memory,
            gpu.model,
            gpu.count.to_string(),
        ]));
    }

    table
}

fn memory_table(memory: Vec<::rpc::forge::SkuComponentMemory>) -> Table {
    let mut table = create_table(vec!["Type", "Capacity", "Count"]);
    for m in memory {
        table.add_row(Row::from(vec![
            m.memory_type,
            ::utils::sku::capacity_string(m.capacity_mb as u64),
            m.count.to_string(),
        ]));
    }

    table
}

fn ib_device_table(devices: Vec<::rpc::forge::SkuComponentInfinibandDevices>) -> Table {
    let mut table = create_table(vec!["Vendor", "Model", "Count", "Inactive Devices"]);
    for dev in devices {
        let inactive_devices = serde_json::to_string(&dev.inactive_devices).unwrap();
        table.add_row(Row::from(vec![
            dev.vendor,
            dev.model,
            dev.count.to_string(),
            inactive_devices,
        ]));
    }

    table
}

fn storage_table(storage: Vec<::rpc::forge::SkuComponentStorage>) -> Table {
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(vec!["Model", "Count"]));
    for s in storage {
        table.add_row(Row::from(vec![s.model, s.count.to_string()]));
    }
    table
}

async fn show_skus_table(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    skus: Vec<::rpc::forge::Sku>,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(&skus)?)?;
        }
        OutputFormat::Csv => {
            let skus = SkusWrapper::from(
                skus.into_iter()
                    .map(std::convert::Into::into)
                    .collect::<Vec<SkuWrapper>>(),
            );
            let table: Table = skus.into();
            async_write_table_as_csv!(output_file, table)?;
        }
        OutputFormat::AsciiTable => {
            let skus = SkusWrapper::from(
                skus.into_iter()
                    .map(std::convert::Into::into)
                    .collect::<Vec<SkuWrapper>>(),
            );

            let table: Table = skus.into();
            async_writeln!(output_file, "{table}")?;
        }
        OutputFormat::Yaml => todo!(),
    }

    Ok(())
}

async fn show_sku_details(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    extended: bool,
    sku: ::rpc::forge::Sku,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => {
            output_file
                .write_all(serde_json::to_string_pretty(&sku)?.to_string().as_bytes())
                .await?;
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::GenericError(
                "CSV output not supported".to_string(),
            ));
        }

        OutputFormat::AsciiTable => {
            let width = 20;
            let mut output: Vec<u8> = Vec::default();
            writeln!(output, "{:<width$}: {}", "ID", sku.id)?;
            writeln!(
                output,
                "{:<width$}: {}",
                "Schema Version", sku.schema_version
            )?;
            writeln!(
                output,
                "{:<width$}: {}",
                "Description",
                sku.description
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )?;
            writeln!(
                output,
                "{:<width$}: {}",
                "Device Type",
                sku.device_type
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )?;

            let model = sku
                .components
                .as_ref()
                .and_then(|c| c.chassis.as_ref().map(|c| c.model.as_str()));
            let architecture = sku
                .components
                .as_ref()
                .and_then(|c| c.chassis.as_ref().map(|c| c.architecture.as_str()));

            writeln!(output, "{:<width$}: {}", "Model", model.unwrap_or_default(),)?;
            writeln!(
                output,
                "{:<width$}: {}",
                "Architecture",
                architecture.unwrap_or_default(),
            )?;
            writeln!(
                output,
                "{:<width$}: {}",
                "Created At",
                sku.created
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )?;
            if let Some(components) = sku.components {
                if let Some(tpm) = components.tpm {
                    writeln!(output, "{:<width$}: {}", "TPM Version", tpm.version)?;
                }
                writeln!(output, "\nCPUs:")?;
                cpu_table(components.cpus).print(&mut output)?;
                writeln!(output, "GPUs:")?;
                gpu_table(components.gpus).print(&mut output)?;
                if components.memory.is_empty() {
                    writeln!(output, "Memory:")?;
                } else {
                    writeln!(
                        output,
                        "Memory ({}): ",
                        ::utils::sku::capacity_string(
                            components
                                .memory
                                .iter()
                                .fold(0u64, |a, v| a + (v.capacity_mb * v.count) as u64)
                        )
                    )?;
                }
                memory_table(components.memory).print(&mut output)?;

                writeln!(output, "IB Devices:")?;
                ib_device_table(components.infiniband_devices).print(&mut output)?;

                if sku.schema_version >= 1 {
                    writeln!(output, "Storage Devices:")?;
                    storage_table(components.storage).print(&mut output)?;
                }
            }

            if extended {
                writeln!(output, "Assigned Machines")?;
                let mut table: Table = create_table(vec!["Machine ID"]);
                for machine_id in sku.associated_machine_ids {
                    table.add_row(Row::from(vec![machine_id.to_string()]));
                }
                table.print(&mut output)?;
            }
            output_file.write_all(output.as_slice()).await?;
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::GenericError(
                "YAML output not supported".to_string(),
            ));
        }
    }

    Ok(())
}

async fn show_machine_table(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    skus: Vec<::rpc::forge::Sku>,
) -> CarbideCliResult<()> {
    if *output_format != OutputFormat::AsciiTable {
        return Err(CarbideCliError::GenericError(
            "Only ascii table format supported".to_string(),
        ));
    }

    let mut output = Vec::default();
    let mut table = Table::new();
    table.set_titles(Row::from(vec!["SKU ID", "Assigned Machine IDs"]));

    for sku in skus {
        let machines = sku
            .associated_machine_ids
            .into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<String>>()
            .join("\n");
        table.add_row(Row::from(vec![sku.id, machines]));
    }
    table.print(&mut output)?;
    output_file.write_all(output.as_slice()).await?;
    Ok(())
}

pub async fn show(
    args: ShowSku,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    if let Some(sku_id) = args.sku_id {
        let skus = api_client.0.find_skus_by_ids(vec![sku_id]).await?;

        if let Some(sku) = skus.skus.into_iter().next() {
            show_sku_details(output, output_format, extended, sku).await?;
        }
    } else {
        let all_ids = api_client.0.get_all_sku_ids().await?;
        let sku_list = if !all_ids.ids.is_empty() {
            api_client.0.find_skus_by_ids(all_ids.ids).await?
        } else {
            SkuList::default()
        };

        show_skus_table(output, output_format, sku_list.skus).await?;
    };

    Ok(())
}

pub async fn show_machines(
    args: ShowSku,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
) -> CarbideCliResult<()> {
    if let Some(sku_id) = args.sku_id {
        let skus = api_client.0.find_skus_by_ids(vec![sku_id]).await?;
        show_machine_table(output, output_format, skus.skus).await?;
    } else {
        let all_ids = api_client.0.get_all_sku_ids().await?;
        let sku_list = if !all_ids.ids.is_empty() {
            api_client.0.find_skus_by_ids(all_ids.ids).await?
        } else {
            SkuList::default()
        };

        show_machine_table(output, output_format, sku_list.skus).await?;
    };

    Ok(())
}

pub async fn generate(
    args: GenerateSku,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    let mut sku = api_client
        .0
        .generate_sku_from_machine(args.machine_id)
        .await?;
    if let Some(id) = args.id {
        sku.id = id;
    }
    show_sku_details(output, output_format, extended, sku).await?;
    Ok(())
}

pub async fn create(
    args: CreateSku,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
) -> CarbideCliResult<()> {
    let file_data = std::fs::read_to_string(args.filename)?;
    // attempt to deserialize a single sku.  if it fails try to deserialize as a SkuList
    let mut sku_list = match serde_json::de::from_str(&file_data) {
        Ok(sku) => SkuList { skus: vec![sku] },
        Err(e) => serde_json::de::from_str(&file_data).map_err(|_| e)?,
    };
    if let Some(id) = args.id {
        if sku_list.skus.len() != 1 {
            return Err(CarbideCliError::GenericError(
                "ID cannot be specified when creating multiple SKUs".to_string(),
            ));
        }
        sku_list.skus[0].id = id;
    }
    let sku_ids = api_client.0.create_sku(sku_list).await?;
    let sku_list = api_client.0.find_skus_by_ids(sku_ids.ids).await?;
    show_skus_table(output, output_format, sku_list.skus).await?;
    Ok(())
}

pub async fn delete(sku_id: String, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_sku(SkuIdList { ids: vec![sku_id] })
        .await?;
    Ok(())
}

pub async fn assign(
    sku_id: String,
    machine_id: carbide_uuid::machine::MachineId,
    force: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .0
        .assign_sku_to_machine(SkuMachinePair {
            sku_id,
            machine_id: Some(machine_id),
            force,
        })
        .await?;
    Ok(())
}

pub async fn unassign(args: UnassignSku, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .remove_sku_association(RemoveSkuRequest {
            machine_id: Some(args.machine_id),
            force: args.force,
        })
        .await?;
    Ok(())
}

pub async fn verify(
    machine_id: carbide_uuid::machine::MachineId,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client.0.verify_sku_for_machine(machine_id).await?;
    Ok(())
}

pub async fn update_metadata(
    args: UpdateSkuMetadata,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client.0.update_sku_metadata(args).await?;
    Ok(())
}

pub async fn bulk_update_metadata(
    args: BulkUpdateSkuMetadata,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let mut rdr =
        csv::Reader::from_path(&args.filename).map_err(|e| CarbideCliError::IOError(e.into()))?;

    // disable reading the first row as a header
    rdr.set_headers(vec!["sku id", "device type"].into());

    let mut current_line = 1;
    for result in rdr.records() {
        match result {
            Err(e) => {
                // log and ignore parsing errors on a single line.
                tracing::error!(
                    "Error reading file {} line {current_line}: {e}",
                    args.filename
                );
            }
            Ok(data) => {
                // Log missing SKUs, but don't stop processing
                let Some(sku_id) = data.get(0).map(str::to_owned) else {
                    tracing::error!("No SKU ID at line {current_line}");
                    continue;
                };
                let device_type = data.get(1).filter(|s| !s.is_empty()).map(str::to_owned);
                let description = data.get(2).filter(|s| !s.is_empty()).map(str::to_owned);

                // log errors but don't stop the processing
                if let Err(e) = api_client
                    .0
                    .update_sku_metadata(UpdateSkuMetadata {
                        sku_id,
                        description,
                        device_type,
                    })
                    .await
                {
                    tracing::error!("{e}");
                }
            }
        }
        current_line += 1;
    }
    Ok(())
}

pub async fn replace(
    args: CreateSku,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
) -> CarbideCliResult<()> {
    let file_data = std::fs::read_to_string(args.filename)?;
    let mut sku: rpc::forge::Sku = serde_json::de::from_str(&file_data)?;
    sku.id = args.id.unwrap_or(sku.id);

    let updated_sku = api_client.0.replace_sku(sku).await?;
    show_skus_table(output, output_format, vec![updated_sku]).await?;
    Ok(())
}
