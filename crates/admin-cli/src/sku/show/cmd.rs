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
use tokio::io::AsyncWriteExt;

use super::args::Args;
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

pub async fn show_skus_table(
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

pub async fn show_sku_details(
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

pub async fn show(
    args: Args,
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
