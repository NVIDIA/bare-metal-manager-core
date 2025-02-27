use ::rpc::forge::SkuList;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{Row, Table};
use utils::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};

use crate::cfg::cli_options::Sku;
use crate::rpc;

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

fn cpu_table(cpus: Vec<::rpc::forge::SkuComponentCpu>) -> Table {
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(vec!["Vendor", "Model", "Threads", "Count"]));
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
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(vec!["Vendor", "Total Memory", "Model", "Count"]));
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
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(vec!["Type", "Capacity", "Count"]));
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
    let mut table = Table::new();
    let table_format = table.get_format();
    table_format.indent(10);

    table.set_titles(Row::from(vec![
        "Vendor",
        "Model",
        "Count",
        "Inactive Devices",
    ]));
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

fn show_skus_table(
    output: &mut dyn std::io::Write,
    output_format: &OutputFormat,
    skus: Vec<::rpc::forge::Sku>,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => {
            output.write_all(
                (serde_json::to_string_pretty(&skus)?)
                    .to_string()
                    .as_bytes(),
            )?;
        }
        OutputFormat::Csv => {
            let skus = SkusWrapper::from(
                skus.into_iter()
                    .map(std::convert::Into::into)
                    .collect::<Vec<SkuWrapper>>(),
            );

            let table: Table = skus.into();
            table
                .to_csv(output)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
        }
        OutputFormat::AsciiTable => {
            let skus = SkusWrapper::from(
                skus.into_iter()
                    .map(std::convert::Into::into)
                    .collect::<Vec<SkuWrapper>>(),
            );

            let table: Table = skus.into();
            table.print(output)?;
        }
        OutputFormat::Yaml => todo!(),
    }

    Ok(())
}

fn show_sku_details(
    output: &mut dyn std::io::Write,
    output_format: &OutputFormat,
    sku: ::rpc::forge::Sku,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => {
            output.write_all((serde_json::to_string_pretty(&sku)?).to_string().as_bytes())?;
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::GenericError(
                "CSV output not supported".to_string(),
            ));
        }
        OutputFormat::AsciiTable => {
            writeln!(output, "ID:              {}", sku.id)?;
            writeln!(
                output,
                "Description:     {}",
                sku.description
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )?;

            let model = sku
                .components
                .as_ref()
                .and_then(|c| c.chassis.as_ref().map(|c| c.model.clone()));
            let architecture = sku
                .components
                .as_ref()
                .and_then(|c| c.chassis.as_ref().map(|c| c.architecture.clone()));

            writeln!(output, "Model:           {}", model.unwrap_or_default(),)?;
            writeln!(
                output,
                "Architecture:    {}",
                architecture.unwrap_or_default(),
            )?;
            writeln!(
                output,
                "Created At:      {}",
                sku.created
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )?;
            if let Some(components) = sku.components {
                writeln!(output, "CPUs:")?;
                cpu_table(components.cpus).print(output)?;
                writeln!(output, "GPUs:")?;
                gpu_table(components.gpus).print(output)?;
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
                memory_table(components.memory).print(output)?;
                writeln!(output, "IB Devices:")?;
                ib_device_table(components.infiniband_devices).print(output)?;
            }
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::GenericError(
                "YAML output not supported".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn handle_sku_command(
    api_config: &ApiConfig<'_>,
    output: &mut dyn std::io::Write,
    output_format: &OutputFormat,
    sku_command: Sku,
) -> Result<(), CarbideCliError> {
    match sku_command {
        Sku::Show(show_sku) => {
            if let Some(sku_id) = show_sku.sku_id {
                let skus = rpc::get_skus_by_ids(api_config, &[sku_id]).await?;
                if let Some(sku) = skus.skus.into_iter().next() {
                    show_sku_details(output, output_format, sku)?;
                }
            } else {
                let all_ids = rpc::get_all_sku_ids(api_config).await?;
                let sku_list = if !all_ids.ids.is_empty() {
                    rpc::get_skus_by_ids(api_config, &all_ids.ids).await?
                } else {
                    SkuList::default()
                };

                show_skus_table(output, output_format, sku_list.skus)?;
            };
        }
        Sku::Generate { machine_id } => {
            let sku = rpc::generate_sku_from_machine(
                api_config,
                ::rpc::common::MachineId { id: machine_id },
            )
            .await?;
            show_sku_details(output, output_format, sku)?;
        }
        Sku::Create { filename } => {
            let file_data = std::fs::read_to_string(filename)?;
            // attempt to deserialize a single sku.  if it fails try to deserialize as a SkuList
            let sku_list = match serde_json::de::from_str(&file_data) {
                Ok(sku) => SkuList { skus: vec![sku] },
                Err(e) => serde_json::de::from_str(&file_data).map_err(|_| e)?,
            };
            let sku_ids = rpc::create_sku(api_config, sku_list).await?;
            let sku_list = rpc::get_skus_by_ids(api_config, &sku_ids.ids).await?;
            show_skus_table(output, output_format, sku_list.skus)?;
        }
        Sku::Delete { sku_id } => {
            rpc::delete_sku(api_config, sku_id).await?;
        }
        Sku::Assign { sku_id, machine_id } => {
            let machine_id = ::rpc::common::MachineId { id: machine_id };

            rpc::assign_sku_to_machine(api_config, sku_id, machine_id).await?;
        }
        Sku::Unassign { machine_id } => {
            let machine_id = ::rpc::common::MachineId { id: machine_id };

            rpc::remove_sku_association(api_config, machine_id).await?;
        }
        Sku::Verify { machine_id } => {
            let machine_id = ::rpc::common::MachineId { id: machine_id };

            rpc::verify_sku_for_machine(api_config, machine_id).await?;
        }
    }
    Ok(())
}
