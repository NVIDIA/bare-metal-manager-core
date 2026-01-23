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

// registry/cmds.rs
// Command handlers for registry operations.

use mlxconfig_variables::MlxVariableRegistry;
use prettytable::{Cell, Row, Table};
use rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use rpc::protos::mlx_device as mlx_device_pb;

use super::args::{RegistryCommand, RegistryListCommand, RegistryShowCommand};
use crate::mlx::{CliContext, wrap_text};

// dispatch routes registry subcommands to their handlers.
pub async fn dispatch(
    command: RegistryCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    match command {
        RegistryCommand::List(cmd) => handle_list(cmd, ctxt).await,
        RegistryCommand::Show(cmd) => handle_show(cmd, ctxt).await,
    }
}

// handle_list lists all registries configured in the remote scout agent.
async fn handle_list(
    cmd: RegistryListCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminRegistryListRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_registry_list(request).await?;

    let registry_listing = response
        .registry_listing
        .ok_or_else(|| CarbideCliError::GenericError("no registry listing returned".to_string()))?;

    let mut registry_names = registry_listing.registry_names;
    registry_names.sort();

    match ctxt.format {
        OutputFormat::AsciiTable => {
            let mut table = Table::new();
            table.add_row(Row::new(vec![Cell::new("Registry Name")]));

            for name in &registry_names {
                table.add_row(Row::new(vec![Cell::new(name)]));
            }

            table.printstd();
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&registry_names)?;
            println!("{json}");
        }
        OutputFormat::Yaml => {
            println!("registries:");
            for name in registry_names {
                println!("  - {name}");
            }
        }
        OutputFormat::Csv => {
            for name in registry_names {
                println!("{name}");
            }
        }
    }

    Ok(())
}

// handle_show shows a profile configured in carbide-api.
async fn handle_show(
    cmd: RegistryShowCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminRegistryShowRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_registry_show(request).await?;

    let variable_registry_pb = response.variable_registry.ok_or_else(|| {
        CarbideCliError::GenericError("no variable_registry returned".to_string())
    })?;

    let variable_registry: MlxVariableRegistry = variable_registry_pb.try_into()?;

    match ctxt.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&variable_registry)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&variable_registry)?);
        }
        OutputFormat::AsciiTable => {
            print_registry_table(&variable_registry);
        }
        OutputFormat::Csv => {
            println!("CSV not yet supported");
        }
    }

    Ok(())
}

// print_registry_table displays a registry in ASCII table format.
fn print_registry_table(registry: &MlxVariableRegistry) {
    let mut table = Table::new();

    // Header: Registry name.
    println!("Registry: {}", registry.name);
    println!();

    // Add variable table header.
    table.add_row(Row::new(vec![
        Cell::new("Variable"),
        Cell::new("Type"),
        Cell::new("RW"),
        Cell::new("Description"),
    ]));

    // Add variable rows.
    for variable in &registry.variables {
        let rw = if variable.read_only { "RO" } else { "RW" };

        let wrapped_description = wrap_text(&variable.description, 60);

        table.add_row(Row::new(vec![
            Cell::new(&variable.name),
            Cell::new(&variable.spec.to_string()),
            Cell::new(rw),
            Cell::new(&wrapped_description),
        ]));
    }

    table.printstd();
}
