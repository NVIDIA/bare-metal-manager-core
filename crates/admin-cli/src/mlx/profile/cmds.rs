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

// profile/cmds.rs
// Command handlers for profile operations.

use mlxconfig_profile::serialization::SerializableProfile;
use mlxconfig_runner::{ComparisonResult, SyncResult};
use prettytable::{Cell, Row, Table};
use rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use rpc::protos::mlx_device as mlx_device_pb;

use super::args::{
    ProfileCommand, ProfileCompareCommand, ProfileListCommand, ProfileShowCommand,
    ProfileSyncCommand,
};
use crate::mlx::{
    CliContext, print_comparison_result_csv, print_comparison_result_table, print_sync_result_csv,
    print_sync_result_table,
};

// dispatch routes profile subcommands to their handlers.
pub async fn dispatch(
    command: ProfileCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    match command {
        ProfileCommand::Compare(cmd) => handle_compare(cmd, ctxt).await,
        ProfileCommand::List(cmd) => handle_list(cmd, ctxt).await,
        ProfileCommand::Sync(cmd) => handle_sync(cmd, ctxt).await,
        ProfileCommand::Show(cmd) => handle_show(cmd, ctxt).await,
    }
}

// handle_compare compares a profile config against running config on a device.
async fn handle_compare(
    cmd: ProfileCompareCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminProfileCompareRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_profile_compare(request).await?;

    let comparison_result_pb = response.comparison_result.ok_or_else(|| {
        CarbideCliError::GenericError("no comparison result returned".to_string())
    })?;

    let comparison_result: ComparisonResult = comparison_result_pb.try_into()?;

    // Output the comparison result in the requested format.
    match ctxt.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&comparison_result)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&comparison_result)?);
        }
        OutputFormat::AsciiTable => {
            print_comparison_result_table(&comparison_result);
        }
        OutputFormat::Csv => {
            print_comparison_result_csv(&comparison_result);
        }
    }

    Ok(())
}

// handle_list lists all profiles configured in carbide-api.
async fn handle_list(
    _cmd: ProfileListCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let response = ctxt.grpc_conn.0.mlx_admin_profile_list().await?;

    let mut profiles = response.profiles;
    // Sort by profile name.
    profiles.sort_by(|a, b| a.name.cmp(&b.name));

    match ctxt.format {
        OutputFormat::Json => {
            let output: Vec<_> = profiles
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "profile_name": p.name,
                        "description": p.description,
                        "registry_name": p.registry_name,
                        "variable_count": p.variable_count
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Yaml => {
            println!("profiles:");
            for profile in profiles {
                println!("  - profile_name: {}", profile.name);
                if let Some(desc) = profile.description {
                    println!("    description: {desc}");
                }
                println!("    registry_name: {}", profile.registry_name);
                println!("    variable_count: {}", profile.variable_count);
            }
        }
        OutputFormat::AsciiTable => {
            print_profiles_table(&profiles);
        }
        OutputFormat::Csv => {
            println!("CSV not yet supported")
        }
    }

    Ok(())
}

// handle_show shows a profile configured in carbide-api.
async fn handle_show(
    cmd: ProfileShowCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminProfileShowRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_profile_show(request).await?;

    let serializable_profile_pb = response
        .serializable_profile
        .ok_or_else(|| CarbideCliError::GenericError("no profile returned".to_string()))?;

    let serializable_profile: SerializableProfile =
        serializable_profile_pb.try_into().map_err(|e| {
            CarbideCliError::GenericError(format!(
                "could not translate serializable profile from pb: {e}"
            ))
        })?;

    match ctxt.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&serializable_profile)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&serializable_profile)?);
        }
        OutputFormat::AsciiTable => {
            print_profile_table(serializable_profile);
        }
        OutputFormat::Csv => {
            println!("CSV not yet supported")
        }
    }

    Ok(())
}

// handle_sync syncs a profile from carbide-api to a device.
async fn handle_sync(
    cmd: ProfileSyncCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminProfileSyncRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_profile_sync(request).await?;

    let sync_result_pb = response
        .sync_result
        .ok_or_else(|| CarbideCliError::GenericError("no sync result returned".to_string()))?;

    let sync_result: SyncResult = sync_result_pb.try_into()?;

    match ctxt.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&sync_result)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&sync_result)?);
        }
        OutputFormat::AsciiTable => {
            print_sync_result_table(&sync_result);
        }
        OutputFormat::Csv => {
            print_sync_result_csv(&sync_result);
        }
    }

    Ok(())
}

// print_profiles_table prints a table of profile summaries.
fn print_profiles_table(profiles: &[mlx_device_pb::ProfileSummary]) {
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Profile Name"),
        Cell::new("Description"),
        Cell::new("Variables"),
        Cell::new("Registry"),
    ]));

    for profile in profiles {
        table.add_row(Row::new(vec![
            Cell::new(&profile.name),
            Cell::new(profile.description.as_deref().unwrap_or("-")),
            Cell::new(&profile.variable_count.to_string()),
            Cell::new(&profile.registry_name),
        ]));
    }

    table.printstd();
}

// print_profile_table prints a detailed table for a single profile.
fn print_profile_table(profile: SerializableProfile) {
    let mut table = Table::new();

    // Name row.
    table.add_row(Row::new(vec![Cell::new("Name"), Cell::new(&profile.name)]));

    // Description row.
    table.add_row(Row::new(vec![
        Cell::new("Description"),
        Cell::new(profile.description.as_deref().unwrap_or("-")),
    ]));

    // Registry row.
    table.add_row(Row::new(vec![
        Cell::new("Registry Name"),
        Cell::new(&profile.registry_name),
    ]));

    // Config header (double-wide).
    table.add_row(Row::new(vec![Cell::new("Config").with_hspan(2)]));

    // Config variables (sorted by name).
    let mut config_entries: Vec<_> = profile.config.into_iter().collect();
    config_entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (variable_name, value) in config_entries {
        // Format the value as a compact YAML string.
        let value_str = format_yaml_value(value);
        table.add_row(Row::new(vec![
            Cell::new(&variable_name),
            Cell::new(&value_str),
        ]));
    }

    table.printstd();
}

// format_yaml_value formats a YAML value into a compact string representation.
fn format_yaml_value(value: serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s,
        serde_yaml::Value::Sequence(seq) => {
            // Format arrays compactly.
            let items: Vec<String> = seq.into_iter().map(format_yaml_value).collect();
            format!("[{}]", items.join(", "))
        }
        serde_yaml::Value::Mapping(map) => {
            // Format maps compactly.
            let items: Vec<String> = map
                .into_iter()
                .map(|(k, v)| format!("{}: {}", format_yaml_value(k), format_yaml_value(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        serde_yaml::Value::Tagged(tagged) => {
            // For tagged values, just show the value part.
            format_yaml_value(tagged.value)
        }
    }
}
