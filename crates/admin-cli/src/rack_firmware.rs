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

use std::fs;

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use prettytable::{Cell, Row, Table};

use crate::cfg::cli_options::*;
use crate::rpc::ApiClient;

pub async fn handle_rack_firmware(
    action: RackFirmwareActions,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    match action {
        RackFirmwareActions::Create(opts) => {
            // Read JSON file
            let config_json = fs::read_to_string(&opts.json_file).map_err(|e| {
                CarbideCliError::GenericError(format!(
                    "Failed to read file {}: {}",
                    opts.json_file.display(),
                    e
                ))
            })?;

            // Check that the JSON is valid
            serde_json::from_str::<serde_json::Value>(&config_json).map_err(|e| {
                CarbideCliError::GenericError(format!("Invalid JSON in file: {}", e))
            })?;

            let request = rpc::forge::RackFirmwareCreateRequest {
                config_json,
                artifactory_token: opts.artifactory_token,
            };

            let result = api_client.0.create_rack_firmware(request).await?;

            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Created Rack firmware configuration:");
                println!("  ID: {}", result.id);
                println!("  Available: {}", result.available);
                println!("  Created: {}", result.created);
            }
        }

        RackFirmwareActions::Get(opts) => {
            let request = rpc::forge::RackFirmwareGetRequest {
                id: opts.id.clone(),
            };

            let result = match api_client.0.get_rack_firmware(request).await {
                Ok(response) => response,
                Err(status) if status.code() == tonic::Code::NotFound => {
                    return Err(CarbideCliError::GenericError(format!(
                        "Rack firmware configuration not found: {}",
                        opts.id
                    )));
                }
                Err(err) => return Err(CarbideCliError::from(err)),
            };

            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Rack Firmware Configuration:");
                println!("  ID: {}", result.id);
                println!("  Available: {}", result.available);
                println!("  Created: {}", result.created);
                println!("  Updated: {}", result.updated);

                // Display parsed firmware components
                if !result.parsed_components.is_empty() && result.parsed_components != "{}" {
                    if let Ok(parsed) =
                        serde_json::from_str::<serde_json::Value>(&result.parsed_components)
                        && let Some(devices) = parsed.get("devices").and_then(|d| d.as_object())
                    {
                        for (device_type, components) in devices {
                            println!("\n[{}]", device_type);

                            let mut component_table = Table::new();
                            component_table.set_titles(Row::new(vec![
                                Cell::new("Component"),
                                Cell::new("Type"),
                                Cell::new("Bundle"),
                                Cell::new("Target"),
                            ]));

                            // Collect components with their subcomponents for display
                            let mut component_subcomps: Vec<(String, &[serde_json::Value])> =
                                Vec::new();

                            if let Some(comp_map) = components.as_object() {
                                for (_key, entry) in comp_map {
                                    let component = entry
                                        .get("component")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("-");
                                    let bundle =
                                        entry.get("bundle").and_then(|v| v.as_str()).unwrap_or("-");
                                    let fw_type = entry
                                        .get("firmware_type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("-");
                                    let target =
                                        entry.get("target").and_then(|v| v.as_str()).unwrap_or("-");

                                    component_table.add_row(Row::new(vec![
                                        Cell::new(component),
                                        Cell::new(&fw_type.to_uppercase()),
                                        Cell::new(bundle),
                                        Cell::new(target),
                                    ]));

                                    // Collect subcomponents for later display
                                    if let Some(subcomps) =
                                        entry.get("subcomponents").and_then(|s| s.as_array())
                                        && !subcomps.is_empty()
                                    {
                                        component_subcomps.push((component.to_string(), subcomps));
                                    }
                                }
                            }

                            component_table.printstd();

                            // Print subcomponents for each component
                            for (comp_name, subcomps) in component_subcomps {
                                println!("\n  {} Subcomponents:", comp_name);

                                let mut sub_table = Table::new();
                                sub_table.set_titles(Row::new(vec![
                                    Cell::new("Component"),
                                    Cell::new("Version"),
                                    Cell::new("SKUID"),
                                ]));

                                for subcomp in subcomps {
                                    let sub_name = subcomp
                                        .get("component")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("-");
                                    let sub_version = subcomp
                                        .get("version")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("-");
                                    let sub_skuid = subcomp
                                        .get("skuid")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("-");

                                    sub_table.add_row(Row::new(vec![
                                        Cell::new(sub_name),
                                        Cell::new(sub_version),
                                        Cell::new(sub_skuid),
                                    ]));
                                }

                                // Indent the table output
                                let table_str = sub_table.to_string();
                                for line in table_str.lines() {
                                    println!("  {}", line);
                                }
                            }
                        }
                    }
                } else {
                    println!("\nFirmware Components: (not yet downloaded)");
                }
            }
        }

        RackFirmwareActions::List(opts) => {
            let request = rpc::forge::RackFirmwareListRequest {
                only_available: opts.only_available,
            };

            let result = api_client.0.list_rack_firmware(request).await?;

            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&result.configs)?);
            } else if result.configs.is_empty() {
                println!("No Rack firmware configurations found.");
            } else {
                let mut table = Table::new();
                table.set_titles(Row::new(vec![
                    Cell::new("ID"),
                    Cell::new("Available"),
                    Cell::new("Created"),
                    Cell::new("Updated"),
                ]));

                for config in result.configs {
                    table.add_row(Row::new(vec![
                        Cell::new(&config.id),
                        Cell::new(&config.available.to_string()),
                        Cell::new(&config.created),
                        Cell::new(&config.updated),
                    ]));
                }

                table.printstd();
            }
        }

        RackFirmwareActions::Delete(opts) => {
            let request = rpc::forge::RackFirmwareDeleteRequest {
                id: opts.id.clone(),
            };

            match api_client.0.delete_rack_firmware(request).await {
                Ok(_) => {
                    println!("Deleted Rack firmware configuration: {}", opts.id);
                }
                Err(status) if status.code() == tonic::Code::NotFound => {
                    return Err(CarbideCliError::GenericError(format!(
                        "Rack firmware configuration not found: {}",
                        opts.id
                    )));
                }
                Err(err) => return Err(CarbideCliError::from(err)),
            }
        }

        RackFirmwareActions::Apply(opts) => {
            apply_firmware(opts, format, api_client).await?;
        }
    }

    Ok(())
}

async fn apply_firmware(
    opts: RackFirmwareApply,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    println!(
        "Applying firmware ID '{}' ({}) to rack '{}'...",
        opts.firmware_id, opts.firmware_type, opts.rack_id
    );

    let request = rpc::forge::RackFirmwareApplyRequest {
        rack_id: Some(opts.rack_id),
        firmware_id: opts.firmware_id,
        firmware_type: opts.firmware_type,
    };

    let response = api_client
        .0
        .apply_rack_firmware(request)
        .await
        .map_err(CarbideCliError::from)?;

    // Display results based on format
    if format == OutputFormat::Json {
        let result = serde_json::json!({
            "total_updates": response.total_updates,
            "successful_updates": response.successful_updates,
            "failed_updates": response.failed_updates,
            "device_results": response.device_results.iter().map(|r| serde_json::json!({
                "device_id": r.device_id,
                "device_type": r.device_type,
                "success": r.success,
                "message": r.message,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Device ID"),
            Cell::new("Hardware Type"),
            Cell::new("Status"),
            Cell::new("Message"),
        ]));

        for device_result in &response.device_results {
            let status_text = if device_result.success {
                "✓ SUCCESS"
            } else {
                "✗ FAILED"
            };

            table.add_row(Row::new(vec![
                Cell::new(&device_result.device_id),
                Cell::new(&device_result.device_type),
                Cell::new(status_text),
                Cell::new(&device_result.message),
            ]));
        }

        println!("\n{}", "=".repeat(80));
        println!("Firmware Update Summary");
        println!("{}", "=".repeat(80));
        table.printstd();
        println!("\nTotal updates: {}", response.total_updates);
        println!("Successful: {}", response.successful_updates);
        println!("Failed: {}", response.failed_updates);
    }

    if response.failed_updates > 0 {
        return Err(CarbideCliError::GenericError(format!(
            "{} firmware updates failed",
            response.failed_updates
        )));
    }

    Ok(())
}
