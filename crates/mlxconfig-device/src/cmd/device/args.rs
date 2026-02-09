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

use clap::{Args, Subcommand, ValueEnum};

use crate::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};

// DeviceArgs represents the arguments for device-related commands.
#[derive(Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub action: DeviceAction,
}

// DeviceAction defines the available device subcommands.
#[derive(Subcommand, Clone)]
pub enum DeviceAction {
    // List all discovered Mellanox devices.
    #[command(about = "List all discovered Mellanox devices on this machine.")]
    List {
        // format specifies the output format for device information.
        #[arg(long, default_value = "ascii-table")]
        format: OutputFormat,

        // detailed shows detailed device information.
        #[arg(long)]
        detailed: bool,
    },

    // Filter devices using advanced filter expressions.
    #[command(about = "Filter devices based on DeviceFilter options.")]
    Filter {
        // format specifies the output format for device information.
        #[arg(long, default_value = "ascii-table")]
        format: OutputFormat,

        // filter specifies filter expression in the format field:value:match_mode.
        // Examples:
        //   --filter device_type:ConnectX-6:prefix
        //   --filter part_number:MCX.*:regex
        //   --filter firmware_version:22.32.1010:exact
        #[arg(long)]
        filter: Vec<DeviceFilter>,

        // detailed shows detailed device information.
        #[arg(long)]
        detailed: bool,
    },

    // Describe detailed information about a specific device.
    #[command(about = "Show everything known about a device by its ID.")]
    Describe {
        // device specifies the PCI address or identifier of the target device.
        device: String,
        // format specifies the output format for device information.
        #[arg(long, default_value = "ascii-table")]
        format: OutputFormat,
    },

    // Generate a complete device discovery report.
    #[command(
        about = "Generate an MlxDeviceReport in a given --format and optional --filter args."
    )]
    Report {
        // format specifies the output format for the report.
        #[arg(long, default_value = "ascii-table")]
        format: OutputFormat,

        // filter specifies filter expression in the format field:value:match_mode.
        // Examples:
        //   --filter device_type:ConnectX-6:prefix
        //   --filter part_number:MCX.*:regex
        //   --filter firmware_version:22.32.1010:exact
        #[arg(long)]
        filter: Vec<DeviceFilter>,

        // detailed shows detailed device information.
        #[arg(long)]
        detailed: bool,
    },
}

// OutputFormat defines the available output formats for device information.
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    // ascii-table outputs device information in a formatted ASCII table.
    #[value(name = "ascii-table")]
    AsciiTable,
    // json outputs device information in JSON format.
    #[value(name = "json")]
    Json,
    // yaml outputs device information in YAML format.
    #[value(name = "yaml")]
    Yaml,
}

// parse_filter_expression parses a filter expression in the format field:value:match_mode.
// Values can be comma-separated for OR logic: field:value1,value2,value3:match_mode
pub fn parse_filter_expression(expression: &str) -> Result<DeviceFilter, String> {
    let parts: Vec<&str> = expression.split(':').collect();

    if parts.len() < 2 || parts.len() > 3 {
        return Err(format!(
            "Invalid filter expression '{expression}'. Expected format: field:value[,value2,value3] or field:value[,value2,value3]:match_mode"
        ));
    }

    let field = parse_device_field(parts[0])?;

    // Parse comma-separated values for OR logic.
    let values: Vec<String> = parts[1]
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();

    if values.is_empty() {
        return Err(format!(
            "No valid values found in filter expression '{expression}'"
        ));
    }

    let match_mode = if parts.len() == 3 {
        parse_match_mode(parts[2])?
    } else {
        // Use regex as default for all fields.
        MatchMode::Regex
    };

    Ok(DeviceFilter::new(field, values, match_mode))
}

// parse_device_field converts a string to a DeviceField enum.
fn parse_device_field(field_str: &str) -> Result<DeviceField, String> {
    match field_str.to_lowercase().as_str() {
        "device_type" | "type" => Ok(DeviceField::DeviceType),
        "part_number" | "part" => Ok(DeviceField::PartNumber),
        "firmware_version" | "firmware" | "fw" => Ok(DeviceField::FirmwareVersion),
        "mac_address" | "mac" => Ok(DeviceField::MacAddress),
        "description" | "desc" => Ok(DeviceField::Description),
        "pci_name" | "pci" => Ok(DeviceField::PciName),
        "status" => Ok(DeviceField::Status),
        _ => Err(format!(
            "Unknown field '{field_str}'. Valid fields: device_type, part_number, firmware_version, mac_address, description, pci_name, status"
        )),
    }
}

// parse_match_mode converts a string to a MatchMode enum.
fn parse_match_mode(mode_str: &str) -> Result<MatchMode, String> {
    match mode_str.to_lowercase().as_str() {
        "regex" => Ok(MatchMode::Regex),
        "exact" => Ok(MatchMode::Exact),
        "prefix" => Ok(MatchMode::Prefix),
        _ => Err(format!(
            "Unknown match mode '{mode_str}'. Valid modes: regex, exact, prefix"
        )),
    }
}

// build_filter_set_from_filter_args creates a DeviceFilterSet from filter command arguments.
pub fn build_filter_set_from_filter_args(
    filter_expressions: Vec<String>,
) -> Result<DeviceFilterSet, String> {
    let mut filter_set = DeviceFilterSet::new();

    for expression in filter_expressions {
        let filter = parse_filter_expression(&expression)?;
        filter_set.add_filter(filter);
    }

    Ok(filter_set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_filter_from_str_integration() {
        use std::str::FromStr;

        let filter = DeviceFilter::from_str("device_type:ConnectX-6:prefix").unwrap();
        assert_eq!(filter.field, crate::filters::DeviceField::DeviceType);
        assert_eq!(filter.values, vec!["ConnectX-6"]);
        assert!(matches!(
            filter.match_mode,
            crate::filters::MatchMode::Prefix
        ));
    }
}
