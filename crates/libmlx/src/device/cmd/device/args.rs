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

use crate::device::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};

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

    Ok(DeviceFilter {
        field,
        values,
        match_mode,
    })
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
        assert_eq!(
            filter.field,
            crate::device::filters::DeviceField::DeviceType
        );
        assert_eq!(filter.values, vec!["ConnectX-6"]);
        assert!(matches!(
            filter.match_mode,
            crate::device::filters::MatchMode::Prefix
        ));
    }
}

#[cfg(test)]
mod coverage_tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // Projection of a DeviceFilter into PartialEq pieces, since DeviceFilter
    // itself is not PartialEq. (field, values, match_mode) captures every
    // observable output of the parsers under test.
    type FilterParts = (DeviceField, Vec<String>, MatchMode);

    fn parts(f: &DeviceFilter) -> FilterParts {
        (f.field.clone(), f.values.clone(), f.match_mode.clone())
    }

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    // parse_device_field: every accepted alias maps to its DeviceField arm,
    // case-insensitively, and any unknown token is rejected.
    #[test]
    fn parse_device_field_cases() {
        check_cases(
            [
                Case {
                    scenario: "device_type canonical",
                    input: "device_type",
                    expect: Yields(DeviceField::DeviceType),
                },
                Case {
                    scenario: "type alias",
                    input: "type",
                    expect: Yields(DeviceField::DeviceType),
                },
                Case {
                    scenario: "device_type uppercased (lowercased internally)",
                    input: "DEVICE_TYPE",
                    expect: Yields(DeviceField::DeviceType),
                },
                Case {
                    scenario: "part_number canonical",
                    input: "part_number",
                    expect: Yields(DeviceField::PartNumber),
                },
                Case {
                    scenario: "part alias",
                    input: "part",
                    expect: Yields(DeviceField::PartNumber),
                },
                Case {
                    scenario: "firmware_version canonical",
                    input: "firmware_version",
                    expect: Yields(DeviceField::FirmwareVersion),
                },
                Case {
                    scenario: "firmware alias",
                    input: "firmware",
                    expect: Yields(DeviceField::FirmwareVersion),
                },
                Case {
                    scenario: "fw alias",
                    input: "fw",
                    expect: Yields(DeviceField::FirmwareVersion),
                },
                Case {
                    scenario: "mac_address canonical",
                    input: "mac_address",
                    expect: Yields(DeviceField::MacAddress),
                },
                Case {
                    scenario: "mac alias",
                    input: "mac",
                    expect: Yields(DeviceField::MacAddress),
                },
                Case {
                    scenario: "description canonical",
                    input: "description",
                    expect: Yields(DeviceField::Description),
                },
                Case {
                    scenario: "desc alias",
                    input: "desc",
                    expect: Yields(DeviceField::Description),
                },
                Case {
                    scenario: "pci_name canonical",
                    input: "pci_name",
                    expect: Yields(DeviceField::PciName),
                },
                Case {
                    scenario: "pci alias",
                    input: "pci",
                    expect: Yields(DeviceField::PciName),
                },
                Case {
                    scenario: "status canonical",
                    input: "status",
                    expect: Yields(DeviceField::Status),
                },
                Case {
                    scenario: "unknown field rejected",
                    input: "bogus",
                    expect: FailsWith(
                        "Unknown field 'bogus'. Valid fields: device_type, part_number, \
                         firmware_version, mac_address, description, pci_name, status"
                            .to_string(),
                    ),
                },
                Case {
                    scenario: "empty field rejected",
                    input: "",
                    expect: FailsWith(
                        "Unknown field ''. Valid fields: device_type, part_number, \
                         firmware_version, mac_address, description, pci_name, status"
                            .to_string(),
                    ),
                },
            ],
            parse_device_field,
        );
    }

    // parse_match_mode: each accepted mode (case-insensitive) maps to its
    // MatchMode arm; anything else is rejected with the canonical message.
    #[test]
    fn parse_match_mode_cases() {
        check_cases(
            [
                Case {
                    scenario: "regex",
                    input: "regex",
                    expect: Yields(MatchMode::Regex),
                },
                Case {
                    scenario: "exact",
                    input: "exact",
                    expect: Yields(MatchMode::Exact),
                },
                Case {
                    scenario: "prefix",
                    input: "prefix",
                    expect: Yields(MatchMode::Prefix),
                },
                Case {
                    scenario: "uppercased prefix (lowercased internally)",
                    input: "PREFIX",
                    expect: Yields(MatchMode::Prefix),
                },
                Case {
                    scenario: "unknown mode rejected",
                    input: "fuzzy",
                    expect: FailsWith(
                        "Unknown match mode 'fuzzy'. Valid modes: regex, exact, prefix".to_string(),
                    ),
                },
                Case {
                    scenario: "empty mode rejected",
                    input: "",
                    expect: FailsWith(
                        "Unknown match mode ''. Valid modes: regex, exact, prefix".to_string(),
                    ),
                },
            ],
            parse_match_mode,
        );
    }

    // parse_filter_expression success paths: 2-part defaults to Regex,
    // 3-part honors the explicit mode, comma-separated values become an OR
    // list, and surrounding whitespace on values is trimmed while empties drop.
    #[test]
    fn parse_filter_expression_ok_cases() {
        check_cases(
            [
                Case {
                    scenario: "two parts default to regex",
                    input: "device_type:ConnectX-6",
                    expect: Yields((
                        DeviceField::DeviceType,
                        owned(&["ConnectX-6"]),
                        MatchMode::Regex,
                    )),
                },
                Case {
                    scenario: "three parts with explicit prefix mode",
                    input: "part_number:MCX:prefix",
                    expect: Yields((DeviceField::PartNumber, owned(&["MCX"]), MatchMode::Prefix)),
                },
                Case {
                    scenario: "comma-separated OR values",
                    input: "status:ok,fail,warn:exact",
                    expect: Yields((
                        DeviceField::Status,
                        owned(&["ok", "fail", "warn"]),
                        MatchMode::Exact,
                    )),
                },
                Case {
                    scenario: "values are trimmed and empties dropped",
                    input: "fw: 22.32 , ,1010 :exact",
                    expect: Yields((
                        DeviceField::FirmwareVersion,
                        owned(&["22.32", "1010"]),
                        MatchMode::Exact,
                    )),
                },
                Case {
                    scenario: "alias field with default mode",
                    input: "mac:00:11",
                    // Note: three colon-parts here -> third part parsed as mode.
                    // "00:11" splits to ["mac","00","11"]; "11" is not a mode.
                    expect: Fails,
                },
            ],
            |expr| parse_filter_expression(expr).map(|f| parts(&f)),
        );
    }

    // parse_filter_expression rejection paths: too few / too many colon parts,
    // unknown field propagated, unknown mode propagated, and a values list
    // that collapses to empty after trimming.
    #[test]
    fn parse_filter_expression_err_cases() {
        check_cases(
            [
                Case {
                    scenario: "single part (no colon) rejected",
                    input: "device_type",
                    expect: FailsWith(
                        "Invalid filter expression 'device_type'. Expected format: \
                         field:value[,value2,value3] or \
                         field:value[,value2,value3]:match_mode"
                            .to_string(),
                    ),
                },
                Case {
                    scenario: "four parts rejected",
                    input: "a:b:c:d",
                    expect: FailsWith(
                        "Invalid filter expression 'a:b:c:d'. Expected format: \
                         field:value[,value2,value3] or \
                         field:value[,value2,value3]:match_mode"
                            .to_string(),
                    ),
                },
                Case {
                    scenario: "unknown field propagated",
                    input: "nope:value",
                    expect: FailsWith(
                        "Unknown field 'nope'. Valid fields: device_type, part_number, \
                         firmware_version, mac_address, description, pci_name, status"
                            .to_string(),
                    ),
                },
                Case {
                    scenario: "unknown mode propagated",
                    input: "device_type:val:bogus",
                    expect: FailsWith(
                        "Unknown match mode 'bogus'. Valid modes: regex, exact, prefix".to_string(),
                    ),
                },
                Case {
                    scenario: "values empty after trim/drop",
                    input: "device_type: , :exact",
                    expect: FailsWith(
                        "No valid values found in filter expression 'device_type: , :exact'"
                            .to_string(),
                    ),
                },
            ],
            |expr| parse_filter_expression(expr).map(|f| parts(&f)),
        );
    }

    // build_filter_set_from_filter_args: empty input yields an empty set;
    // multiple valid expressions accumulate in order; any single invalid
    // expression aborts the whole build.
    #[test]
    fn build_filter_set_ok_cases() {
        check_cases(
            [
                Case {
                    scenario: "empty input -> empty set",
                    input: vec![],
                    expect: Yields(vec![]),
                },
                Case {
                    scenario: "single valid expression",
                    input: vec!["device_type:ConnectX:exact".to_string()],
                    expect: Yields(vec![(
                        DeviceField::DeviceType,
                        owned(&["ConnectX"]),
                        MatchMode::Exact,
                    )]),
                },
                Case {
                    scenario: "multiple expressions accumulate in order",
                    input: vec!["part:MCX:prefix".to_string(), "status:ok".to_string()],
                    expect: Yields(vec![
                        (DeviceField::PartNumber, owned(&["MCX"]), MatchMode::Prefix),
                        (DeviceField::Status, owned(&["ok"]), MatchMode::Regex),
                    ]),
                },
            ],
            |exprs| {
                build_filter_set_from_filter_args(exprs)
                    .map(|set| set.filters.iter().map(parts).collect::<Vec<_>>())
            },
        );
    }

    // build_filter_set_from_filter_args aborts on the first bad expression and
    // surfaces that expression's error verbatim.
    #[test]
    fn build_filter_set_propagates_first_error() {
        check_cases(
            [
                Case {
                    scenario: "invalid field aborts the build",
                    input: vec!["device_type:ok".to_string(), "nope:value".to_string()],
                    expect: FailsWith(
                        "Unknown field 'nope'. Valid fields: device_type, part_number, \
                         firmware_version, mac_address, description, pci_name, status"
                            .to_string(),
                    ),
                },
                Case {
                    scenario: "malformed expression aborts the build",
                    input: vec!["justonepart".to_string()],
                    expect: FailsWith(
                        "Invalid filter expression 'justonepart'. Expected format: \
                         field:value[,value2,value3] or \
                         field:value[,value2,value3]:match_mode"
                            .to_string(),
                    ),
                },
            ],
            |exprs| {
                build_filter_set_from_filter_args(exprs)
                    .map(|set| set.filters.iter().map(parts).collect::<Vec<_>>())
            },
        );
    }

    // OutputFormat round-trips through clap's ValueEnum string forms, covering
    // every variant's kebab-cased name.
    #[test]
    fn output_format_value_enum_round_trip() {
        check_values(
            [
                Check {
                    scenario: "ascii-table",
                    input: "ascii-table",
                    expect: true,
                },
                Check {
                    scenario: "json",
                    input: "json",
                    expect: true,
                },
                Check {
                    scenario: "yaml",
                    input: "yaml",
                    expect: true,
                },
                Check {
                    scenario: "unknown format not accepted",
                    input: "xml",
                    expect: false,
                },
            ],
            |name| OutputFormat::from_str(name, true).is_ok(),
        );
    }
}
