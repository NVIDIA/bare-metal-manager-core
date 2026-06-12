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
use std::str::FromStr;

use carbide_libmlx_model::device::info::MlxDeviceInfo;
use carbide_test_support::Outcome::*;
use carbide_test_support::{Case, Check, check_cases, check_values};
use libmlx::device::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};

// A single filter against the fully-populated test device should match across
// every field and match mode -- device type (exact/prefix/regex/complex regex),
// part number, firmware, MAC, and the case-insensitive/substring description
// paths -- plus the OR-logic case where any one of several values matches.
#[test]
fn filter_matches_complete_device() {
    let device = MlxDeviceInfo::create_test_device();

    check_values(
        [
            Check {
                scenario: "device_type exact \"ConnectX-6 Dx\"",
                input: DeviceFilter::device_type(
                    vec!["ConnectX-6 Dx".to_string()],
                    MatchMode::Exact,
                ),
                expect: true,
            },
            Check {
                scenario: "device_type prefix \"ConnectX\"",
                input: DeviceFilter::device_type(vec!["ConnectX".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "device_type regex \"Connect.*\"",
                input: DeviceFilter::device_type(vec!["Connect.*".to_string()], MatchMode::Regex),
                expect: true,
            },
            Check {
                scenario: "device_type complex regex \".*X-6.*\"",
                input: DeviceFilter::device_type(vec![".*X-6.*".to_string()], MatchMode::Regex),
                expect: true,
            },
            Check {
                scenario: "part_number prefix \"MCX623\"",
                input: DeviceFilter::part_number(vec!["MCX623".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "firmware_version prefix \"22.32\"",
                input: DeviceFilter::firmware_version(vec!["22.32".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "mac_address prefix \"b8:3f:d2\"",
                input: DeviceFilter::mac_address(vec!["b8:3f:d2".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "description regex substring \".*100GbE.*\"",
                input: DeviceFilter::description(vec![".*100GbE.*".to_string()], MatchMode::Regex),
                expect: true,
            },
            Check {
                scenario: "description case-insensitive prefix \"mellanox\"",
                input: DeviceFilter::description(vec!["mellanox".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "multiple values, OR logic (one value matches)",
                input: DeviceFilter::device_type(
                    vec!["ConnectX-7".to_string(), "ConnectX-6 Dx".to_string()],
                    MatchMode::Exact,
                ),
                expect: true,
            },
        ],
        |filter| filter.matches(&device),
    );
}

// The device with missing data has only its device type and status populated.
// Filters on present fields match (status, device type); filters on absent
// fields (part number, firmware, MAC) do not.
#[test]
fn filter_matches_device_with_missing_data() {
    let device = MlxDeviceInfo::create_test_device_with_missing_data();

    check_values(
        [
            Check {
                scenario: "status exact \"Failed to open device\" present",
                input: DeviceFilter::status(
                    vec!["Failed to open device".to_string()],
                    MatchMode::Exact,
                ),
                expect: true,
            },
            Check {
                scenario: "status prefix \"Failed\" present",
                input: DeviceFilter::status(vec!["Failed".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "device_type prefix \"BlueField\" present",
                input: DeviceFilter::device_type(vec!["BlueField".to_string()], MatchMode::Prefix),
                expect: true,
            },
            Check {
                scenario: "part_number prefix \"MCX\" absent",
                input: DeviceFilter::part_number(vec!["MCX".to_string()], MatchMode::Prefix),
                expect: false,
            },
            Check {
                scenario: "firmware_version prefix \"22.32\" absent",
                input: DeviceFilter::firmware_version(vec!["22.32".to_string()], MatchMode::Prefix),
                expect: false,
            },
            Check {
                scenario: "mac_address prefix \"b8:3f\" absent",
                input: DeviceFilter::mac_address(vec!["b8:3f".to_string()], MatchMode::Prefix),
                expect: false,
            },
        ],
        |filter| filter.matches(&device),
    );
}

#[test]
fn test_device_filter_set_no_filters_matches_all() {
    let device = MlxDeviceInfo::create_test_device();
    let filter_set = DeviceFilterSet::new();

    assert!(filter_set.matches(&device));
    assert!(!filter_set.has_filters());
}

#[test]
fn test_device_filter_set_multiple_criteria_all_match() {
    let device = MlxDeviceInfo::create_test_device();
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["MCX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::firmware_version(
        vec!["22".to_string()],
        MatchMode::Prefix,
    ));

    assert!(filter_set.matches(&device));
    assert!(filter_set.has_filters());
}

#[test]
fn test_device_filter_set_multiple_criteria_one_fails() {
    let device = MlxDeviceInfo::create_test_device();
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["WRONG".to_string()],
        MatchMode::Prefix,
    ));

    assert!(!filter_set.matches(&device));
}

#[test]
fn test_device_filter_set_summary_empty() {
    let filter_set = DeviceFilterSet::new();
    let summary = filter_set.to_string();

    assert_eq!(summary, "No filters");
}

#[test]
fn test_device_filter_set_summary_with_filters() {
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["MCX".to_string()],
        MatchMode::Prefix,
    ));

    let summary_vec = filter_set.summary();

    assert_eq!(summary_vec.len(), 2);
    assert!(summary_vec.iter().any(|s| s.contains("device_type")));
    assert!(summary_vec.iter().any(|s| s.contains("part_number")));
}

// DeviceFilter::from_str parses "field:values[:match_mode]". The field and the
// (comma-split) values are required; an omitted match mode defaults to Regex.
// Each row pins the full parsed triple (field, values, match_mode).
#[test]
fn device_filter_from_str_parses_field_values_and_mode() {
    check_cases(
        [
            Case {
                scenario: "\"device_type:ConnectX\" defaults to regex",
                input: "device_type:ConnectX",
                expect: Yields((
                    DeviceField::DeviceType,
                    vec!["ConnectX".to_string()],
                    MatchMode::Regex,
                )),
            },
            Case {
                scenario: "\"part_number:MCX623:exact\" with explicit mode",
                input: "part_number:MCX623:exact",
                expect: Yields((
                    DeviceField::PartNumber,
                    vec!["MCX623".to_string()],
                    MatchMode::Exact,
                )),
            },
            Case {
                scenario: "\"device_type:ConnectX-6,ConnectX-7:prefix\" splits values",
                input: "device_type:ConnectX-6,ConnectX-7:prefix",
                expect: Yields((
                    DeviceField::DeviceType,
                    vec!["ConnectX-6".to_string(), "ConnectX-7".to_string()],
                    MatchMode::Prefix,
                )),
            },
        ],
        |s| {
            DeviceFilter::from_str(s)
                .map(|f| (f.field, f.values, f.match_mode))
                .map_err(drop)
        },
    );
}

// MatchMode::from_str accepts the three mode names case-insensitively and
// rejects anything else.
#[test]
fn match_mode_from_str_parses_known_modes() {
    check_cases(
        [
            Case {
                scenario: "\"regex\"",
                input: "regex",
                expect: Yields(MatchMode::Regex),
            },
            Case {
                scenario: "\"exact\"",
                input: "exact",
                expect: Yields(MatchMode::Exact),
            },
            Case {
                scenario: "\"prefix\"",
                input: "prefix",
                expect: Yields(MatchMode::Prefix),
            },
            Case {
                scenario: "\"REGEX\" is case-insensitive",
                input: "REGEX",
                expect: Yields(MatchMode::Regex),
            },
            Case {
                scenario: "\"invalid\" is rejected",
                input: "invalid",
                expect: Fails,
            },
        ],
        |s| MatchMode::from_str(s).map_err(drop),
    );
}

// DeviceField::from_str accepts each field's full name and its short alias, and
// rejects anything else.
#[test]
fn device_field_from_str_parses_names_and_aliases() {
    check_cases(
        [
            Case {
                scenario: "\"device_type\"",
                input: "device_type",
                expect: Yields(DeviceField::DeviceType),
            },
            Case {
                scenario: "\"type\" alias",
                input: "type",
                expect: Yields(DeviceField::DeviceType),
            },
            Case {
                scenario: "\"part_number\"",
                input: "part_number",
                expect: Yields(DeviceField::PartNumber),
            },
            Case {
                scenario: "\"part\" alias",
                input: "part",
                expect: Yields(DeviceField::PartNumber),
            },
            Case {
                scenario: "\"firmware_version\"",
                input: "firmware_version",
                expect: Yields(DeviceField::FirmwareVersion),
            },
            Case {
                scenario: "\"fw\" alias",
                input: "fw",
                expect: Yields(DeviceField::FirmwareVersion),
            },
            Case {
                scenario: "\"status\"",
                input: "status",
                expect: Yields(DeviceField::Status),
            },
            Case {
                scenario: "\"invalid\" is rejected",
                input: "invalid",
                expect: Fails,
            },
        ],
        |s| DeviceField::from_str(s).map_err(drop),
    );
}

#[test]
fn test_mixed_device_filtering() {
    let complete_device = MlxDeviceInfo::create_test_device();
    let partial_device = MlxDeviceInfo::create_test_device_with_missing_data();

    // Filter that should match only complete devices
    let part_filter = DeviceFilter::part_number(vec!["MCX".to_string()], MatchMode::Prefix);
    assert!(part_filter.matches(&complete_device));
    assert!(!part_filter.matches(&partial_device));

    // A ".*" regex on device type matches both, since device type is always present
    let type_filter = DeviceFilter::device_type(vec![".*".to_string()], MatchMode::Regex);
    assert!(type_filter.matches(&complete_device)); // ConnectX-6 Dx
    assert!(type_filter.matches(&partial_device)); // BlueField3

    // An explicit alternation matches both device types too
    let broad_filter =
        DeviceFilter::device_type(vec!["Connect.*|Blue.*".to_string()], MatchMode::Regex);
    assert!(broad_filter.matches(&complete_device));
    assert!(broad_filter.matches(&partial_device));
}
