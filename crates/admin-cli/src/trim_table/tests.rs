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

// The intent of the tests.rs file is to test the integrity of the
// command, including things like basic structure parsing, enum
// translations, and any external input validators that are
// configured. Specific "categories" are:
//
// Command Structure - Baseline debug_assert() of the entire command.
// Argument Parsing  - Ensure required/optional arg combinations parse correctly.

use clap::{CommandFactory, Parser};

use super::*;

// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_measured_boot ensures measured-boot parses with keep_entries.
#[test]
fn parse_measured_boot() {
    let cmd = Cmd::try_parse_from(["trim-table", "measured-boot", "--keep-entries", "100"])
        .expect("should parse measured-boot");

    match cmd {
        Cmd::MeasuredBoot(args) => {
            assert_eq!(args.keep_entries, 100);
        }
    }
}

// parse_measured_boot_zero ensures measured-boot accepts zero entries.
#[test]
fn parse_measured_boot_zero() {
    let cmd = Cmd::try_parse_from(["trim-table", "measured-boot", "--keep-entries", "0"])
        .expect("should parse with zero");

    match cmd {
        Cmd::MeasuredBoot(args) => {
            assert_eq!(args.keep_entries, 0);
        }
    }
}

// parse_measured_boot_large_value ensures measured-boot
// accepts large values.
#[test]
fn parse_measured_boot_large_value() {
    let cmd = Cmd::try_parse_from(["trim-table", "measured-boot", "--keep-entries", "1000000"])
        .expect("should parse large value");

    match cmd {
        Cmd::MeasuredBoot(args) => {
            assert_eq!(args.keep_entries, 1000000);
        }
    }
}

// parse_measured_boot_missing_arg_fails ensures
// measured-boot requires --keep-entries.
#[test]
fn parse_measured_boot_missing_arg_fails() {
    let result = Cmd::try_parse_from(["trim-table", "measured-boot"]);
    assert!(result.is_err(), "should fail without --keep-entries");
}

// parse_measured_boot_invalid_value_fails ensures
// measured-boot fails with non-numeric value.
#[test]
fn parse_measured_boot_invalid_value_fails() {
    let result = Cmd::try_parse_from(["trim-table", "measured-boot", "--keep-entries", "abc"]);
    assert!(result.is_err(), "should fail with non-numeric value");
}

// parse_measured_boot_negative_fails ensures measured-boot
// fails with negative value.
#[test]
fn parse_measured_boot_negative_fails() {
    let result = Cmd::try_parse_from(["trim-table", "measured-boot", "--keep-entries", "-1"]);
    assert!(result.is_err(), "should fail with negative value");
}
