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

use super::args::*;

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

// parse_inventory ensures inventory subcommand parses with no args.
#[test]
fn parse_inventory() {
    let cmd = Cmd::try_parse_from(["rms", "inventory"]).expect("should parse inventory");
    assert!(matches!(cmd, Cmd::Inventory));
}

// parse_poweron_sequence ensures poweron-sequence subcommand
// parses with no args.
#[test]
fn parse_poweron_sequence() {
    let cmd = Cmd::try_parse_from(["rms", "poweron-sequence", "rack-123"])
        .expect("should parse poweron-sequence");
    match cmd {
        Cmd::PowerOnSequence(args) => {
            assert_eq!(args.rack_id, "rack-123");
        }
        _ => panic!("expected poweron-sequence variant"),
    }
}

// parse_power_state ensures power-state parses with rack_id and node_id.
#[test]
fn parse_power_state() {
    let cmd = Cmd::try_parse_from(["rms", "power-state", "rack-123", "node-123"])
        .expect("should parse power-state");

    match cmd {
        Cmd::PowerState(args) => {
            assert_eq!(args.rack_id, "rack-123");
            assert_eq!(args.node_id, "node-123");
            assert_eq!(args.rack_id, "rack-123");
        }
        _ => panic!("expected PowerState variant"),
    }
}

// parse_firmware_inventory ensures firmware-inventory
// parses with rack_id and node_id.
#[test]
fn parse_firmware_inventory() {
    let cmd = Cmd::try_parse_from(["rms", "firmware-inventory", "rack-123", "node-123"])
        .expect("should parse firmware-inventory");

    match cmd {
        Cmd::FirmwareInventory(args) => {
            assert_eq!(args.rack_id, "rack-123");
            assert_eq!(args.node_id, "node-123");
            assert_eq!(args.rack_id, "rack-123");
        }
        _ => panic!("expected FirmwareInventory variant"),
    }
}
