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

// parse_poweron_order ensures poweron-order subcommand
// parses with rack_id.
#[test]
fn parse_poweron_order() {
    let cmd = Cmd::try_parse_from(["rms", "poweron-order", "rack-123"])
        .expect("should parse poweron-order");
    match cmd {
        Cmd::PoweronOrder(args) => {
            assert_eq!(args.rack_id, "rack-123");
        }
        _ => panic!("expected PoweronOrder variant"),
    }
}

// parse_bkc_files ensures bkc-files subcommand parses with no args.
#[test]
fn parse_bkc_files() {
    let cmd = Cmd::try_parse_from(["rms", "bkc-files"]).expect("should parse bkc-files");
    assert!(matches!(cmd, Cmd::BkcFiles));
}

// parse_check_bkc_compliance ensures check-bkc-compliance
// subcommand parses with no args.
#[test]
fn parse_check_bkc_compliance() {
    let cmd = Cmd::try_parse_from(["rms", "check-bkc-compliance"])
        .expect("should parse check-bkc-compliance");
    assert!(matches!(cmd, Cmd::CheckBkcCompliance));
}

// parse_remove_node ensures remove-node parses with rack_id and node_id.
#[test]
fn parse_remove_node() {
    let cmd = Cmd::try_parse_from(["rms", "remove-node", "rack-123", "node-123"])
        .expect("should parse remove-node");

    match cmd {
        Cmd::RemoveNode(args) => {
            assert_eq!(args.rack_id, "rack-123");
            assert_eq!(args.node_id, "node-123");
        }
        _ => panic!("expected RemoveNode variant"),
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
        }
        _ => panic!("expected FirmwareInventory variant"),
    }
}

// parse_available_fw_images ensures available-fw-images
// parses with optional rack_id and node_id.
#[test]
fn parse_available_fw_images() {
    let cmd = Cmd::try_parse_from(["rms", "available-fw-images"])
        .expect("should parse available-fw-images with no args");

    match cmd {
        Cmd::AvailableFwImages(args) => {
            assert!(args.rack_id.is_none());
            assert!(args.node_id.is_none());
        }
        _ => panic!("expected AvailableFwImages variant"),
    }
}

// parse_available_fw_images_with_args ensures available-fw-images
// parses with rack_id and node_id.
#[test]
fn parse_available_fw_images_with_args() {
    let cmd = Cmd::try_parse_from(["rms", "available-fw-images", "rack-123", "node-123"])
        .expect("should parse available-fw-images with args");

    match cmd {
        Cmd::AvailableFwImages(args) => {
            assert_eq!(args.rack_id.as_deref(), Some("rack-123"));
            assert_eq!(args.node_id.as_deref(), Some("node-123"));
        }
        _ => panic!("expected AvailableFwImages variant"),
    }
}

// parse_remove_node_requires_args ensures remove-node
// requires both rack_id and node_id.
#[test]
fn parse_remove_node_requires_args() {
    let result = Cmd::try_parse_from(["rms", "remove-node"]);
    assert!(result.is_err(), "should fail without rack_id and node_id");

    let result = Cmd::try_parse_from(["rms", "remove-node", "rack-123"]);
    assert!(result.is_err(), "should fail without node_id");
}
