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
    RedfishAction::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_bios_attrs ensures bios-attrs parses.
#[test]
fn parse_bios_attrs() {
    let action =
        RedfishAction::try_parse_from(["redfish", "bios-attrs"]).expect("should parse bios-attrs");

    assert!(matches!(action.command, Cmd::BiosAttrs));
}

// parse_boot_hdd ensures boot-hdd parses.
#[test]
fn parse_boot_hdd() {
    let action =
        RedfishAction::try_parse_from(["redfish", "boot-hdd"]).expect("should parse boot-hdd");

    assert!(matches!(action.command, Cmd::BootHdd));
}

// parse_boot_pxe ensures boot-pxe parses.
#[test]
fn parse_boot_pxe() {
    let action =
        RedfishAction::try_parse_from(["redfish", "boot-pxe"]).expect("should parse boot-pxe");

    assert!(matches!(action.command, Cmd::BootPxe));
}

// parse_get_power_state ensures get-power-state parses.
#[test]
fn parse_get_power_state() {
    let action = RedfishAction::try_parse_from(["redfish", "get-power-state"])
        .expect("should parse get-power-state");

    assert!(matches!(action.command, Cmd::GetPowerState));
}

// parse_force_off ensures force-off parses.
#[test]
fn parse_force_off() {
    let action =
        RedfishAction::try_parse_from(["redfish", "force-off"]).expect("should parse force-off");

    assert!(matches!(action.command, Cmd::ForceOff));
}

// parse_force_restart ensures force-restart parses.
#[test]
fn parse_force_restart() {
    let action = RedfishAction::try_parse_from(["redfish", "force-restart"])
        .expect("should parse force-restart");

    assert!(matches!(action.command, Cmd::ForceRestart));
}

// parse_on ensures on parses.
#[test]
fn parse_on() {
    let action = RedfishAction::try_parse_from(["redfish", "on"]).expect("should parse on");

    assert!(matches!(action.command, Cmd::On));
}

// parse_with_address ensures command parses with
// global address option.
#[test]
fn parse_with_address() {
    let action =
        RedfishAction::try_parse_from(["redfish", "--address", "192.168.1.100", "get-power-state"])
            .expect("should parse with address");

    assert_eq!(action.address, Some("192.168.1.100".to_string()));
}

// parse_with_credentials ensures command parses with
// global credentials.
#[test]
fn parse_with_credentials() {
    let action = RedfishAction::try_parse_from([
        "redfish",
        "--address",
        "192.168.1.100",
        "--username",
        "admin",
        "--password",
        "secret",
        "get-power-state",
    ])
    .expect("should parse with credentials");

    assert_eq!(action.username, Some("admin".to_string()));
    assert_eq!(action.password, Some("secret".to_string()));
}

// parse_create_bmc_user ensures create-bmc-user parses
// with required args.
#[test]
fn parse_create_bmc_user() {
    let action = RedfishAction::try_parse_from([
        "redfish",
        "create-bmc-user",
        "--new-password",
        "secret",
        "--user",
        "admin",
    ])
    .expect("should parse create-bmc-user");

    match action.command {
        Cmd::CreateBmcUser(args) => {
            assert_eq!(args.user, "admin");
            assert_eq!(args.new_password, "secret");
        }
        _ => panic!("expected CreateBmcUser variant"),
    }
}

// parse_dpu_firmware_status ensures dpu firmware status parses.
#[test]
fn parse_dpu_firmware_status() {
    let action = RedfishAction::try_parse_from(["redfish", "dpu", "firmware", "status"])
        .expect("should parse dpu firmware status");

    match action.command {
        Cmd::Dpu(DpuOperations::Firmware(FwCommand::Status)) => {}
        _ => panic!("expected Dpu Firmware Status variant"),
    }
}

// parse_browse ensures browse parses with uri.
#[test]
fn parse_browse() {
    let action = RedfishAction::try_parse_from(["redfish", "browse", "--uri", "/redfish/v1"])
        .expect("should parse browse");

    match action.command {
        Cmd::Browse(args) => {
            assert_eq!(args.uri, "/redfish/v1");
        }
        _ => panic!("expected Browse variant"),
    }
}
