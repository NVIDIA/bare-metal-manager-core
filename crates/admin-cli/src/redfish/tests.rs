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

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
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

// variant names the parsed subcommand so routing tests can assert which
// `Cmd` an argv lands on without matching every payload-free variant by hand.
fn variant(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::BiosAttrs => "bios-attrs",
        Cmd::BootHdd => "boot-hdd",
        Cmd::BootPxe => "boot-pxe",
        Cmd::GetPowerState => "get-power-state",
        Cmd::ForceOff => "force-off",
        Cmd::ForceRestart => "force-restart",
        Cmd::On => "on",
        other => panic!("unexpected variant: {other:?}"),
    }
}

// Each payload-free subcommand routes to its matching `Cmd` variant when given
// a valid global --address.
#[test]
fn payload_free_subcommands_route_to_their_variant() {
    scenarios!(
        run = |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| variant(&a.command))
                .map_err(drop)
        };
        "bios-attrs" {
            &["redfish", "--address", "192.0.2.10", "bios-attrs"][..] => Yields("bios-attrs"),
        }

        "boot-hdd" {
            &["redfish", "--address", "192.0.2.10", "boot-hdd"][..] => Yields("boot-hdd"),
        }

        "boot-pxe" {
            &["redfish", "--address", "192.0.2.10", "boot-pxe"][..] => Yields("boot-pxe"),
        }

        "get-power-state" {
            &["redfish", "--address", "192.0.2.10", "get-power-state"][..] => Yields("get-power-state"),
        }

        "force-off" {
            &["redfish", "--address", "192.0.2.10", "force-off"][..] => Yields("force-off"),
        }

        "force-restart" {
            &["redfish", "--address", "192.0.2.10", "force-restart"][..] => Yields("force-restart"),
        }

        "on" {
            &["redfish", "--address", "192.0.2.10", "on"][..] => Yields("on"),
        }
    );
}

// parse_with_address ensures command parses with
// global address option.
#[test]
fn parse_with_address() {
    let action =
        RedfishAction::try_parse_from(["redfish", "--address", "192.168.1.100", "get-power-state"])
            .expect("should parse with address");

    assert_eq!(action.address, "192.168.1.100");
}

// parse_missing_address_is_error ensures a missing --address is rejected by
// clap itself (a usage error with exit code 2), enforcing the requirement at
// parse time rather than via a runtime check in the handler. The requirement
// lives on the parent, so one representative subcommand covers every variant.
#[test]
fn parse_missing_address_is_error() {
    let err = RedfishAction::try_parse_from(["redfish", "get-power-state"])
        .expect_err("missing --address should be a parse error");

    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    assert_eq!(err.exit_code(), 2);
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

// create-bmc-user parses with its required args, carrying user and
// new-password through to the CreateBmcUser variant.
#[test]
fn parse_create_bmc_user() {
    scenarios!(
        run = |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| match a.command {
                    Cmd::CreateBmcUser(args) => (args.user, args.new_password),
                    _ => panic!("expected CreateBmcUser variant"),
                })
                .map_err(drop)
        };
        "create-bmc-user with user and new-password" {
            &[
                "redfish",
                "--address",
                "192.0.2.10",
                "create-bmc-user",
                "--new-password",
                "secret",
                "--user",
                "admin",
            ][..] => Yields(("admin".to_string(), "secret".to_string())),
        }
    );
}

// `dpu firmware status` parses through the nested DpuOperations / FwCommand
// subcommands to the Dpu Firmware Status variant.
#[test]
fn parse_dpu_firmware_status() {
    scenarios!(
        run = |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| match a.command {
                    Cmd::Dpu(DpuOperations::Firmware(FwCommand::Status)) => "dpu firmware status",
                    _ => panic!("expected Dpu Firmware Status variant"),
                })
                .map_err(drop)
        };
        "dpu firmware status" {
            &[
                "redfish",
                "--address",
                "192.0.2.10",
                "dpu",
                "firmware",
                "status",
            ][..] => Yields("dpu firmware status"),
        }
    );
}
