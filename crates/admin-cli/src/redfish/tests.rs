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
use carbide_test_support::{Case, check_cases};
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
    check_cases(
        [
            Case {
                scenario: "bios-attrs",
                input: &["redfish", "--address", "192.0.2.10", "bios-attrs"][..],
                expect: Yields("bios-attrs"),
            },
            Case {
                scenario: "boot-hdd",
                input: &["redfish", "--address", "192.0.2.10", "boot-hdd"][..],
                expect: Yields("boot-hdd"),
            },
            Case {
                scenario: "boot-pxe",
                input: &["redfish", "--address", "192.0.2.10", "boot-pxe"][..],
                expect: Yields("boot-pxe"),
            },
            Case {
                scenario: "get-power-state",
                input: &["redfish", "--address", "192.0.2.10", "get-power-state"][..],
                expect: Yields("get-power-state"),
            },
            Case {
                scenario: "force-off",
                input: &["redfish", "--address", "192.0.2.10", "force-off"][..],
                expect: Yields("force-off"),
            },
            Case {
                scenario: "force-restart",
                input: &["redfish", "--address", "192.0.2.10", "force-restart"][..],
                expect: Yields("force-restart"),
            },
            Case {
                scenario: "on",
                input: &["redfish", "--address", "192.0.2.10", "on"][..],
                expect: Yields("on"),
            },
        ],
        |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| variant(&a.command))
                .map_err(drop)
        },
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
    check_cases(
        [Case {
            scenario: "create-bmc-user with user and new-password",
            input: &[
                "redfish",
                "--address",
                "192.0.2.10",
                "create-bmc-user",
                "--new-password",
                "secret",
                "--user",
                "admin",
            ][..],
            expect: Yields(("admin".to_string(), "secret".to_string())),
        }],
        |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| match a.command {
                    Cmd::CreateBmcUser(args) => (args.user, args.new_password),
                    _ => panic!("expected CreateBmcUser variant"),
                })
                .map_err(drop)
        },
    );
}

// `dpu firmware status` parses through the nested DpuOperations / FwCommand
// subcommands to the Dpu Firmware Status variant.
#[test]
fn parse_dpu_firmware_status() {
    check_cases(
        [Case {
            scenario: "dpu firmware status",
            input: &[
                "redfish",
                "--address",
                "192.0.2.10",
                "dpu",
                "firmware",
                "status",
            ][..],
            expect: Yields("dpu firmware status"),
        }],
        |argv| {
            RedfishAction::try_parse_from(argv.iter().copied())
                .map(|a| match a.command {
                    Cmd::Dpu(DpuOperations::Firmware(FwCommand::Status)) => "dpu firmware status",
                    _ => panic!("expected Dpu Firmware Status variant"),
                })
                .map_err(drop)
        },
    );
}
