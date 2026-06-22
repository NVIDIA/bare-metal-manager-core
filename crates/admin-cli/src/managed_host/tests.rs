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
// ValueEnum Parsing - Test string parsing for types deriving claps ValueEnum.

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use clap::{CommandFactory, Parser};

use super::maintenance::args::Args as MaintenanceAction;
use super::power_options::args::{Args as PowerOptions, DesiredPowerState};
use super::quarantine::args::Args as QuarantineAction;
use super::*;

// Define a basic/working MachineId for testing.
const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

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

// show routes to the Show variant across its argument combinations: bare (all
// hosts), with a machine id, and with --fix. Each row yields the parsed
// (machine.is_some(), all, ips, more, fix) so every original assertion holds.
#[test]
fn parse_show_routes_to_show() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (
                        args.machine.is_some(),
                        args.all,
                        args.ips,
                        args.more,
                        args.fix,
                    ),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "no args (all hosts)" {
            &["managed-host", "show"][..] => Yields((false, false, false, false, false)),
        }

        "with machine id" {
            &["managed-host", "show", TEST_MACHINE_ID][..] => Yields((true, false, false, false, false)),
        }

        "with --fix flag" {
            &["managed-host", "show", "--fix"][..] => Yields((false, false, false, false, true)),
        }
    );
}

// maintenance on/off route to the Maintenance variant with the expected host
// (and reference, for `on`). Each row yields (host, reference) -- reference is
// empty for the `off` case which carries none.
#[test]
fn parse_maintenance_routes_to_maintenance() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Maintenance(MaintenanceAction::On(args)) => {
                        (args.host.to_string(), args.reference)
                    }
                    Cmd::Maintenance(MaintenanceAction::Off(args)) => {
                        (args.host.to_string(), String::new())
                    }
                    _ => panic!("expected Maintenance variant"),
                })
                .map_err(drop)
        };
        "on with host and reference" {
            &[
                "managed-host",
                "maintenance",
                "on",
                "--host",
                TEST_MACHINE_ID,
                "--reference",
                "TICKET-123",
            ][..] => Yields((TEST_MACHINE_ID.to_string(), "TICKET-123".to_string())),
        }

        "off with host" {
            &[
                "managed-host",
                "maintenance",
                "off",
                "--host",
                TEST_MACHINE_ID,
            ][..] => Yields((TEST_MACHINE_ID.to_string(), String::new())),
        }
    );
}

// quarantine on/off route to the Quarantine variant with the expected host
// (and reason, for `on`). Each row yields (host, reason) -- reason is empty
// for the `off` case which carries none.
#[test]
fn parse_quarantine_routes_to_quarantine() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Quarantine(QuarantineAction::On(args)) => {
                        (args.host.to_string(), args.reason)
                    }
                    Cmd::Quarantine(QuarantineAction::Off(args)) => {
                        (args.host.to_string(), String::new())
                    }
                    _ => panic!("expected Quarantine variant"),
                })
                .map_err(drop)
        };
        "on with host and reason" {
            &[
                "managed-host",
                "quarantine",
                "on",
                "--host",
                TEST_MACHINE_ID,
                "--reason",
                "Security issue",
            ][..] => Yields((TEST_MACHINE_ID.to_string(), "Security issue".to_string())),
        }

        "off with host" {
            &[
                "managed-host",
                "quarantine",
                "off",
                "--host",
                TEST_MACHINE_ID,
            ][..] => Yields((TEST_MACHINE_ID.to_string(), String::new())),
        }
    );
}

// parse_reset_host_reprovisioning ensures
// reset-host-reprovisioning parses.
#[test]
fn parse_reset_host_reprovisioning() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "reset-host-reprovisioning",
        "--machine",
        TEST_MACHINE_ID,
    ])
    .expect("should parse reset-host-reprovisioning");

    match cmd {
        Cmd::ResetHostReprovisioning(args) => {
            assert_eq!(args.machine.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected ResetHostReprovisioning variant"),
    }
}

// power-options show/update route to the PowerOptions variant. show carries no
// machine; update carries a machine and a desired power state. Each row yields
// (machine, desired-power-state-string) -- show yields (empty, empty).
#[test]
fn parse_power_options_routes_to_power_options() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::PowerOptions(PowerOptions::Show(args)) => {
                        assert!(args.machine.is_none());
                        (String::new(), String::new())
                    }
                    Cmd::PowerOptions(PowerOptions::Update(args)) => (
                        args.machine.to_string(),
                        format!("{:?}", args.desired_power_state),
                    ),
                    _ => panic!("expected PowerOptions variant"),
                })
                .map_err(drop)
        };
        "show with no machine" {
            &["managed-host", "power-options", "show"][..] => Yields((String::new(), String::new())),
        }

        "update with machine and desired power state" {
            &[
                "managed-host",
                "power-options",
                "update",
                TEST_MACHINE_ID,
                "--desired-power-state",
                "on",
            ][..] => Yields((
                TEST_MACHINE_ID.to_string(),
                format!("{:?}", DesiredPowerState::On),
            )),
        }
    );
}

// parse_set_primary_dpu ensures set-primary-dpu parses
// with required args.
#[test]
fn parse_set_primary_dpu() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "set-primary-dpu",
        TEST_MACHINE_ID,
        TEST_MACHINE_ID,
    ])
    .expect("should parse set-primary-dpu");

    match cmd {
        Cmd::SetPrimaryDpu(args) => {
            assert!(!args.reboot);
        }
        _ => panic!("expected SetPrimaryDpu variant"),
    }
}

// parse_set_primary_interface ensures set-primary-interface parses
// with required args (a host machine id and a machine interface id).
#[test]
fn parse_set_primary_interface() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "set-primary-interface",
        TEST_MACHINE_ID,
        "00000000-0000-0000-0000-000000000001",
    ])
    .expect("should parse set-primary-interface");

    match cmd {
        Cmd::SetPrimaryInterface(args) => {
            assert!(!args.reboot);
        }
        _ => panic!("expected SetPrimaryInterface variant"),
    }
}

// parse_debug_bundle ensures debug-bundle parses with
// required args.
#[test]
fn parse_debug_bundle() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "debug-bundle",
        TEST_MACHINE_ID,
        "--start-time",
        "2025-01-01 00:00:00",
    ])
    .expect("should parse debug-bundle");

    match cmd {
        Cmd::DebugBundle(args) => {
            assert_eq!(args.host_id, TEST_MACHINE_ID);
            assert_eq!(args.start_time, "2025-01-01 00:00:00");
            assert!(!args.utc);
        }
        _ => panic!("expected DebugBundle variant"),
    }
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "maintenance on without --host and --reference" {
            &["managed-host", "maintenance", "on"][..] => Fails,
        }
    );
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// desired_power_state_value_enum ensures DesiredPowerState parses from its
// string representations, and rejects an unknown value. Each row yields the
// debug form of the parsed variant; the unknown value fails.
#[test]
fn desired_power_state_value_enum() {
    use clap::ValueEnum;

    scenarios!(
        run = |s| DesiredPowerState::from_str(s, false).map(|v| format!("{v:?}"));
        "on" {
            "on" => Yields(format!("{:?}", DesiredPowerState::On)),
        }

        "off" {
            "off" => Yields(format!("{:?}", DesiredPowerState::Off)),
        }

        "power-manager-disabled" {
            "power-manager-disabled" => Yields(format!("{:?}", DesiredPowerState::PowerManagerDisabled)),
        }

        "invalid value" {
            "invalid" => Fails,
        }
    );
}
