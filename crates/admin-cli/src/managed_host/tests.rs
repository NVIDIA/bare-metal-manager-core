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

// parse_show_no_args ensures show parses with no
// arguments (all hosts).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["managed-host", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.machine.is_none());
            assert!(!args.all);
            assert!(!args.ips);
            assert!(!args.more);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_machine ensures show parses with
// machine ID.
#[test]
fn parse_show_with_machine() {
    let cmd = Cmd::try_parse_from(["managed-host", "show", TEST_MACHINE_ID])
        .expect("should parse show with machine");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.machine.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_fix_flag ensures show parses with
// --fix flag.
#[test]
fn parse_show_with_fix_flag() {
    let cmd =
        Cmd::try_parse_from(["managed-host", "show", "--fix"]).expect("should parse show --fix");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.fix);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_maintenance_on ensures maintenance on parses
// with required args.
#[test]
fn parse_maintenance_on() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "maintenance",
        "on",
        "--host",
        TEST_MACHINE_ID,
        "--reference",
        "TICKET-123",
    ])
    .expect("should parse maintenance on");

    match cmd {
        Cmd::Maintenance(MaintenanceAction::On(args)) => {
            assert_eq!(args.host.to_string(), TEST_MACHINE_ID);
            assert_eq!(args.reference, "TICKET-123");
        }
        _ => panic!("expected Maintenance On variant"),
    }
}

// parse_maintenance_off ensures maintenance off parses
// with required args.
#[test]
fn parse_maintenance_off() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "maintenance",
        "off",
        "--host",
        TEST_MACHINE_ID,
    ])
    .expect("should parse maintenance off");

    match cmd {
        Cmd::Maintenance(MaintenanceAction::Off(args)) => {
            assert_eq!(args.host.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Maintenance Off variant"),
    }
}

// parse_quarantine_on ensures quarantine on parses
// with required args.
#[test]
fn parse_quarantine_on() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "quarantine",
        "on",
        "--host",
        TEST_MACHINE_ID,
        "--reason",
        "Security issue",
    ])
    .expect("should parse quarantine on");

    match cmd {
        Cmd::Quarantine(QuarantineAction::On(args)) => {
            assert_eq!(args.host.to_string(), TEST_MACHINE_ID);
            assert_eq!(args.reason, "Security issue");
        }
        _ => panic!("expected Quarantine On variant"),
    }
}

// parse_quarantine_off ensures quarantine off parses
// with required args.
#[test]
fn parse_quarantine_off() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "quarantine",
        "off",
        "--host",
        TEST_MACHINE_ID,
    ])
    .expect("should parse quarantine off");

    match cmd {
        Cmd::Quarantine(QuarantineAction::Off(args)) => {
            assert_eq!(args.host.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Quarantine Off variant"),
    }
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

// parse_power_options_show ensures power-options
// show parses.
#[test]
fn parse_power_options_show() {
    let cmd = Cmd::try_parse_from(["managed-host", "power-options", "show"])
        .expect("should parse power-options show");

    match cmd {
        Cmd::PowerOptions(PowerOptions::Show(args)) => {
            assert!(args.machine.is_none());
        }
        _ => panic!("expected PowerOptions Show variant"),
    }
}

// parse_power_options_update ensures power-options
// update parses.
#[test]
fn parse_power_options_update() {
    let cmd = Cmd::try_parse_from([
        "managed-host",
        "power-options",
        "update",
        TEST_MACHINE_ID,
        "--desired-power-state",
        "on",
    ])
    .expect("should parse power-options update");

    match cmd {
        Cmd::PowerOptions(PowerOptions::Update(args)) => {
            assert_eq!(args.machine.to_string(), TEST_MACHINE_ID);
            assert_eq!(args.desired_power_state, DesiredPowerState::On);
        }
        _ => panic!("expected PowerOptions Update variant"),
    }
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

// parse_maintenance_on_missing_required_fails ensures
// maintenance on fails without required args.
#[test]
fn parse_maintenance_on_missing_required_fails() {
    let result = Cmd::try_parse_from(["managed-host", "maintenance", "on"]);
    assert!(
        result.is_err(),
        "should fail without --host and --reference"
    );
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// desired_power_state_value_enum ensures DesiredPowerState
// parses from strings.
#[test]
fn desired_power_state_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        DesiredPowerState::from_str("on", false),
        Ok(DesiredPowerState::On)
    ));
    assert!(matches!(
        DesiredPowerState::from_str("off", false),
        Ok(DesiredPowerState::Off)
    ));
    assert!(matches!(
        DesiredPowerState::from_str("power-manager-disabled", false),
        Ok(DesiredPowerState::PowerManagerDisabled)
    ));
    assert!(DesiredPowerState::from_str("invalid", false).is_err());
}
