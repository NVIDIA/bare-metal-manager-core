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
// Enum Conversions  - Test From implementations for proto <-> non-proto mapping.
// ValueEnum Parsing - Test string parsing for types deriving claps ValueEnum.

use carbide_test_support::Outcome::*;
use carbide_test_support::{Case, check_cases};
use clap::{CommandFactory, Parser};

use super::common::AdminPowerControlAction;
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

// parse_bmc_reset routes to the BmcReset variant; the --machine value is
// captured verbatim and --use-ipmitool toggles the flag (default off).
#[test]
fn parse_bmc_reset() {
    check_cases(
        [
            Case {
                scenario: "bmc-reset with required args, ipmitool off",
                input: &["bmc-machine", "bmc-reset", "--machine", "machine-123"][..],
                expect: Yields(("machine-123".to_string(), false)),
            },
            Case {
                scenario: "bmc-reset with --use-ipmitool",
                input: &[
                    "bmc-machine",
                    "bmc-reset",
                    "--machine",
                    "machine-123",
                    "--use-ipmitool",
                ][..],
                expect: Yields(("machine-123".to_string(), true)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::BmcReset(args) => (args.machine, args.use_ipmitool),
                    _ => panic!("expected BmcReset variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_admin_power_control routes to the AdminPowerControl variant; the
// --machine value is captured and --action on maps to the On action.
#[test]
fn parse_admin_power_control() {
    check_cases(
        [Case {
            scenario: "admin-power-control --action on",
            input: &[
                "bmc-machine",
                "admin-power-control",
                "--machine",
                "machine-123",
                "--action",
                "on",
            ][..],
            expect: Yields(("machine-123".to_string(), true)),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::AdminPowerControl(args) => (
                        args.machine,
                        matches!(args.action, AdminPowerControlAction::On),
                    ),
                    _ => panic!("expected AdminPowerControl variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_lockdown routes to the Lockdown variant; --enable and --disable are
// mutually exclusive flags, each setting exactly its own bool.
#[test]
fn parse_lockdown() {
    check_cases(
        [
            Case {
                scenario: "lockdown --enable",
                input: &[
                    "bmc-machine",
                    "lockdown",
                    "--machine",
                    TEST_MACHINE_ID,
                    "--enable",
                ][..],
                expect: Yields((true, false)),
            },
            Case {
                scenario: "lockdown --disable",
                input: &[
                    "bmc-machine",
                    "lockdown",
                    "--machine",
                    TEST_MACHINE_ID,
                    "--disable",
                ][..],
                expect: Yields((false, true)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Lockdown(args) => (args.enable, args.disable),
                    _ => panic!("expected Lockdown variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_create_bmc_user routes to the CreateBmcUser variant, capturing the
// username, password, and optional IP address.
#[test]
fn parse_create_bmc_user() {
    check_cases(
        [Case {
            scenario: "create-bmc-user with username, password, and ip",
            input: &[
                "bmc-machine",
                "create-bmc-user",
                "--username",
                "admin",
                "--password",
                "secret123",
                "--ip-address",
                "192.168.1.100",
            ][..],
            expect: Yields((
                "admin".to_string(),
                "secret123".to_string(),
                Some("192.168.1.100".to_string()),
            )),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::CreateBmcUser(args) => (args.username, args.password, args.ip_address),
                    _ => panic!("expected CreateBmcUser variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed lockdown invocation is rejected at parse time -- neither
// --enable nor --disable, or both at once (a conflict).
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "lockdown without --enable or --disable",
                input: &["bmc-machine", "lockdown", "--machine", TEST_MACHINE_ID][..],
                expect: Fails,
            },
            Case {
                scenario: "lockdown with both --enable and --disable",
                input: &[
                    "bmc-machine",
                    "lockdown",
                    "--machine",
                    TEST_MACHINE_ID,
                    "--enable",
                    "--disable",
                ][..],
                expect: Fails,
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}

/////////////////////////////////////////////////////////////////////////////
// Enum Conversions
//
// This section is for testing the proto <-> non-proto enum
// From implementations that exist, ensuring enums translate
// from -> into their expected variants.

// admin_power_control_action_to_proto ensures
// AdminPowerControlAction converts to protobuf.
#[test]
fn admin_power_control_action_to_proto() {
    use rpc::forge::admin_power_control_request::SystemPowerControl;

    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::On),
        SystemPowerControl::On
    ));
    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::GracefulShutdown),
        SystemPowerControl::GracefulShutdown
    ));
    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::ForceOff),
        SystemPowerControl::ForceOff
    ));
    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::GracefulRestart),
        SystemPowerControl::GracefulRestart
    ));
    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::ForceRestart),
        SystemPowerControl::ForceRestart
    ));
    assert!(matches!(
        SystemPowerControl::from(AdminPowerControlAction::ACPowercycle),
        SystemPowerControl::AcPowercycle
    ));
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// admin_power_control_action_value_enum ensures AdminPowerControlAction
// parses from strings.
#[test]
fn admin_power_control_action_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        AdminPowerControlAction::from_str("on", false),
        Ok(AdminPowerControlAction::On)
    ));
    assert!(matches!(
        AdminPowerControlAction::from_str("graceful-shutdown", false),
        Ok(AdminPowerControlAction::GracefulShutdown)
    ));
    assert!(matches!(
        AdminPowerControlAction::from_str("force-off", false),
        Ok(AdminPowerControlAction::ForceOff)
    ));
    assert!(matches!(
        AdminPowerControlAction::from_str("graceful-restart", false),
        Ok(AdminPowerControlAction::GracefulRestart)
    ));
    assert!(matches!(
        AdminPowerControlAction::from_str("force-restart", false),
        Ok(AdminPowerControlAction::ForceRestart)
    ));
    assert!(matches!(
        AdminPowerControlAction::from_str("ac-powercycle", false),
        Ok(AdminPowerControlAction::ACPowercycle)
    ));
    assert!(AdminPowerControlAction::from_str("invalid", false).is_err());
}
