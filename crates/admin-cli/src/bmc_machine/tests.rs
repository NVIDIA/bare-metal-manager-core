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

// parse_bmc_reset ensures bmc-reset parses with
// required args.
#[test]
fn parse_bmc_reset() {
    let cmd = Cmd::try_parse_from(["bmc-machine", "bmc-reset", "--machine", "machine-123"])
        .expect("should parse bmc-reset");

    match cmd {
        Cmd::BmcReset(args) => {
            assert_eq!(args.machine, "machine-123");
            assert!(!args.use_ipmitool);
        }
        _ => panic!("expected BmcReset variant"),
    }
}

// parse_bmc_reset_with_ipmitool ensures bmc-reset
// parses with --use-ipmitool flag.
#[test]
fn parse_bmc_reset_with_ipmitool() {
    let cmd = Cmd::try_parse_from([
        "bmc-machine",
        "bmc-reset",
        "--machine",
        "machine-123",
        "--use-ipmitool",
    ])
    .expect("should parse bmc-reset with ipmitool");

    match cmd {
        Cmd::BmcReset(args) => {
            assert!(args.use_ipmitool);
        }
        _ => panic!("expected BmcReset variant"),
    }
}

// parse_admin_power_control ensures admin-power-control
// parses correctly.
#[test]
fn parse_admin_power_control() {
    let cmd = Cmd::try_parse_from([
        "bmc-machine",
        "admin-power-control",
        "--machine",
        "machine-123",
        "--action",
        "on",
    ])
    .expect("should parse admin-power-control");

    match cmd {
        Cmd::AdminPowerControl(args) => {
            assert_eq!(args.machine, "machine-123");
            assert!(matches!(args.action, AdminPowerControlAction::On));
        }
        _ => panic!("expected AdminPowerControl variant"),
    }
}

// parse_lockdown_enable ensures lockdown parses with
// --enable.
#[test]
fn parse_lockdown_enable() {
    let cmd = Cmd::try_parse_from([
        "bmc-machine",
        "lockdown",
        "--machine",
        TEST_MACHINE_ID,
        "--enable",
    ])
    .expect("should parse lockdown with enable");

    match cmd {
        Cmd::Lockdown(args) => {
            assert!(args.enable);
            assert!(!args.disable);
        }
        _ => panic!("expected Lockdown variant"),
    }
}

// parse_lockdown_disable ensures lockdown parses with
// --disable.
#[test]
fn parse_lockdown_disable() {
    let cmd = Cmd::try_parse_from([
        "bmc-machine",
        "lockdown",
        "--machine",
        TEST_MACHINE_ID,
        "--disable",
    ])
    .expect("should parse lockdown with disable");

    match cmd {
        Cmd::Lockdown(args) => {
            assert!(!args.enable);
            assert!(args.disable);
        }
        _ => panic!("expected Lockdown variant"),
    }
}

// parse_lockdown_requires_enable_or_disable ensures
// lockdown fails without enable/disable.
#[test]
fn parse_lockdown_requires_enable_or_disable() {
    let result = Cmd::try_parse_from(["bmc-machine", "lockdown", "--machine", TEST_MACHINE_ID]);
    assert!(result.is_err(), "should fail without --enable or --disable");
}

// parse_lockdown_conflicts_enable_disable ensures
// lockdown fails with both enable and disable.
#[test]
fn parse_lockdown_conflicts_enable_disable() {
    let result = Cmd::try_parse_from([
        "bmc-machine",
        "lockdown",
        "--machine",
        TEST_MACHINE_ID,
        "--enable",
        "--disable",
    ]);
    assert!(
        result.is_err(),
        "should fail with both --enable and --disable"
    );
}

// parse_create_bmc_user ensures create-bmc-user parses
// correctly.
#[test]
fn parse_create_bmc_user() {
    let cmd = Cmd::try_parse_from([
        "bmc-machine",
        "create-bmc-user",
        "--username",
        "admin",
        "--password",
        "secret123",
        "--ip-address",
        "192.168.1.100",
    ])
    .expect("should parse create-bmc-user");

    match cmd {
        Cmd::CreateBmcUser(args) => {
            assert_eq!(args.username, "admin");
            assert_eq!(args.password, "secret123");
            assert_eq!(args.ip_address, Some("192.168.1.100".to_string()));
        }
        _ => panic!("expected CreateBmcUser variant"),
    }
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
