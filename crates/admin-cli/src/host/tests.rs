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

// parse_set_uefi_password ensures set-uefi-password
// parses with machine query.
#[test]
fn parse_set_uefi_password() {
    let cmd = Cmd::try_parse_from(["host", "set-uefi-password", "--query", "machine-123"])
        .expect("should parse set-uefi-password");

    assert!(matches!(cmd, Cmd::SetUefiPassword(_)));
}

// parse_clear_uefi_password ensures clear-uefi-password
// parses with machine query.
#[test]
fn parse_clear_uefi_password() {
    let cmd = Cmd::try_parse_from(["host", "clear-uefi-password", "--query", "machine-123"])
        .expect("should parse clear-uefi-password");

    assert!(matches!(cmd, Cmd::ClearUefiPassword(_)));
}

// parse_generate_host_uefi_password ensures
// generate-host-uefi-password parses with no args.
#[test]
fn parse_generate_host_uefi_password() {
    let cmd = Cmd::try_parse_from(["host", "generate-host-uefi-password"])
        .expect("should parse generate-host-uefi-password");

    assert!(matches!(cmd, Cmd::GenerateHostUefiPassword(_)));
}

// Define a basic/working MachineId for testing.
const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

// parse_reprovision_set ensures reprovision set parses
// with required args.
#[test]
fn parse_reprovision_set() {
    let cmd = Cmd::try_parse_from(["host", "reprovision", "set", "--id", TEST_MACHINE_ID])
        .expect("should parse reprovision set");

    match cmd {
        Cmd::Reprovision(reprovision::args::Args::Set(args)) => {
            assert_eq!(args.id.to_string(), TEST_MACHINE_ID);
            assert!(!args.update_firmware);
            assert!(args.update_message.is_none());
        }
        _ => panic!("expected Reprovision Set variant"),
    }
}

// parse_reprovision_set_with_options ensures
// reprovision set parses with all options.
#[test]
fn parse_reprovision_set_with_options() {
    let cmd = Cmd::try_parse_from([
        "host",
        "reprovision",
        "set",
        "--id",
        TEST_MACHINE_ID,
        "--update-firmware",
        "--update-message",
        "Maintenance in progress",
    ])
    .expect("should parse reprovision set with options");

    match cmd {
        Cmd::Reprovision(reprovision::args::Args::Set(args)) => {
            assert!(args.update_firmware);
            assert_eq!(
                args.update_message,
                Some("Maintenance in progress".to_string())
            );
        }
        _ => panic!("expected Reprovision Set variant"),
    }
}

// parse_reprovision_clear ensures reprovision clear
// parses with required args.
#[test]
fn parse_reprovision_clear() {
    let cmd = Cmd::try_parse_from(["host", "reprovision", "clear", "--id", TEST_MACHINE_ID])
        .expect("should parse reprovision clear");

    match cmd {
        Cmd::Reprovision(reprovision::args::Args::Clear(args)) => {
            assert_eq!(args.id.to_string(), TEST_MACHINE_ID);
            assert!(!args.update_firmware);
        }
        _ => panic!("expected Reprovision Clear variant"),
    }
}

// parse_reprovision_list ensures reprovision list
// parses with no args.
#[test]
fn parse_reprovision_list() {
    let cmd = Cmd::try_parse_from(["host", "reprovision", "list"])
        .expect("should parse reprovision list");

    assert!(matches!(
        cmd,
        Cmd::Reprovision(reprovision::args::Args::List)
    ));
}

// parse_reprovision_set_missing_id_fails ensures
// reprovision set requires --id.
#[test]
fn parse_reprovision_set_missing_id_fails() {
    let result = Cmd::try_parse_from(["host", "reprovision", "set"]);
    assert!(result.is_err(), "should fail without --id");
}

// parse_reprovision_mark_manual_upgrade_complete ensures
// mark-manual-upgrade-complete parses with required --id.
#[test]
fn parse_reprovision_mark_manual_upgrade_complete() {
    let cmd = Cmd::try_parse_from([
        "host",
        "reprovision",
        "mark-manual-upgrade-complete",
        "--id",
        TEST_MACHINE_ID,
    ])
    .expect("should parse mark-manual-upgrade-complete");

    match cmd {
        Cmd::Reprovision(reprovision::args::Args::MarkManualUpgradeComplete(args)) => {
            assert_eq!(args.id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Reprovision MarkManualUpgradeComplete variant"),
    }
}

// parse_reprovision_mark_manual_upgrade_complete_missing_id_fails
// ensures mark-manual-upgrade-complete requires --id.
#[test]
fn parse_reprovision_mark_manual_upgrade_complete_missing_id_fails() {
    let result = Cmd::try_parse_from(["host", "reprovision", "mark-manual-upgrade-complete"]);
    assert!(result.is_err(), "should fail without --id");
}
