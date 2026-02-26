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
// Command Structure   - Baseline debug_assert() of the entire command.
// Argument Parsing    - Ensure required/optional arg combinations parse correctly.
// Validation Logic    - Test business logic validators on parsed arguments.

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

// parse_show_no_args ensures show parses with no
// arguments (all machines).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["expected-machine", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.bmc_mac_address.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_mac ensures show parses with MAC address.
#[test]
fn parse_show_with_mac() {
    let cmd = Cmd::try_parse_from(["expected-machine", "show", "1a:2b:3c:4d:5e:6f"])
        .expect("should parse show with MAC");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.bmc_mac_address.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_add ensures add parses with required arguments.
#[test]
fn parse_add() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse add");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.bmc_username, "admin");
            assert_eq!(args.chassis_serial_number, "SN12345");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_with_options ensures add parses with
// all options.
#[test]
fn parse_add_with_options() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--meta-name",
        "MyMachine",
        "--label",
        "env:prod",
        "--sku-id",
        "sku123",
    ])
    .expect("should parse add with options");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.meta_name, Some("MyMachine".to_string()));
            assert_eq!(args.sku_id, Some("sku123".to_string()));
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_delete ensures delete parses with MAC address.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["expected-machine", "delete", "1a:2b:3c:4d:5e:6f"])
        .expect("should parse delete");

    assert!(matches!(cmd, Cmd::Delete(_)));
}

// parse_patch ensures patch parses with required arguments.
#[test]
fn parse_patch() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--sku-id",
        "new_sku",
    ])
    .expect("should parse patch");

    match cmd {
        Cmd::Patch(args) => {
            assert_eq!(args.sku_id, Some("new_sku".to_string()));
        }
        _ => panic!("expected Patch variant"),
    }
}

// parse_update ensures update parses with filename.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from(["expected-machine", "update", "--filename", "machine.json"])
        .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.filename, "machine.json");
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_replace_all ensures replace-all parses with
// filename.
#[test]
fn parse_replace_all() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "replace-all",
        "--filename",
        "machines.json",
    ])
    .expect("should parse replace-all");

    match cmd {
        Cmd::ReplaceAll(args) => {
            assert_eq!(args.filename, "machines.json");
        }
        _ => panic!("expected ReplaceAll variant"),
    }
}

// parse_erase ensures erase parses with no arguments.
#[test]
fn parse_erase() {
    let cmd = Cmd::try_parse_from(["expected-machine", "erase"]).expect("should parse erase");

    assert!(matches!(cmd, Cmd::Erase(_)));
}

// parse_add_missing_required_fails ensures add fails
// without required arguments.
#[test]
fn parse_add_missing_required_fails() {
    let result = Cmd::try_parse_from(["expected-machine", "add"]);
    assert!(result.is_err(), "should fail without required arguments");
}

// parse_patch_username_requires_password ensures patch
// fails with username only (password required).
#[test]
fn parse_patch_username_requires_password() {
    let result = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-username",
        "admin",
    ]);
    assert!(result.is_err(), "should fail with username but no password");
}

// parse_patch_password_requires_username ensures patch
// fails with password only (username required).
#[test]
fn parse_patch_password_requires_username() {
    let result = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-password",
        "secret",
    ]);
    assert!(result.is_err(), "should fail with password but no username");
}

// parse_update_missing_filename_fails ensures update
// fails without --filename.
#[test]
fn parse_update_missing_filename_fails() {
    let result = Cmd::try_parse_from(["expected-machine", "update"]);
    assert!(result.is_err(), "should fail without --filename");
}

// parse_add_dpu_serial_requires_value ensures add fails
// when --fallback-dpu-serial-number has no value.
#[test]
fn parse_add_dpu_serial_requires_value() {
    let result = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "0a:0b:0c:0d:0e:0f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--fallback-dpu-serial-number",
    ]);
    assert!(result.is_err(), "should fail without dpu serial value");
}

/////////////////////////////////////////////////////////////////////////////
// Validation Logic
//
// This section tests business logic validators on parsed arguments,
// including custom validation methods like duplicate detection.

// validate_no_duplicate_dpu_serials ensures
// has_duplicate_dpu_serials returns false for unique serials.
#[test]
fn validate_no_duplicate_dpu_serials() {
    let machine = add::Args::try_parse_from([
        "ExpectedMachine",
        "--bmc-mac-address",
        "0a:0b:0c:0d:0e:0f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--fallback-dpu-serial-number",
        "dpu1",
        "-d",
        "dpu2",
        "-d",
        "dpu3",
    ])
    .expect("should parse");

    assert!(
        !machine.has_duplicate_dpu_serials(),
        "unique serials should not be duplicates"
    );
}

// validate_duplicate_dpu_serials_detected ensures
// has_duplicate_dpu_serials returns true for duplicates.
#[test]
fn validate_duplicate_dpu_serials_detected() {
    let machine = add::Args::try_parse_from([
        "ExpectedMachine",
        "--bmc-mac-address",
        "0a:0b:0c:0d:0e:0f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "-d",
        "dpu1",
        "-d",
        "dpu2",
        "-d",
        "dpu3",
        "-d",
        "dpu1",
    ])
    .expect("should parse");

    assert!(
        machine.has_duplicate_dpu_serials(),
        "duplicate serials should be detected"
    );
}

// validate_empty_dpu_serials ensures has_duplicate_dpu_serials
// returns false when no serials provided.
#[test]
fn validate_empty_dpu_serials() {
    let machine = add::Args::try_parse_from([
        "ExpectedMachine",
        "--bmc-mac-address",
        "0a:0b:0c:0d:0e:0f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse");

    assert!(
        !machine.has_duplicate_dpu_serials(),
        "empty serials should not be duplicates"
    );
}

// validate_patch_with_dpu_serials ensures patch validate()
// passes with unique DPU serials.
#[test]
fn validate_patch_with_dpu_serials() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--fallback-dpu-serial-number",
        "dpu1",
        "-d",
        "dpu2",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "unique serials should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_duplicate_dpu_serials_fails ensures patch
// validate() fails with duplicate DPU serials.
#[test]
fn validate_patch_duplicate_dpu_serials_fails() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--fallback-dpu-serial-number",
        "dpu1",
        "-d",
        "dpu2",
        "-d",
        "dpu3",
        "-d",
        "dpu2",
        "-d",
        "dpu4",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(
                args.validate().is_err(),
                "duplicate serials should fail validation"
            );
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_with_credentials ensures patch validate()
// passes with username and password together.
#[test]
fn validate_patch_with_credentials() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "credentials should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_all_fields ensures patch validate()
// passes with all fields provided.
#[test]
fn validate_patch_all_fields() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--fallback-dpu-serial-number",
        "dpu1",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "all fields should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}
