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

// parse_show_no_args ensures show parses with no
// arguments (all power shelves).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["expected-power-shelf", "show"]).expect("should parse show");

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
    let cmd = Cmd::try_parse_from(["expected-power-shelf", "show", "1a:2b:3c:4d:5e:6f"])
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
        "expected-power-shelf",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--shelf-serial-number",
        "SHELF12345",
    ])
    .expect("should parse add");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.bmc_username, "admin");
            assert_eq!(args.shelf_serial_number, "SHELF12345");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_with_options ensures add parses with
// all options.
#[test]
fn parse_add_with_options() {
    let cmd = Cmd::try_parse_from([
        "expected-power-shelf",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--shelf-serial-number",
        "SHELF12345",
        "--meta-name",
        "MyPowerShelf",
        "--label",
        "env:prod",
    ])
    .expect("should parse add with options");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.meta_name, Some("MyPowerShelf".to_string()));
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_delete ensures delete parses with MAC address.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["expected-power-shelf", "delete", "1a:2b:3c:4d:5e:6f"])
        .expect("should parse delete");

    assert!(matches!(cmd, Cmd::Delete(_)));
}

// parse_update ensures update parses with required
// arguments.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from([
        "expected-power-shelf",
        "update",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--shelf-serial-number",
        "NEW_SERIAL",
    ])
    .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.shelf_serial_number, Some("NEW_SERIAL".to_string()));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_replace_all ensures replace-all parses with
// filename.
#[test]
fn parse_replace_all() {
    let cmd = Cmd::try_parse_from([
        "expected-power-shelf",
        "replace-all",
        "--filename",
        "shelves.json",
    ])
    .expect("should parse replace-all");

    match cmd {
        Cmd::ReplaceAll(args) => {
            assert_eq!(args.filename, "shelves.json");
        }
        _ => panic!("expected ReplaceAll variant"),
    }
}

// parse_erase ensures erase parses with no arguments.
#[test]
fn parse_erase() {
    let cmd = Cmd::try_parse_from(["expected-power-shelf", "erase"]).expect("should parse erase");

    assert!(matches!(cmd, Cmd::Erase(_)));
}

// parse_add_missing_required_fails ensures add fails
// without required arguments.
#[test]
fn parse_add_missing_required_fails() {
    let result = Cmd::try_parse_from(["expected-power-shelf", "add"]);
    assert!(result.is_err(), "should fail without required arguments");
}
