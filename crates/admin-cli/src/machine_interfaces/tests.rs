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

// Valid MachineInterfaceId format for tests (standard UUID format)
const TEST_INTERFACE_ID: &str = "00000000-0000-0000-0000-000000000001";

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
// arguments (all interfaces).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["machine-interface", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.interface_id.is_none());
            assert!(!args.all);
            assert!(!args.more);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_more ensures show parses with --more flag.
#[test]
fn parse_show_with_more() {
    let cmd = Cmd::try_parse_from(["machine-interface", "show", "--more"])
        .expect("should parse show --more");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.more);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_interface_id ensures show parses
// with interface ID.
#[test]
fn parse_show_with_interface_id() {
    let cmd = Cmd::try_parse_from(["machine-interface", "show", TEST_INTERFACE_ID])
        .expect("should parse show with interface ID");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.interface_id.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_delete ensures delete parses with interface ID.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["machine-interface", "delete", TEST_INTERFACE_ID])
        .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.interface_id.to_string(), TEST_INTERFACE_ID);
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_delete_missing_id_fails ensures delete fails
// without interface ID.
#[test]
fn parse_delete_missing_id_fails() {
    let result = Cmd::try_parse_from(["machine-interface", "delete"]);
    assert!(result.is_err(), "should fail without interface ID");
}
