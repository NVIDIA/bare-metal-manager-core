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

// parse_list_defaults ensures list parses with default values.
#[test]
fn parse_list_defaults() {
    let cmd = Cmd::try_parse_from(["rack-firmware", "list"]).expect("should parse list");

    match cmd {
        Cmd::List(args) => {
            assert!(!args.only_available);
        }
        _ => panic!("expected List variant"),
    }
}

// parse_list_only_available ensures list parses with --only-available flag.
#[test]
fn parse_list_only_available() {
    let cmd = Cmd::try_parse_from(["rack-firmware", "list", "--only-available"])
        .expect("should parse list with only-available");

    match cmd {
        Cmd::List(args) => {
            assert!(args.only_available);
        }
        _ => panic!("expected List variant"),
    }
}

// parse_create_missing_args_fails ensures create fails without required args.
#[test]
fn parse_create_missing_args_fails() {
    let result = Cmd::try_parse_from(["rack-firmware", "create"]);
    assert!(result.is_err(), "should fail without json_file and token");
}

// parse_get_missing_id_fails ensures get fails without ID.
#[test]
fn parse_get_missing_id_fails() {
    let result = Cmd::try_parse_from(["rack-firmware", "get"]);
    assert!(result.is_err(), "should fail without id");
}

// parse_delete_missing_id_fails ensures delete fails without ID.
#[test]
fn parse_delete_missing_id_fails() {
    let result = Cmd::try_parse_from(["rack-firmware", "delete"]);
    assert!(result.is_err(), "should fail without id");
}
