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

use super::args::*;

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

// parse_with_no_args ensures parses with no arguments
// (optional filename).
#[test]
fn parse_with_no_args() {
    let cmd = Cmd::try_parse_from(["inventory"]).expect("should parse with no args");
    assert!(cmd.filename.is_none());
}

// parse_with_filename ensures parses with --filename option.
#[test]
fn parse_with_filename() {
    let cmd = Cmd::try_parse_from(["inventory", "--filename", "output.json"])
        .expect("should parse with filename");
    assert_eq!(cmd.filename, Some("output.json".to_string()));
}

// parse_with_short_flag ensures parses with -f short flag.
#[test]
fn parse_with_short_flag() {
    let cmd =
        Cmd::try_parse_from(["inventory", "-f", "output.json"]).expect("should parse with -f");
    assert_eq!(cmd.filename, Some("output.json".to_string()));
}

// parse_with_various_filenames ensures parses various
// filename formats.
#[test]
fn parse_with_various_filenames() {
    let cmd1 = Cmd::try_parse_from(["inventory", "-f", "/tmp/inventory.json"])
        .expect("should parse absolute path");
    assert_eq!(cmd1.filename, Some("/tmp/inventory.json".to_string()));

    let cmd2 = Cmd::try_parse_from(["inventory", "-f", "./relative/path.csv"])
        .expect("should parse relative path");
    assert_eq!(cmd2.filename, Some("./relative/path.csv".to_string()));
}
