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

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
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

// variant names the subcommand a parsed Cmd routes to, for cases that only
// assert "routes to variant X" with no field checks.
fn variant(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::List(_) => "list",
        Cmd::Grow(_) => "grow",
    }
}

// list parses with no arguments and routes to the List variant.
#[test]
fn parse_list() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "list with no arguments" {
            &["resource-pool", "list"][..] => Yields("list"),
        }
    );
}

// grow parses with --filename and surfaces that filename on the Grow variant.
#[test]
fn parse_grow() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Grow(args) => args.filename,
                    _ => panic!("expected Grow variant"),
                })
                .map_err(drop)
        };
        "grow with --filename" {
            &["resource-pool", "grow", "--filename", "config.toml"][..] => Yields("config.toml".to_string()),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, grow without
// its required --filename.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "grow without --filename" {
            &["resource-pool", "grow"][..] => Fails,
        }
    );
}
