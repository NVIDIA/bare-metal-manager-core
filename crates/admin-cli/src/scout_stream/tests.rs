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
use carbide_test_support::{Case, check_cases};
use clap::{CommandFactory, Parser};

use super::*;

const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    ScoutStreamAction::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_show ensures show parses with no arguments and routes to the Show
// variant.
#[test]
fn parse_show() {
    check_cases(
        [Case {
            scenario: "show with no arguments",
            input: &["scout-stream", "show"][..],
            expect: Yields("show"),
        }],
        |argv| {
            ScoutStreamAction::try_parse_from(argv.iter().copied())
                .map(|a| variant(&a))
                .map_err(drop)
        },
    );
}

// The machine-id subcommands (disconnect, ping) parse the supplied id and route
// to their respective variant; this table confirms each one round-trips the id.
#[test]
fn parse_machine_id_subcommands() {
    check_cases(
        [
            Case {
                scenario: "disconnect parses machine_id",
                input: &["scout-stream", "disconnect", TEST_MACHINE_ID][..],
                expect: Yields(("disconnect", TEST_MACHINE_ID.to_string())),
            },
            Case {
                scenario: "ping parses machine_id",
                input: &["scout-stream", "ping", TEST_MACHINE_ID][..],
                expect: Yields(("ping", TEST_MACHINE_ID.to_string())),
            },
        ],
        |argv| {
            ScoutStreamAction::try_parse_from(argv.iter().copied())
                .map(|a| match a {
                    ScoutStreamAction::Disconnect(cmd) => {
                        ("disconnect", cmd.machine_id.to_string())
                    }
                    ScoutStreamAction::Ping(cmd) => ("ping", cmd.machine_id.to_string()),
                    _ => panic!("expected Disconnect or Ping variant"),
                })
                .map_err(drop)
        },
    );
}

// The machine-id subcommands reject an invocation that omits the required
// machine_id positional argument.
#[test]
fn missing_machine_id_is_rejected() {
    check_cases(
        [
            Case {
                scenario: "disconnect without machine_id",
                input: &["scout-stream", "disconnect"][..],
                expect: Fails,
            },
            Case {
                scenario: "ping without machine_id",
                input: &["scout-stream", "ping"][..],
                expect: Fails,
            },
        ],
        |argv| {
            ScoutStreamAction::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}

// variant names the parsed subcommand, for cases that only assert routing.
fn variant(action: &ScoutStreamAction) -> &'static str {
    match action {
        ScoutStreamAction::Show(_) => "show",
        ScoutStreamAction::Disconnect(_) => "disconnect",
        ScoutStreamAction::Ping(_) => "ping",
    }
}
