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

// show parses with any combination of its optional args; each row yields the
// observed (interface_id present, --all, --more) so the no-args, --more, and
// interface-id cases are all checked against one parse.
#[test]
fn parse_show_variants() {
    check_cases(
        [
            Case {
                scenario: "no arguments (all interfaces)",
                input: &["machine-interface", "show"][..],
                expect: Yields((false, false, false)),
            },
            Case {
                scenario: "--more flag",
                input: &["machine-interface", "show", "--more"][..],
                expect: Yields((false, false, true)),
            },
            Case {
                scenario: "with an interface ID",
                input: &["machine-interface", "show", TEST_INTERFACE_ID][..],
                expect: Yields((true, false, false)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.interface_id.is_some(), args.all, args.more),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// delete parses with an interface ID and routes to the Delete variant,
// round-tripping the ID through its string form.
#[test]
fn parse_delete_variants() {
    check_cases(
        [Case {
            scenario: "with an interface ID",
            input: &["machine-interface", "delete", TEST_INTERFACE_ID][..],
            expect: Yields(TEST_INTERFACE_ID.to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.interface_id.to_string(),
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- e.g. delete left
// without its required interface ID.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "delete without an interface ID",
            input: &["machine-interface", "delete"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
