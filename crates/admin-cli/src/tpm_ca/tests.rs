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

// The argument-free subcommands route to their own variant: `show` lists every
// CA, `show-unmatched-ek` lists endorsement keys with no matching CA.
#[test]
fn parse_routes_argument_free_subcommands() {
    fn variant(cmd: &Cmd) -> &'static str {
        match cmd {
            Cmd::Show(_) => "show",
            Cmd::ShowUnmatchedEk(_) => "show-unmatched-ek",
            _ => "other",
        }
    }

    check_cases(
        [
            Case {
                scenario: "show parses with no arguments",
                input: &["tpm-ca", "show"][..],
                expect: Yields("show"),
            },
            Case {
                scenario: "show-unmatched-ek parses with no arguments",
                input: &["tpm-ca", "show-unmatched-ek"][..],
                expect: Yields("show-unmatched-ek"),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        },
    );
}

// parse_delete ensures delete parses with ca_id.
#[test]
fn parse_delete() {
    Case {
        scenario: "delete parses with --ca-id",
        input: &["tpm-ca", "delete", "--ca-id", "123"][..],
        expect: Yields(123),
    }
    .check(|argv| {
        Cmd::try_parse_from(argv.iter().copied())
            .map(|cmd| match cmd {
                Cmd::Delete(args) => args.ca_id,
                _ => panic!("expected Delete variant"),
            })
            .map_err(drop)
    });
}

// parse_add ensures add parses with filename.
#[test]
fn parse_add() {
    Case {
        scenario: "add parses with --filename",
        input: &["tpm-ca", "add", "--filename", "ca.pem"][..],
        expect: Yields("ca.pem".to_string()),
    }
    .check(|argv| {
        Cmd::try_parse_from(argv.iter().copied())
            .map(|cmd| match cmd {
                Cmd::Add(args) => args.filename,
                _ => panic!("expected Add variant"),
            })
            .map_err(drop)
    });
}

// parse_add_bulk ensures add-bulk parses with dirname.
#[test]
fn parse_add_bulk() {
    Case {
        scenario: "add-bulk parses with --dirname",
        input: &["tpm-ca", "add-bulk", "--dirname", "/path/to/certs"][..],
        expect: Yields("/path/to/certs".to_string()),
    }
    .check(|argv| {
        Cmd::try_parse_from(argv.iter().copied())
            .map(|cmd| match cmd {
                Cmd::AddBulk(args) => args.dirname,
                _ => panic!("expected AddBulk variant"),
            })
            .map_err(drop)
    });
}

// Every subcommand that takes a required argument is rejected at parse time when
// that argument is omitted: delete without --ca-id, add without --filename, and
// add-bulk without --dirname.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "delete without --ca-id",
                input: &["tpm-ca", "delete"][..],
                expect: Fails,
            },
            Case {
                scenario: "add without --filename",
                input: &["tpm-ca", "add"][..],
                expect: Fails,
            },
            Case {
                scenario: "add-bulk without --dirname",
                input: &["tpm-ca", "add-bulk"][..],
                expect: Fails,
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
