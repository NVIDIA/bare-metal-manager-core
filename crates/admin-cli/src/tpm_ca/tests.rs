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

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "show parses with no arguments" {
            &["tpm-ca", "show"][..] => Yields("show"),
        }

        "show-unmatched-ek parses with no arguments" {
            &["tpm-ca", "show-unmatched-ek"][..] => Yields("show-unmatched-ek"),
        }
    );
}

// parse_delete ensures delete parses with ca_id.
#[test]
fn parse_delete() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.ca_id,
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        };
        "delete parses with --ca-id" {
            &["tpm-ca", "delete", "--ca-id", "123"][..] => Yields(123),
        }
    );
}

// parse_add ensures add parses with filename.
#[test]
fn parse_add() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => args.filename,
                    _ => panic!("expected Add variant"),
                })
                .map_err(drop)
        };
        "add parses with --filename" {
            &["tpm-ca", "add", "--filename", "ca.pem"][..] => Yields("ca.pem".to_string()),
        }
    );
}

// parse_add_bulk ensures add-bulk parses with dirname.
#[test]
fn parse_add_bulk() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::AddBulk(args) => args.dirname,
                    _ => panic!("expected AddBulk variant"),
                })
                .map_err(drop)
        };
        "add-bulk parses with --dirname" {
            &["tpm-ca", "add-bulk", "--dirname", "/path/to/certs"][..] => Yields("/path/to/certs".to_string()),
        }
    );
}

// Every subcommand that takes a required argument is rejected at parse time when
// that argument is omitted: delete without --ca-id, add without --filename, and
// add-bulk without --dirname.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "delete without --ca-id" {
            &["tpm-ca", "delete"][..] => Fails,
        }

        "add without --filename" {
            &["tpm-ca", "add"][..] => Fails,
        }

        "add-bulk without --dirname" {
            &["tpm-ca", "add-bulk"][..] => Fails,
        }
    );
}
