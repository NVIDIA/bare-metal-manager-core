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

// variant names the subcommand a parsed `Cmd` routed to, so cases that only
// assert routing (delete, erase) can compare a stable string.
fn variant(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::Show(_) => "show",
        Cmd::Add(_) => "add",
        Cmd::Delete(_) => "delete",
        Cmd::Update(_) => "update",
        Cmd::ReplaceAll(_) => "replace-all",
        Cmd::Erase(_) => "erase",
    }
}

// show parses both with no MAC argument (all power shelves) and with one; the
// yielded bool is whether `bmc_mac_address` was supplied.
#[test]
fn parse_show() {
    check_cases(
        [
            Case {
                scenario: "show with no arguments (all power shelves)",
                input: &["expected-power-shelf", "show"][..],
                expect: Yields(false),
            },
            Case {
                scenario: "show with a MAC address",
                input: &["expected-power-shelf", "show", "1a:2b:3c:4d:5e:6f"][..],
                expect: Yields(true),
            },
        ],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Show(args)) => Ok(args.bmc_mac_address.is_some()),
            Ok(other) => panic!("expected Show variant, got {}", variant(&other)),
            Err(_) => Err(()),
        },
    );
}

// add parses with the required arguments alone and with the full optional set;
// the yielded tuple is the fields the originals asserted (username, serial,
// and the optional meta-name).
#[test]
fn parse_add() {
    check_cases(
        [
            Case {
                scenario: "add with required arguments",
                input: &[
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
                ][..],
                expect: Yields(("admin".to_string(), "SHELF12345".to_string(), None)),
            },
            Case {
                scenario: "add with all options",
                input: &[
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
                ][..],
                expect: Yields((
                    "admin".to_string(),
                    "SHELF12345".to_string(),
                    Some("MyPowerShelf".to_string()),
                )),
            },
        ],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Add(args)) => Ok((args.bmc_username, args.shelf_serial_number, args.meta_name)),
            Ok(other) => panic!("expected Add variant, got {}", variant(&other)),
            Err(_) => Err(()),
        },
    );
}

// update parses with the required arguments; the yielded value is the new
// serial number the original asserted.
#[test]
fn parse_update() {
    check_cases(
        [Case {
            scenario: "update with required arguments",
            input: &[
                "expected-power-shelf",
                "update",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--shelf-serial-number",
                "NEW_SERIAL",
            ][..],
            expect: Yields(Some("NEW_SERIAL".to_string())),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Update(args)) => Ok(args.shelf_serial_number),
            Ok(other) => panic!("expected Update variant, got {}", variant(&other)),
            Err(_) => Err(()),
        },
    );
}

// replace-all parses with a filename; the yielded value is that filename.
#[test]
fn parse_replace_all() {
    check_cases(
        [Case {
            scenario: "replace-all with a filename",
            input: &[
                "expected-power-shelf",
                "replace-all",
                "--filename",
                "shelves.json",
            ][..],
            expect: Yields("shelves.json".to_string()),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::ReplaceAll(args)) => Ok(args.filename),
            Ok(other) => panic!("expected ReplaceAll variant, got {}", variant(&other)),
            Err(_) => Err(()),
        },
    );
}

// delete and erase only need to route to their respective subcommand variant;
// the yielded value is the variant name.
#[test]
fn parse_routes_to_variant() {
    check_cases(
        [
            Case {
                scenario: "delete with a MAC address",
                input: &["expected-power-shelf", "delete", "1a:2b:3c:4d:5e:6f"][..],
                expect: Yields("delete"),
            },
            Case {
                scenario: "erase with no arguments",
                input: &["expected-power-shelf", "erase"][..],
                expect: Yields("erase"),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- here, an add missing
// its required arguments.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "add without its required arguments",
            input: &["expected-power-shelf", "add"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
