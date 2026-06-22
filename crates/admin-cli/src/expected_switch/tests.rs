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

// show parses with or without an optional MAC address; the yielded bool is
// whether a MAC was supplied.
#[test]
fn parse_show() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => args.bmc_mac_address.is_some(),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "show with no arguments (all switches)" {
            &["expected-switch", "show"][..] => Yields(false),
        }

        "show with a MAC address" {
            &["expected-switch", "show", "1a:2b:3c:4d:5e:6f"][..] => Yields(true),
        }
    );
}

// add parses with the required credential/serial set, and with the optional
// meta-name supplied; the yielded tuple is (bmc_username, switch_serial_number,
// meta_name).
#[test]
fn parse_add() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => {
                        (args.bmc_username, args.switch_serial_number, args.meta_name)
                    }
                    _ => panic!("expected Add variant"),
                })
                .map_err(drop)
        };
        "add with required arguments" {
            &[
                "expected-switch",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--switch-serial-number",
                "SW12345",
            ][..] => Yields(("admin".to_string(), "SW12345".to_string(), None)),
        }

        "add with all options" {
            &[
                "expected-switch",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--switch-serial-number",
                "SW12345",
                "--meta-name",
                "MySwitch",
                "--label",
                "env:prod",
            ][..] => Yields((
                "admin".to_string(),
                "SW12345".to_string(),
                Some("MySwitch".to_string()),
            )),
        }
    );
}

// update parses with the required MAC plus the optional serial-number override;
// the yielded value is the parsed switch_serial_number.
#[test]
fn parse_update() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Update(args) => args.switch_serial_number,
                    _ => panic!("expected Update variant"),
                })
                .map_err(drop)
        };
        "update with required arguments" {
            &[
                "expected-switch",
                "update",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--switch-serial-number",
                "NEW_SERIAL",
            ][..] => Yields(Some("NEW_SERIAL".to_string())),
        }
    );
}

// replace-all parses with a filename; the yielded value is the parsed filename.
#[test]
fn parse_replace_all() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::ReplaceAll(args) => args.filename,
                    _ => panic!("expected ReplaceAll variant"),
                })
                .map_err(drop)
        };
        "replace-all with a filename" {
            &[
                "expected-switch",
                "replace-all",
                "--filename",
                "switches.json",
            ][..] => Yields("switches.json".to_string()),
        }
    );
}

// delete and erase only need to route to their respective subcommand variants;
// the yielded string names the variant the argv landed on.
#[test]
fn parse_routes_to_variant() {
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

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "delete with a MAC address" {
            &["expected-switch", "delete", "1a:2b:3c:4d:5e:6f"][..] => Yields("delete"),
        }

        "erase with no arguments" {
            &["expected-switch", "erase"][..] => Yields("erase"),
        }
    );
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "add without its required arguments" {
            &["expected-switch", "add"][..] => Fails,
        }
    );
}
