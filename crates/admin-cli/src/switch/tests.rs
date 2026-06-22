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
use carbide_uuid::switch::SwitchId;
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

// show parses with or without an identifier: with no positional it leaves
// switch_id unset (all switches); given a SwitchId it parses that exact id.
#[test]
fn parse_show_routes_to_show() {
    use std::str::FromStr;

    let switch_id = "sw100nsmnq69j4ntqlj162fnnbvg747gfqbicaa6tqgq6spocirfle7rom0";

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => args.switch_id,
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "no args parses with no switch id" {
            &["switch", "show"][..] => Yields(None),
        }

        "an identifier parses to that switch id" {
            &["switch", "show", switch_id][..] => Yields(Some(SwitchId::from_str(switch_id).unwrap())),
        }
    );
}

// list parses with no arguments, and with its optional filter flags: bare
// `list` leaves the filters at their defaults, while the flags set deleted,
// controller-state, and bmc-mac. The tuple is
// (deleted == Only, controller_state, bmc_mac.is_some()).
#[test]
fn parse_list_routes_to_list() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::List(args) => (
                        matches!(args.deleted, rpc::forge::DeletedFilter::Only),
                        args.controller_state,
                        args.bmc_mac.is_some(),
                    ),
                    _ => panic!("expected List variant"),
                })
                .map_err(drop)
        };
        "no args parses with default filters" {
            &["switch", "list"][..] => Yields((false, None, false)),
        }

        "filter flags parse onto the args" {
            &[
                "switch",
                "list",
                "--deleted",
                "only",
                "--controller-state",
                "ready",
                "--bmc-mac",
                "AA:BB:CC:DD:EE:FF",
            ][..] => Yields((true, Some("ready".to_string()), true)),
        }
    );
}

// Every malformed list invocation is rejected at parse time -- an out-of-range
// `--deleted` value, or a `--bmc-mac` that isn't a MAC address.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "list with an invalid --deleted value" {
            &["switch", "list", "--deleted", "bogus"][..] => Fails,
        }

        "list with an invalid --bmc-mac" {
            &["switch", "list", "--bmc-mac", "not-a-mac"][..] => Fails,
        }
    );
}
