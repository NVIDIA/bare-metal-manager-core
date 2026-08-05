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
use carbide_uuid::machine::MachineInterfaceId;
use clap::{CommandFactory, Parser};
use mac_address::MacAddress;

use super::*;
use crate::test_support::parse_leaf;

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
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["show"])
                .map(|matches| {
                    (
                        matches
                            .get_one::<MachineInterfaceId>("interface_id")
                            .is_some(),
                        matches.get_flag("all"),
                        matches.get_flag("more"),
                    )
                })
                .map_err(drop)
        };
        "no arguments (all interfaces)" {
            &["machine-interface", "show"][..] => Yields((false, false, false)),
        }

        "--more flag" {
            &["machine-interface", "show", "--more"][..] => Yields((false, false, true)),
        }

        "with an interface ID" {
            &["machine-interface", "show", TEST_INTERFACE_ID][..] => Yields((true, false, false)),
        }
    );
}

// delete parses either selector into its concrete ID or MAC address type and
// routes to the Delete variant.
#[test]
fn parse_delete_variants() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["delete"])
                .map(|matches| {
                    (
                        matches
                            .get_one::<MachineInterfaceId>("interface_id")
                            .copied(),
                        matches.get_one::<MacAddress>("mac_address").copied(),
                    )
                })
                .map_err(drop)
        };
        "with an interface ID" {
            &["machine-interface", "delete", TEST_INTERFACE_ID][..]
                => Yields((Some(TEST_INTERFACE_ID.parse::<MachineInterfaceId>().unwrap()), None)),
        }

        "with a MAC address" {
            &["machine-interface", "delete", "--mac-address", "00:11:22:33:44:55"][..]
                => Yields((None, Some("00:11:22:33:44:55".parse::<MacAddress>().unwrap()))),
        }

        "ID and MAC together are rejected" {
            &["machine-interface", "delete", TEST_INTERFACE_ID, "--mac-address", "00:11:22:33:44:55"][..]
                => Fails,
        }

        "a malformed MAC is rejected at parse time" {
            &["machine-interface", "delete", "--mac-address", "not-a-mac"][..] => Fails,
        }
    );
}

// Every malformed invocation is rejected at parse time -- e.g. delete left
// without its required interface ID.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "delete without an interface ID" {
            &["machine-interface", "delete"][..] => Fails,
        }
    );
}
