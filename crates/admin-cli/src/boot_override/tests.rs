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

use super::*;
use crate::test_support::{parse_with_leaf_matches, raw_value};

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

// The get and clear subcommands each route to their own variant and parse the
// shared interface_id. The closure yields the routed variant name paired with the
// parsed interface_id, so one table covers both.
#[test]
fn parse_get_and_clear() {
    scenarios!(
        run = |argv| {
            let subcommand = argv[1];
            parse_with_leaf_matches::<Cmd>(argv, &[subcommand])
                .map(|(cmd, matches)| {
                    let variant = match cmd {
                        Cmd::Get(_) => "get",
                        Cmd::Clear(_) => "clear",
                        _ => panic!("expected Get or Clear variant"),
                    };
                    (
                        variant,
                        matches
                            .get_one::<MachineInterfaceId>("interface_id")
                            .expect("interface_id is required")
                            .to_string(),
                    )
                })
                .map_err(drop)
        };
        "get routes to Get and parses interface_id" {
            &[
                "boot-override",
                "get",
                "550e8400-e29b-41d4-a716-446655440000",
            ][..] => Yields(("get", "550e8400-e29b-41d4-a716-446655440000".to_string())),
        }

        "clear routes to Clear and parses interface_id" {
            &[
                "boot-override",
                "clear",
                "550e8400-e29b-41d4-a716-446655440000",
            ][..] => Yields(("clear", "550e8400-e29b-41d4-a716-446655440000".to_string())),
        }
    );
}

// parse_set covers the set subcommand: it parses with just interface_id
// (custom flags unset), with the long --custom-pxe/--custom-user-data flags,
// and with the short -p/-u aliases. Each row yields the parsed
// (interface_id, custom_pxe, custom_user_data).
#[test]
fn parse_set() {
    scenarios!(
        run = |argv| {
            parse_with_leaf_matches::<Cmd>(argv, &["set"])
                .map(|(cmd, matches)| {
                    assert!(matches!(cmd, Cmd::Set(_)));
                    (
                        matches
                            .get_one::<MachineInterfaceId>("interface_id")
                            .expect("interface_id is required")
                            .to_string(),
                        raw_value(&matches, "custom_pxe"),
                        raw_value(&matches, "custom_user_data"),
                    )
                })
                .map_err(drop)
        };
        "set with just interface_id leaves the custom flags unset" {
            &[
                "boot-override",
                "set",
                "550e8400-e29b-41d4-a716-446655440000",
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                None,
                None,
            )),
        }

        "set with the long --custom-pxe/--custom-user-data flags" {
            &[
                "boot-override",
                "set",
                "550e8400-e29b-41d4-a716-446655440000",
                "--custom-pxe",
                "http://pxe.example.com/boot",
                "--custom-user-data",
                "some-user-data",
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                Some("http://pxe.example.com/boot".to_string()),
                Some("some-user-data".to_string()),
            )),
        }

        "set with the short -p/-u aliases" {
            &[
                "boot-override",
                "set",
                "550e8400-e29b-41d4-a716-446655440000",
                "-p",
                "http://pxe.example.com/boot",
                "-u",
                "some-user-data",
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                Some("http://pxe.example.com/boot".to_string()),
                Some("some-user-data".to_string()),
            )),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, a subcommand
// invoked without its required interface_id.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "get without interface_id" {
            &["boot-override", "get"][..] => Fails,
        }
    );
}
