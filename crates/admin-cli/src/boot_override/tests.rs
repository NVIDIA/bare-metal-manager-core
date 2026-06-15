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

// parse_get ensures the get subcommand routes to the Get variant and
// parses its interface_id.
#[test]
fn parse_get() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Get(args) => args.inner.interface_id.to_string(),
                    _ => panic!("expected Get variant"),
                })
                .map_err(drop)
        };
        "get parses interface_id" {
            &[
                "boot-override",
                "get",
                "550e8400-e29b-41d4-a716-446655440000",
            ][..] => Yields("550e8400-e29b-41d4-a716-446655440000".to_string()),
        }
    );
}

// parse_clear ensures the clear subcommand routes to the Clear variant and
// parses its interface_id.
#[test]
fn parse_clear() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Clear(args) => args.inner.interface_id.to_string(),
                    _ => panic!("expected Clear variant"),
                })
                .map_err(drop)
        };
        "clear parses interface_id" {
            &[
                "boot-override",
                "clear",
                "550e8400-e29b-41d4-a716-446655440000",
            ][..] => Yields("550e8400-e29b-41d4-a716-446655440000".to_string()),
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
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Set(args) => (
                        args.interface_id.to_string(),
                        args.custom_pxe,
                        args.custom_user_data,
                    ),
                    _ => panic!("expected Set variant"),
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
