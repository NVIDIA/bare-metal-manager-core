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
// ValueEnum Parsing - Test clap ValueEnum translations (if applicable).

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use clap::{CommandFactory, Parser};

use super::*;

// variant names the parsed subcommand so a routing-only case can assert
// "parsed into the right variant" without inspecting any fields.
fn variant(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::Get(_) => "get",
        Cmd::Add(_) => "add",
        Cmd::Remove(_) => "remove",
        Cmd::Replace(_) => "replace",
    }
}

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

// Each subcommand parses to its own variant, with no arguments required:
// `get` always, and `add`/`remove`/`replace` accept an empty IP list too.
#[test]
fn subcommands_route_to_their_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "get with no args" {
            &["route-server", "get"][..] => Yields("get"),
        }

        "remove with an IP" {
            &["route-server", "remove", "192.168.1.1"][..] => Yields("remove"),
        }

        "replace with an IP" {
            &["route-server", "replace", "192.168.1.1"][..] => Yields("replace"),
        }
    );
}

// The positional IP list parses for add/remove/replace: a single address, a
// comma-separated list, and the empty (no-args) case all land as the right
// count. Yields the parsed IP count for whichever subcommand carries them.
#[test]
fn ip_list_parses_for_each_subcommand() {
    fn ip_count(cmd: &Cmd) -> usize {
        match cmd {
            Cmd::Add(args) => args.inner.ip.len(),
            Cmd::Remove(args) => args.inner.ip.len(),
            Cmd::Replace(args) => args.inner.ip.len(),
            Cmd::Get(_) => panic!("expected an IP-bearing variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| ip_count(&cmd))
                .map_err(drop)
        };
        "add with a single IP" {
            &["route-server", "add", "192.168.1.1"][..] => Yields(1),
        }

        "add with comma-separated IPs" {
            &["route-server", "add", "192.168.1.1,192.168.1.2,10.0.0.1"][..] => Yields(3),
        }

        "add with no IPs" {
            &["route-server", "add"][..] => Yields(0),
        }

        "remove with no IPs" {
            &["route-server", "remove"][..] => Yields(0),
        }

        "replace with no IPs" {
            &["route-server", "replace"][..] => Yields(0),
        }
    );
}

// A single IP renders back to its canonical string, confirming the positional
// argument is parsed into a real address type rather than a raw string.
#[test]
fn parse_add_single_ip_renders_back() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => args.inner.ip[0].to_string(),
                    _ => panic!("expected Add variant"),
                })
                .map_err(drop)
        };
        "single IP round-trips its string form" {
            &["route-server", "add", "192.168.1.1"][..] => Yields("192.168.1.1".to_string()),
        }
    );
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// This section tests clap ValueEnum translations for the
// source_type argument.

// --source-type maps each accepted ValueEnum string onto its proto integer:
// config_file = 0, admin_api = 1. Yields the parsed source_type as i32.
#[test]
fn add_source_type_maps_to_proto_int() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => args.inner.source_type as i32,
                    _ => panic!("expected Add variant"),
                })
                .map_err(drop)
        };
        "admin_api is 1" {
            &[
                "route-server",
                "add",
                "192.168.1.1",
                "--source-type",
                "admin_api",
            ][..] => Yields(1),
        }

        "config_file is 0" {
            &[
                "route-server",
                "add",
                "192.168.1.1",
                "--source-type",
                "config_file",
            ][..] => Yields(0),
        }
    );
}

// Malformed add invocations are rejected at parse time: an unknown
// --source-type value, and a positional that isn't a valid IP address.
#[test]
fn invalid_add_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "unknown --source-type value" {
            &[
                "route-server",
                "add",
                "192.168.1.1",
                "--source-type",
                "invalid",
            ][..] => Fails,
        }

        "positional is not an IP" {
            &["route-server", "add", "not-an-ip"][..] => Fails,
        }
    );
}
