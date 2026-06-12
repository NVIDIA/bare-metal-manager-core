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

// Every malformed invocation is rejected at parse time -- log-filter without
// its required --filter, and the toggle subcommands left without an
// --enable/--disable choice.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "log-filter without --filter",
                input: &["set", "log-filter"][..],
                expect: Fails,
            },
            Case {
                scenario: "create-machines without --enable/--disable",
                input: &["set", "create-machines"][..],
                expect: Fails,
            },
            Case {
                scenario: "site-explorer without --enable/--disable",
                input: &["set", "site-explorer"][..],
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

// log-filter parses its required --filter and an optional --expiry that
// defaults to "1h"; the yielded tuple is (filter, expiry).
#[test]
fn parse_log_filter_routes_to_variant() {
    check_cases(
        [
            Case {
                scenario: "filter only, expiry defaults",
                input: &["set", "log-filter", "--filter", "debug"][..],
                expect: Yields(("debug".to_string(), "1h".to_string())),
            },
            Case {
                scenario: "filter with custom expiry",
                input: &[
                    "set",
                    "log-filter",
                    "--filter",
                    "trace",
                    "--expiry",
                    "30min",
                ][..],
                expect: Yields(("trace".to_string(), "30min".to_string())),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::LogFilter(args) => (args.filter, args.expiry),
                    _ => panic!("expected LogFilter variant"),
                })
                .map_err(drop)
        },
    );
}

// create-machines routes to the CreateMachines variant; --enable yields
// is_enabled() == true, --disable yields false.
#[test]
fn parse_create_machines_toggle() {
    check_cases(
        [
            Case {
                scenario: "--enable",
                input: &["set", "create-machines", "--enable"][..],
                expect: Yields(true),
            },
            Case {
                scenario: "--disable",
                input: &["set", "create-machines", "--disable"][..],
                expect: Yields(false),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::CreateMachines(args) => args.is_enabled(),
                    _ => panic!("expected CreateMachines variant"),
                })
                .map_err(drop)
        },
    );
}

// site-explorer routes to the SiteExplorer variant; --enable yields
// is_enabled() == true, --disable yields false.
#[test]
fn parse_site_explorer_toggle() {
    check_cases(
        [
            Case {
                scenario: "--enable",
                input: &["set", "site-explorer", "--enable"][..],
                expect: Yields(true),
            },
            Case {
                scenario: "--disable",
                input: &["set", "site-explorer", "--disable"][..],
                expect: Yields(false),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::SiteExplorer(args) => args.is_enabled(),
                    _ => panic!("expected SiteExplorer variant"),
                })
                .map_err(drop)
        },
    );
}

// bmc-proxy parses --enabled and --proxy; the yielded tuple is
// (enabled, proxy).
#[test]
fn parse_bmc_proxy_routes_to_variant() {
    check_cases(
        [Case {
            scenario: "enabled with a proxy address",
            input: &[
                "set",
                "bmc-proxy",
                "--enabled",
                "true",
                "--proxy",
                "proxy.example.com:8080",
            ][..],
            expect: Yields((true, Some("proxy.example.com:8080".to_string()))),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::BmcProxy(args) => (args.enabled, args.proxy),
                    _ => panic!("expected BmcProxy variant"),
                })
                .map_err(drop)
        },
    );
}

// tracing-enabled routes to the TracingEnabled variant; "true" yields
// value == true, "false" yields false.
#[test]
fn parse_tracing_enabled_value() {
    check_cases(
        [
            Case {
                scenario: "true",
                input: &["set", "tracing-enabled", "true"][..],
                expect: Yields(true),
            },
            Case {
                scenario: "false",
                input: &["set", "tracing-enabled", "false"][..],
                expect: Yields(false),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::TracingEnabled(args) => args.value,
                    _ => panic!("expected TracingEnabled variant"),
                })
                .map_err(drop)
        },
    );
}
