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
use crate::test_support::{parse_leaf, raw_value};

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
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "log-filter without --filter" {
            &["set", "log-filter"][..] => Fails,
        }

        "create-machines without --enable/--disable" {
            &["set", "create-machines"][..] => Fails,
        }

        "site-explorer without --enable/--disable" {
            &["set", "site-explorer"][..] => Fails,
        }
    );
}

// log-filter parses its required --filter and an optional --expiry that
// defaults to "1h"; the yielded tuple is (filter, expiry).
#[test]
fn parse_log_filter_routes_to_variant() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["log-filter"])
                .map(|matches| {
                    (
                        raw_value(&matches, "filter").expect("filter is required"),
                        raw_value(&matches, "expiry").expect("expiry has a default"),
                    )
                })
                .map_err(drop)
        };
        "filter only, expiry defaults" {
            &["set", "log-filter", "--filter", "debug"][..] => Yields(("debug".to_string(), "1h".to_string())),
        }

        "filter with custom expiry" {
            &[
                "set",
                "log-filter",
                "--filter",
                "trace",
                "--expiry",
                "30min",
            ][..] => Yields(("trace".to_string(), "30min".to_string())),
        }
    );
}

// create-machines routes to the CreateMachines variant; --enable yields true
// and --disable yields false.
#[test]
fn parse_create_machines_toggle() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["create-machines"])
                .map(|matches| matches.get_flag("enable"))
                .map_err(drop)
        };
        "--enable" {
            &["set", "create-machines", "--enable"][..] => Yields(true),
        }

        "--disable" {
            &["set", "create-machines", "--disable"][..] => Yields(false),
        }
    );
}

// site-explorer routes to the SiteExplorer variant; --enable yields true and
// --disable yields false.
#[test]
fn parse_site_explorer_toggle() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["site-explorer"])
                .map(|matches| matches.get_flag("enable"))
                .map_err(drop)
        };
        "--enable" {
            &["set", "site-explorer", "--enable"][..] => Yields(true),
        }

        "--disable" {
            &["set", "site-explorer", "--disable"][..] => Yields(false),
        }
    );
}

// bmc-proxy parses --enabled and --proxy; the yielded tuple is
// (enabled, proxy).
#[test]
fn parse_bmc_proxy_routes_to_variant() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["bmc-proxy"])
                .map(|matches| {
                    (
                        *matches
                            .get_one::<bool>("enabled")
                            .expect("enabled is required"),
                        raw_value(&matches, "proxy"),
                    )
                })
                .map_err(drop)
        };
        "enabled with a proxy address" {
            &[
                "set",
                "bmc-proxy",
                "--enabled",
                "true",
                "--proxy",
                "proxy.example.com:8080",
            ][..] => Yields((true, Some("proxy.example.com:8080".to_string()))),
        }
    );
}

// tracing-enabled routes to the TracingEnabled variant; "true" yields
// value == true, "false" yields false.
#[test]
fn parse_tracing_enabled_value() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["tracing-enabled"])
                .map(|matches| {
                    *matches
                        .get_one::<bool>("value")
                        .expect("value is required")
                })
                .map_err(drop)
        };
        "true" {
            &["set", "tracing-enabled", "true"][..] => Yields(true),
        }

        "false" {
            &["set", "tracing-enabled", "false"][..] => Yields(false),
        }
    );
}
