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

// parse_get_report_all ensures get-report all parses.
#[test]
fn parse_get_report_all() {
    parse_leaf::<Cmd>(
        &["site-explorer", "get-report", "all"],
        &["get-report", "all"],
    )
    .expect("should parse get-report all");
}

// parse_get_report_managed_host ensures get-report
// managed-host parses.
#[test]
fn parse_get_report_managed_host() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "get-report", "managed-host"],
        &["get-report", "managed-host"],
    )
    .expect("should parse get-report managed-host");

    assert!(raw_value(&matches, "address").is_none());
}

// parse_get_report_endpoint ensures get-report endpoint parses.
#[test]
fn parse_get_report_endpoint() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "get-report", "endpoint"],
        &["get-report", "endpoint"],
    )
    .expect("should parse get-report endpoint");

    assert!(raw_value(&matches, "address").is_none());
    assert!(!matches.get_flag("unpairedonly"));
    assert!(!matches.get_flag("erroronly"));
}

// explore routes to the Explore variant; --mac is optional. Each row yields
// (parsed address, whether a MAC was supplied).
#[test]
fn parse_explore() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["explore"])
                .map(|matches| {
                    (
                        raw_value(&matches, "address").expect("address is required"),
                        raw_value(&matches, "mac").is_some(),
                    )
                })
                .map_err(drop)
        };
        "address only, no mac" {
            &["site-explorer", "explore", "192.168.1.100"][..] => Yields(("192.168.1.100".to_string(), false)),
        }

        "address with mac" {
            &[
                "site-explorer",
                "explore",
                "192.168.1.100",
                "--mac",
                "00:11:22:33:44:55",
            ][..] => Yields(("192.168.1.100".to_string(), true)),
        }
    );
}

// parse_re_explore ensures re-explore parses with address.
#[test]
fn parse_re_explore() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "re-explore", "192.168.1.100"],
        &["re-explore"],
    )
    .expect("should parse re-explore");

    assert_eq!(
        raw_value(&matches, "address").as_deref(),
        Some("192.168.1.100")
    );
}

// parse_clear_error ensures clear-error parses with address.
#[test]
fn parse_clear_error() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "clear-error", "192.168.1.100"],
        &["clear-error"],
    )
    .expect("should parse clear-error");

    assert_eq!(
        raw_value(&matches, "address").as_deref(),
        Some("192.168.1.100")
    );
}

// parse_delete ensures delete parses with address.
#[test]
fn parse_delete() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "delete", "--address", "192.168.1.100"],
        &["delete"],
    )
    .expect("should parse delete");

    assert_eq!(
        raw_value(&matches, "address").as_deref(),
        Some("192.168.1.100")
    );
}

// parse_remediation ensures remediation parses with
// address and options.
#[test]
fn parse_remediation() {
    let matches = parse_leaf::<Cmd>(
        &["site-explorer", "remediation", "192.168.1.100", "--pause"],
        &["remediation"],
    )
    .expect("should parse remediation");

    assert_eq!(
        raw_value(&matches, "address").as_deref(),
        Some("192.168.1.100")
    );
    assert!(matches.get_flag("pause"));
    assert!(!matches.get_flag("resume"));
}

// Malformed invocations are rejected at parse time -- e.g. a subcommand left
// without its required positional address.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "explore without an address" {
            &["site-explorer", "explore"][..] => Fails,
        }
    );
}
