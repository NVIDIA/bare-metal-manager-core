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

// find parses a valid IP and routes to the Find variant: IPv4 in its various
// ranges (including 0.0.0.0) and IPv6 all parse, and the parsed address
// round-trips to the canonical string the original argv supplied.
#[test]
fn parse_find_accepts_valid_ips() {
    check_cases(
        [
            Case {
                scenario: "standard IPv4 address",
                input: &["ip", "find", "192.168.1.100"][..],
                expect: Yields("192.168.1.100".to_string()),
            },
            Case {
                scenario: "10.x IPv4 address",
                input: &["ip", "find", "10.0.0.1"][..],
                expect: Yields("10.0.0.1".to_string()),
            },
            Case {
                scenario: "172.x IPv4 address",
                input: &["ip", "find", "172.16.0.1"][..],
                expect: Yields("172.16.0.1".to_string()),
            },
            Case {
                scenario: "0.0.0.0 IPv4 address",
                input: &["ip", "find", "0.0.0.0"][..],
                expect: Yields("0.0.0.0".to_string()),
            },
            Case {
                scenario: "IPv6 loopback address",
                input: &["ip", "find", "::1"][..],
                expect: Yields("::1".to_string()),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| {
                    let Cmd::Find(args) = cmd;
                    args.ip.to_string()
                })
                .map_err(drop)
        },
    );
}

// find rejects malformed invocations at parse time: an unparseable IP value
// and a missing required ip argument.
#[test]
fn parse_find_rejects_invalid_invocations() {
    check_cases(
        [
            Case {
                scenario: "value is not a valid IP",
                input: &["ip", "find", "not-an-ip"][..],
                expect: Fails,
            },
            Case {
                scenario: "missing required ip argument",
                input: &["ip", "find"][..],
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
