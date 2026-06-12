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

use super::args::Cmd;

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

// The positional id accepts any identifier format -- machine ID, IP address,
// UUID, or MAC address -- and round-trips it verbatim onto `cmd.id`.
#[test]
fn parse_accepts_any_id_format() {
    check_cases(
        [
            Case {
                scenario: "machine ID",
                input: &["jump", "machine-123"][..],
                expect: Yields("machine-123".to_string()),
            },
            Case {
                scenario: "IP address",
                input: &["jump", "192.168.1.100"][..],
                expect: Yields("192.168.1.100".to_string()),
            },
            Case {
                scenario: "UUID",
                input: &["jump", "550e8400-e29b-41d4-a716-446655440000"][..],
                expect: Yields("550e8400-e29b-41d4-a716-446655440000".to_string()),
            },
            Case {
                scenario: "MAC address",
                input: &["jump", "00:11:22:33:44:55"][..],
                expect: Yields("00:11:22:33:44:55".to_string()),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| cmd.id)
                .map_err(drop)
        },
    );
}

// The positional id is required: an invocation without it is rejected at parse
// time.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "no id argument",
            input: &["jump"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
