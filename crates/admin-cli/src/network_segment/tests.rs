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

// show parses with any mix of its optional filters and routes to the Show
// variant; each row yields whether `network` is set plus the parsed
// `tenant_org_id` and `name`.
#[test]
fn parse_show_routes_to_show() {
    check_cases(
        [
            Case {
                scenario: "no arguments (all segments)",
                input: &["network-segment", "show"][..],
                expect: Yields((false, None, None)),
            },
            Case {
                scenario: "with --tenant-org-id",
                input: &["network-segment", "show", "--tenant-org-id", "tenant-123"][..],
                expect: Yields((false, Some("tenant-123".to_string()), None)),
            },
            Case {
                scenario: "with --name",
                input: &["network-segment", "show", "--name", "my-segment"][..],
                expect: Yields((false, None, Some("my-segment".to_string()))),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.network.is_some(), args.tenant_org_id, args.name),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "delete without --id",
            input: &["network-segment", "delete"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
