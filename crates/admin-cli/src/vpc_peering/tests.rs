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

const TEST_VPC_ID_1: &str = "00000000-0000-0000-0000-000000000001";
const TEST_VPC_ID_2: &str = "00000000-0000-0000-0000-000000000002";
const TEST_PEERING_ID: &str = "00000000-0000-0000-0000-000000000003";

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

// parse_create ensures create parses two positional VPC IDs into the Create
// variant, preserving each id in order.
#[test]
fn parse_create() {
    check_cases(
        [Case {
            scenario: "create with two VPC IDs",
            input: &["vpc-peering", "create", TEST_VPC_ID_1, TEST_VPC_ID_2][..],
            expect: Yields((TEST_VPC_ID_1.to_string(), TEST_VPC_ID_2.to_string())),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (args.vpc1_id.to_string(), args.vpc2_id.to_string()),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_show covers the Show variant's optional selectors: no args, --id alone,
// and --vpc-id alone each parse, yielding which of (id, vpc_id) is set.
#[test]
fn parse_show() {
    check_cases(
        [
            Case {
                scenario: "no arguments",
                input: &["vpc-peering", "show"][..],
                expect: Yields((false, false)),
            },
            Case {
                scenario: "with --id",
                input: &["vpc-peering", "show", "--id", TEST_PEERING_ID][..],
                expect: Yields((true, false)),
            },
            Case {
                scenario: "with --vpc-id",
                input: &["vpc-peering", "show", "--vpc-id", TEST_VPC_ID_1][..],
                expect: Yields((false, true)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.id.is_some(), args.vpc_id.is_some()),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_delete ensures delete parses with --id into the Delete variant,
// preserving the peering id.
#[test]
fn parse_delete() {
    check_cases(
        [Case {
            scenario: "delete with --id",
            input: &["vpc-peering", "delete", "--id", TEST_PEERING_ID][..],
            expect: Yields(TEST_PEERING_ID.to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.id.to_string(),
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- conflicting selectors
// on show, or a required argument left off create/delete.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "show with both --id and --vpc-id",
                input: &[
                    "vpc-peering",
                    "show",
                    "--id",
                    TEST_PEERING_ID,
                    "--vpc-id",
                    TEST_VPC_ID_1,
                ][..],
                expect: Fails,
            },
            Case {
                scenario: "delete without --id",
                input: &["vpc-peering", "delete"][..],
                expect: Fails,
            },
            Case {
                scenario: "create without VPC IDs",
                input: &["vpc-peering", "create"][..],
                expect: Fails,
            },
            Case {
                scenario: "create with only one VPC ID",
                input: &["vpc-peering", "create", TEST_VPC_ID_1][..],
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
