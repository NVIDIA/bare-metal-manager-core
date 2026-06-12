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

const TEST_VPC_ID: &str = "00000000-0000-0000-0000-000000000001";
const TEST_VPC_PREFIX_ID: &str = "00000000-0000-0000-0000-000000000002";

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

// parse_show routes every valid `show` invocation to the Show variant and
// reports which selectors/filters landed: a tuple of (prefix_selector?,
// vpc_id?, contains?, contained_by?, deleted-discriminant) so each original
// presence/enum assertion survives as a row.
#[test]
fn parse_show_routes_to_show_variant() {
    fn deleted_str(d: &rpc::forge::DeletedFilter) -> &'static str {
        match d {
            rpc::forge::DeletedFilter::Exclude => "exclude",
            rpc::forge::DeletedFilter::Only => "only",
            _ => "other",
        }
    }

    check_cases(
        [
            Case {
                scenario: "show with no arguments",
                input: &["vpc-prefix", "show"][..],
                expect: Yields((false, false, false, false, "exclude")),
            },
            Case {
                scenario: "show with --deleted only",
                input: &["vpc-prefix", "show", "--deleted", "only"][..],
                expect: Yields((false, false, false, false, "only")),
            },
            Case {
                scenario: "show with a prefix-selector id",
                input: &["vpc-prefix", "show", TEST_VPC_PREFIX_ID][..],
                expect: Yields((true, false, false, false, "exclude")),
            },
            Case {
                scenario: "show with a prefix-selector cidr",
                input: &["vpc-prefix", "show", "10.0.0.0/8"][..],
                expect: Yields((true, false, false, false, "exclude")),
            },
            Case {
                scenario: "show with --vpc-id",
                input: &["vpc-prefix", "show", "--vpc-id", TEST_VPC_ID][..],
                expect: Yields((false, true, false, false, "exclude")),
            },
            Case {
                scenario: "show with --contains",
                input: &["vpc-prefix", "show", "--contains", "10.0.0.0/24"][..],
                expect: Yields((false, false, true, false, "exclude")),
            },
            Case {
                scenario: "show with --contained-by",
                input: &["vpc-prefix", "show", "--contained-by", "10.0.0.0/8"][..],
                expect: Yields((false, false, false, true, "exclude")),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (
                        args.prefix_selector.is_some(),
                        args.vpc_id.is_some(),
                        args.contains.is_some(),
                        args.contained_by.is_some(),
                        deleted_str(&args.deleted),
                    ),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_create routes every valid `create` invocation to the Create variant,
// reporting (vpc_id, prefix, name, vpc_prefix_id?) so the required-field and
// optional-id assertions each become a row.
#[test]
fn parse_create_routes_to_create_variant() {
    check_cases(
        [
            Case {
                scenario: "create with required args",
                input: &[
                    "vpc-prefix",
                    "create",
                    "--vpc-id",
                    TEST_VPC_ID,
                    "--prefix",
                    "10.0.0.0/8",
                    "--name",
                    "test-prefix",
                ][..],
                expect: Yields((
                    TEST_VPC_ID.to_string(),
                    "10.0.0.0/8".to_string(),
                    "test-prefix".to_string(),
                    false,
                )),
            },
            Case {
                scenario: "create with optional --vpc-prefix-id",
                input: &[
                    "vpc-prefix",
                    "create",
                    "--vpc-id",
                    TEST_VPC_ID,
                    "--prefix",
                    "10.0.0.0/8",
                    "--name",
                    "test-prefix",
                    "--vpc-prefix-id",
                    TEST_VPC_PREFIX_ID,
                ][..],
                expect: Yields((
                    TEST_VPC_ID.to_string(),
                    "10.0.0.0/8".to_string(),
                    "test-prefix".to_string(),
                    true,
                )),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (
                        args.vpc_id.to_string(),
                        args.prefix.to_string(),
                        args.name,
                        args.vpc_prefix_id.is_some(),
                    ),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_delete routes a valid `delete` invocation to the Delete variant,
// reporting the parsed vpc_prefix_id.
#[test]
fn parse_delete_routes_to_delete_variant() {
    check_cases(
        [Case {
            scenario: "delete with a vpc-prefix-id",
            input: &["vpc-prefix", "delete", TEST_VPC_PREFIX_ID][..],
            expect: Yields(TEST_VPC_PREFIX_ID.to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.vpc_prefix_id.to_string(),
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- mutually exclusive
// filters, a missing required argument, or a subcommand left without its
// positional id.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "show with both --contains and --contained-by",
                input: &[
                    "vpc-prefix",
                    "show",
                    "--contains",
                    "10.0.0.0/24",
                    "--contained-by",
                    "10.0.0.0/8",
                ][..],
                expect: Fails,
            },
            Case {
                scenario: "create without --vpc-id",
                input: &[
                    "vpc-prefix",
                    "create",
                    "--prefix",
                    "10.0.0.0/8",
                    "--name",
                    "test",
                ][..],
                expect: Fails,
            },
            Case {
                scenario: "delete without a vpc-prefix-id",
                input: &["vpc-prefix", "delete"][..],
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
