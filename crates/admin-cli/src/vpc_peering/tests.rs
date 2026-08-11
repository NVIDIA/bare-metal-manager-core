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
use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_peering::VpcPeeringId;
use clap::{CommandFactory, Parser};

use super::*;
use crate::test_support::parse_leaf;

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
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["create"])
                .map(|matches| {
                    (
                        matches
                            .get_one::<VpcId>("vpc1_id")
                            .copied()
                            .expect("first VPC ID is required"),
                        matches
                            .get_one::<VpcId>("vpc2_id")
                            .copied()
                            .expect("second VPC ID is required"),
                    )
                })
                .map_err(drop)
        };
        "create with two VPC IDs" {
            &["vpc-peering", "create", TEST_VPC_ID_1, TEST_VPC_ID_2][..] => Yields((TEST_VPC_ID_1.parse::<VpcId>().unwrap(), TEST_VPC_ID_2.parse::<VpcId>().unwrap())),
        }
    );
}

// parse_show covers the Show variant's optional selectors: no args, --id alone,
// and --vpc-id alone each parse, yielding which of (id, vpc_id) is set.
#[test]
fn parse_show() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["show"])
                .map(|matches| {
                    (
                        matches.get_one::<VpcPeeringId>("id").is_some(),
                        matches.get_one::<VpcId>("vpc_id").is_some(),
                    )
                })
                .map_err(drop)
        };
        "no arguments" {
            &["vpc-peering", "show"][..] => Yields((false, false)),
        }

        "with --id" {
            &["vpc-peering", "show", "--id", TEST_PEERING_ID][..] => Yields((true, false)),
        }

        "with --vpc-id" {
            &["vpc-peering", "show", "--vpc-id", TEST_VPC_ID_1][..] => Yields((false, true)),
        }
    );
}

// parse_delete ensures delete parses with --id into the Delete variant,
// preserving the peering id.
#[test]
fn parse_delete() {
    scenarios!(
        run = |argv| parse_leaf::<Cmd>(argv, &["delete"])
            .map(|matches| {
                matches
                    .get_one::<VpcPeeringId>("id")
                    .copied()
                    .expect("peering ID is required")
            })
            .map_err(drop);
        "delete with --id" {
            &["vpc-peering", "delete", "--id", TEST_PEERING_ID][..] => Yields(TEST_PEERING_ID.parse::<VpcPeeringId>().unwrap()),
        }
    );
}

// Every malformed invocation is rejected at parse time -- conflicting selectors
// on show, or a required argument left off create/delete.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "show with both --id and --vpc-id" {
            &[
                "vpc-peering",
                "show",
                "--id",
                TEST_PEERING_ID,
                "--vpc-id",
                TEST_VPC_ID_1,
            ][..] => Fails,
        }

        "delete without --id" {
            &["vpc-peering", "delete"][..] => Fails,
        }

        "create without VPC IDs" {
            &["vpc-peering", "create"][..] => Fails,
        }

        "create with only one VPC ID" {
            &["vpc-peering", "create", TEST_VPC_ID_1][..] => Fails,
        }
    );
}
