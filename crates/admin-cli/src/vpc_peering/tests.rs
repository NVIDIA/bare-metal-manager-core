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

// parse_create ensures create parses with two VPC IDs.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from(["vpc-peering", "create", TEST_VPC_ID_1, TEST_VPC_ID_2])
        .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.vpc1_id.to_string(), TEST_VPC_ID_1);
            assert_eq!(args.vpc2_id.to_string(), TEST_VPC_ID_2);
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_show_no_args ensures show parses with no arguments.
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["vpc-peering", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(args.vpc_id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_id ensures show parses with --id.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["vpc-peering", "show", "--id", TEST_PEERING_ID])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_some());
            assert!(args.vpc_id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_vpc_id ensures show parses with --vpc-id.
#[test]
fn parse_show_with_vpc_id() {
    let cmd = Cmd::try_parse_from(["vpc-peering", "show", "--vpc-id", TEST_VPC_ID_1])
        .expect("should parse show with vpc-id");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(args.vpc_id.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_id_and_vpc_id_conflict ensures show fails
// with both --id and --vpc-id.
#[test]
fn parse_show_id_and_vpc_id_conflict() {
    let result = Cmd::try_parse_from([
        "vpc-peering",
        "show",
        "--id",
        TEST_PEERING_ID,
        "--vpc-id",
        TEST_VPC_ID_1,
    ]);
    assert!(result.is_err(), "should fail with both --id and --vpc-id");
}

// parse_delete ensures delete parses with --id.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["vpc-peering", "delete", "--id", TEST_PEERING_ID])
        .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.id.to_string(), TEST_PEERING_ID);
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_delete_missing_id_fails ensures delete fails without --id.
#[test]
fn parse_delete_missing_id_fails() {
    let result = Cmd::try_parse_from(["vpc-peering", "delete"]);
    assert!(result.is_err(), "should fail without --id");
}

// parse_create_missing_vpc_ids_fails ensures create fails
// without VPC IDs.
#[test]
fn parse_create_missing_vpc_ids_fails() {
    let result = Cmd::try_parse_from(["vpc-peering", "create"]);
    assert!(result.is_err(), "should fail without VPC IDs");
}

// parse_create_missing_second_vpc_id_fails ensures create
// fails with only one VPC ID.
#[test]
fn parse_create_missing_second_vpc_id_fails() {
    let result = Cmd::try_parse_from(["vpc-peering", "create", TEST_VPC_ID_1]);
    assert!(result.is_err(), "should fail with only one VPC ID");
}
