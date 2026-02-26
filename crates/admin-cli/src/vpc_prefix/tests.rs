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

// parse_show_no_args ensures show parses with no arguments.
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.prefix_selector.is_none());
            assert!(args.vpc_id.is_none());
            assert!(args.contains.is_none());
            assert!(args.contained_by.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_prefix_selector_id ensures show parses
// with VPC prefix ID.
#[test]
fn parse_show_with_prefix_selector_id() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show", TEST_VPC_PREFIX_ID])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.prefix_selector.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_prefix_selector_cidr ensures show parses
// with IP prefix.
#[test]
fn parse_show_with_prefix_selector_cidr() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show", "10.0.0.0/8"])
        .expect("should parse show with cidr");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.prefix_selector.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_vpc_id ensures show parses with --vpc-id.
#[test]
fn parse_show_with_vpc_id() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show", "--vpc-id", TEST_VPC_ID])
        .expect("should parse show with vpc-id");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.vpc_id.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_contains ensures show parses with --contains.
#[test]
fn parse_show_with_contains() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show", "--contains", "10.0.0.0/24"])
        .expect("should parse show with contains");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.contains.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_contained_by ensures show parses with
// --contained-by.
#[test]
fn parse_show_with_contained_by() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "show", "--contained-by", "10.0.0.0/8"])
        .expect("should parse show with contained-by");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.contained_by.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_contains_and_contained_by_conflict ensures
// show fails with both contains and contained-by.
#[test]
fn parse_show_contains_and_contained_by_conflict() {
    let result = Cmd::try_parse_from([
        "vpc-prefix",
        "show",
        "--contains",
        "10.0.0.0/24",
        "--contained-by",
        "10.0.0.0/8",
    ]);
    assert!(
        result.is_err(),
        "should fail with both --contains and --contained-by"
    );
}

// parse_create ensures create parses with required args.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from([
        "vpc-prefix",
        "create",
        "--vpc-id",
        TEST_VPC_ID,
        "--prefix",
        "10.0.0.0/8",
        "--name",
        "test-prefix",
    ])
    .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.vpc_id.to_string(), TEST_VPC_ID);
            assert_eq!(args.prefix.to_string(), "10.0.0.0/8");
            assert_eq!(args.name, "test-prefix");
            assert!(args.vpc_prefix_id.is_none());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_vpc_prefix_id ensures create parses
// with optional --vpc-prefix-id.
#[test]
fn parse_create_with_vpc_prefix_id() {
    let cmd = Cmd::try_parse_from([
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
    ])
    .expect("should parse create with vpc-prefix-id");

    match cmd {
        Cmd::Create(args) => {
            assert!(args.vpc_prefix_id.is_some());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_delete ensures delete parses with VPC prefix ID.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["vpc-prefix", "delete", TEST_VPC_PREFIX_ID])
        .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.vpc_prefix_id.to_string(), TEST_VPC_PREFIX_ID);
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_create_missing_vpc_id_fails ensures create fails
// without --vpc-id.
#[test]
fn parse_create_missing_vpc_id_fails() {
    let result = Cmd::try_parse_from([
        "vpc-prefix",
        "create",
        "--prefix",
        "10.0.0.0/8",
        "--name",
        "test",
    ]);
    assert!(result.is_err(), "should fail without --vpc-id");
}

// parse_delete_missing_id_fails ensures delete fails without ID.
#[test]
fn parse_delete_missing_id_fails() {
    let result = Cmd::try_parse_from(["vpc-prefix", "delete"]);
    assert!(result.is_err(), "should fail without vpc-prefix-id");
}
