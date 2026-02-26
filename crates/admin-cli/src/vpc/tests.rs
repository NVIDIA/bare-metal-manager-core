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
    let cmd = Cmd::try_parse_from(["vpc", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(args.tenant_org_id.is_none());
            assert!(args.name.is_none());
            assert!(args.label_key.is_none());
            assert!(args.label_value.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_id ensures show parses with VPC ID.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["vpc", "show", TEST_VPC_ID]).expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_tenant_org_id ensures show parses with
// --tenant-org-id.
#[test]
fn parse_show_with_tenant_org_id() {
    let cmd = Cmd::try_parse_from(["vpc", "show", "--tenant-org-id", "org-123"])
        .expect("should parse show with tenant-org-id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.tenant_org_id, Some("org-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_name ensures show parses with --name.
#[test]
fn parse_show_with_name() {
    let cmd = Cmd::try_parse_from(["vpc", "show", "--name", "my-vpc"])
        .expect("should parse show with name");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.name, Some("my-vpc".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_label ensures show parses with label
// key and value.
#[test]
fn parse_show_with_label() {
    let cmd = Cmd::try_parse_from(["vpc", "show", "--label-key", "env", "--label-value", "prod"])
        .expect("should parse show with labels");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.label_key, Some("env".to_string()));
            assert_eq!(args.label_value, Some("prod".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_set_virtualizer ensures set-virtualizer parses
// with id and virtualizer.
#[test]
fn parse_set_virtualizer() {
    let cmd = Cmd::try_parse_from(["vpc", "set-virtualizer", TEST_VPC_ID, "fnn"])
        .expect("should parse set-virtualizer");

    match cmd {
        Cmd::SetVirtualizer(args) => {
            assert_eq!(args.id.to_string(), TEST_VPC_ID);
        }
        _ => panic!("expected SetVirtualizer variant"),
    }
}

// parse_set_virtualizer_etv ensures set-virtualizer parses with etv.
#[test]
fn parse_set_virtualizer_etv() {
    let cmd = Cmd::try_parse_from(["vpc", "set-virtualizer", TEST_VPC_ID, "etv"])
        .expect("should parse set-virtualizer etv");

    assert!(matches!(cmd, Cmd::SetVirtualizer(_)));
}

// parse_set_virtualizer_etv_nvue ensures set-virtualizer parses with etv_nvue.
#[test]
fn parse_set_virtualizer_etv_nvue() {
    let cmd = Cmd::try_parse_from(["vpc", "set-virtualizer", TEST_VPC_ID, "etv_nvue"])
        .expect("should parse set-virtualizer etv_nvue");

    assert!(matches!(cmd, Cmd::SetVirtualizer(_)));
}

// parse_set_virtualizer_missing_args_fails ensures
// set-virtualizer fails without args.
#[test]
fn parse_set_virtualizer_missing_args_fails() {
    let result = Cmd::try_parse_from(["vpc", "set-virtualizer"]);
    assert!(result.is_err(), "should fail without id and virtualizer");
}

// parse_set_virtualizer_invalid_virtualizer_fails ensures
// set-virtualizer fails with invalid virtualizer.
#[test]
fn parse_set_virtualizer_invalid_virtualizer_fails() {
    let result = Cmd::try_parse_from(["vpc", "set-virtualizer", TEST_VPC_ID, "invalid"]);
    assert!(result.is_err(), "should fail with invalid virtualizer");
}
