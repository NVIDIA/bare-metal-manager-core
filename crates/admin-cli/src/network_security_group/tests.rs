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

// parse_create ensures create parses with required
// arguments.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from([
        "network-security-group",
        "create",
        "--tenant-organization-id",
        "tenant-123",
    ])
    .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.tenant_organization_id, "tenant-123");
            assert!(args.id.is_none());
            assert!(args.name.is_none());
            assert!(!args.stateful_egress);
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_options ensures create parses with
// all options.
#[test]
fn parse_create_with_options() {
    let cmd = Cmd::try_parse_from([
        "network-security-group",
        "create",
        "--tenant-organization-id",
        "tenant-123",
        "--id",
        "nsg-123",
        "--name",
        "my-nsg",
        "--description",
        "Test NSG",
        "--stateful-egress",
    ])
    .expect("should parse create with options");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.id, Some("nsg-123".to_string()));
            assert_eq!(args.name, Some("my-nsg".to_string()));
            assert!(args.stateful_egress);
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_show_no_args ensures show parses with no
// arguments (all groups).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["network-security-group", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_id ensures show parses with group ID.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["network-security-group", "show", "nsg-123"])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.id, Some("nsg-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_delete ensures delete parses with required
// arguments.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from([
        "network-security-group",
        "delete",
        "--id",
        "nsg-123",
        "--tenant-organization-id",
        "tenant-123",
    ])
    .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.id, "nsg-123");
            assert_eq!(args.tenant_organization_id, "tenant-123");
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_update ensures update parses with required
// arguments.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from([
        "network-security-group",
        "update",
        "--id",
        "nsg-123",
        "--tenant-organization-id",
        "tenant-123",
    ])
    .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.id, "nsg-123");
            assert_eq!(args.tenant_organization_id, "tenant-123");
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_show_attachments ensures show-attachments
// parses with required ID.
#[test]
fn parse_show_attachments() {
    let cmd = Cmd::try_parse_from([
        "network-security-group",
        "show-attachments",
        "--id",
        "nsg-123",
    ])
    .expect("should parse show-attachments");

    match cmd {
        Cmd::ShowAttachments(args) => {
            assert_eq!(args.id, "nsg-123");
            assert!(!args.include_indirect);
        }
        _ => panic!("expected ShowAttachments variant"),
    }
}

// parse_attach ensures attach parses with NSG ID.
#[test]
fn parse_attach() {
    let cmd = Cmd::try_parse_from(["network-security-group", "attach", "--id", "nsg-123"])
        .expect("should parse attach");

    match cmd {
        Cmd::Attach(args) => {
            assert_eq!(args.id, "nsg-123");
            assert!(args.vpc_id.is_none());
            assert!(args.instance_id.is_none());
        }
        _ => panic!("expected Attach variant"),
    }
}

// parse_detach ensures detach parses with no required args.
#[test]
fn parse_detach() {
    let cmd =
        Cmd::try_parse_from(["network-security-group", "detach"]).expect("should parse detach");

    match cmd {
        Cmd::Detach(args) => {
            assert!(args.vpc_id.is_none());
            assert!(args.instance_id.is_none());
        }
        _ => panic!("expected Detach variant"),
    }
}

// parse_create_missing_required_fails ensures create
// fails without tenant org ID.
#[test]
fn parse_create_missing_required_fails() {
    let result = Cmd::try_parse_from(["network-security-group", "create"]);
    assert!(
        result.is_err(),
        "should fail without --tenant-organization-id"
    );
}
