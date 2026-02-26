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

// parse_create_with_required_args ensures create parses
// with required arguments.
#[test]
fn parse_create_with_required_args() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "create",
        "--id",
        "550e8400-e29b-41d4-a716-446655440000",
        "--url",
        "https://images.example.com/ubuntu.qcow2",
        "--digest",
        "sha256:abc123",
        "--tenant-org-id",
        "tenant-123",
    ])
    .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.id, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(args.url, "https://images.example.com/ubuntu.qcow2");
            assert_eq!(args.digest, "sha256:abc123");
            assert_eq!(args.tenant_org_id, "tenant-123");
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_optional_args ensures create parses
// with optional arguments.
#[test]
fn parse_create_with_optional_args() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "create",
        "-i",
        "550e8400-e29b-41d4-a716-446655440000",
        "-u",
        "https://images.example.com/ubuntu.qcow2",
        "-m",
        "sha256:abc123",
        "-t",
        "tenant-123",
        "-n",
        "Ubuntu 22.04",
        "-d",
        "Ubuntu 22.04 LTS Server",
    ])
    .expect("should parse create with optional args");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.name, Some("Ubuntu 22.04".to_string()));
            assert_eq!(
                args.description,
                Some("Ubuntu 22.04 LTS Server".to_string())
            );
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_alias ensures create has visible alias 'c'.
#[test]
fn parse_create_alias() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "c",
        "-i",
        "550e8400-e29b-41d4-a716-446655440000",
        "-u",
        "https://images.example.com/ubuntu.qcow2",
        "-m",
        "sha256:abc123",
        "-t",
        "tenant-123",
    ])
    .expect("should parse create via alias");

    assert!(matches!(cmd, Cmd::Create(_)));
}

// parse_show_all ensures show parses with no filters.
#[test]
fn parse_show_all() {
    let cmd = Cmd::try_parse_from(["os-image", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(args.tenant_org_id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_filters ensures show parses with id
// and tenant filters.
#[test]
fn parse_show_with_filters() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "show",
        "-i",
        "550e8400-e29b-41d4-a716-446655440000",
        "-t",
        "tenant-123",
    ])
    .expect("should parse show with filters");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(
                args.id,
                Some("550e8400-e29b-41d4-a716-446655440000".to_string())
            );
            assert_eq!(args.tenant_org_id, Some("tenant-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_delete ensures delete parses with required args.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "delete",
        "-i",
        "550e8400-e29b-41d4-a716-446655440000",
        "-t",
        "tenant-123",
    ])
    .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.id, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(args.tenant_org_id, "tenant-123");
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_update ensures update parses with required id.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from([
        "os-image",
        "update",
        "-i",
        "550e8400-e29b-41d4-a716-446655440000",
        "-n",
        "New Name",
    ])
    .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.id, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(args.name, Some("New Name".to_string()));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_create_missing_required_fails ensures create
// fails without required args.
#[test]
fn parse_create_missing_required_fails() {
    let result = Cmd::try_parse_from(["os-image", "create", "-i", "some-id"]);
    assert!(result.is_err(), "should fail without all required args");
}
