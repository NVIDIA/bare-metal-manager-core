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

// create parses with its required args (long flags) and with its optional
// args (short flags + alias `c`); each row routes to the Create variant and
// the parsed fields match what was supplied.
#[test]
fn parse_create_routes_to_create() {
    fn create_fields(
        cmd: Cmd,
    ) -> (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    ) {
        match cmd {
            Cmd::Create(args) => (
                args.id,
                args.url,
                args.digest,
                args.tenant_org_id,
                args.name,
                args.description,
            ),
            _ => panic!("expected Create variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(create_fields)
                .map_err(drop)
        };
        "create with required args (long flags)" {
            &[
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
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "https://images.example.com/ubuntu.qcow2".to_string(),
                "sha256:abc123".to_string(),
                "tenant-123".to_string(),
                None,
                None,
            )),
        }

        "create with optional args (short flags)" {
            &[
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
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "https://images.example.com/ubuntu.qcow2".to_string(),
                "sha256:abc123".to_string(),
                "tenant-123".to_string(),
                Some("Ubuntu 22.04".to_string()),
                Some("Ubuntu 22.04 LTS Server".to_string()),
            )),
        }

        "create via visible alias 'c'" {
            &[
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
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "https://images.example.com/ubuntu.qcow2".to_string(),
                "sha256:abc123".to_string(),
                "tenant-123".to_string(),
                None,
                None,
            )),
        }
    );
}

// show parses with no filters (all images) and with id + tenant filters; each
// row routes to the Show variant and yields its optional filter fields.
#[test]
fn parse_show_routes_to_show() {
    fn show_fields(cmd: Cmd) -> (Option<String>, Option<String>) {
        match cmd {
            Cmd::Show(args) => (args.id, args.tenant_org_id),
            _ => panic!("expected Show variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(show_fields)
                .map_err(drop)
        };
        "show with no filters" {
            &["os-image", "show"][..] => Yields((None, None)),
        }

        "show with id and tenant filters" {
            &[
                "os-image",
                "show",
                "-i",
                "550e8400-e29b-41d4-a716-446655440000",
                "-t",
                "tenant-123",
            ][..] => Yields((
                Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                Some("tenant-123".to_string()),
            )),
        }
    );
}

// delete parses with its required id + tenant args, routing to the Delete
// variant and yielding those fields.
#[test]
fn parse_delete_routes_to_delete() {
    fn delete_fields(cmd: Cmd) -> (String, String) {
        match cmd {
            Cmd::Delete(args) => (args.id, args.tenant_org_id),
            _ => panic!("expected Delete variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(delete_fields)
                .map_err(drop)
        };
        "delete with required args" {
            &[
                "os-image",
                "delete",
                "-i",
                "550e8400-e29b-41d4-a716-446655440000",
                "-t",
                "tenant-123",
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "tenant-123".to_string(),
            )),
        }
    );
}

// update parses with its required id (plus an optional name), routing to the
// Update variant and yielding those fields.
#[test]
fn parse_update_routes_to_update() {
    fn update_fields(cmd: Cmd) -> (String, Option<String>) {
        match cmd {
            Cmd::Update(args) => (args.id, args.name),
            _ => panic!("expected Update variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(update_fields)
                .map_err(drop)
        };
        "update with required id and a name" {
            &[
                "os-image",
                "update",
                "-i",
                "550e8400-e29b-41d4-a716-446655440000",
                "-n",
                "New Name",
            ][..] => Yields((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                Some("New Name".to_string()),
            )),
        }
    );
}

// Malformed invocations are rejected at parse time -- e.g. create without all
// of its required arguments.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create missing required args" {
            &["os-image", "create", "-i", "some-id"][..] => Fails,
        }
    );
}
