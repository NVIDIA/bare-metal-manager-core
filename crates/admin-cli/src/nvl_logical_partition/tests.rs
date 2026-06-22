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

// show parses with or without a --name filter; with no args it
// targets all partitions (empty id list, no name), and --name
// threads the filter through.
#[test]
fn parse_show() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.id.is_empty(), args.name),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "no arguments targets all partitions" {
            &["nvl-logical-partition", "show"][..] => Yields((true, None)),
        }

        "with a --name filter" {
            &["nvl-logical-partition", "show", "--name", "my-partition"][..] => Yields((true, Some("my-partition".to_string()))),
        }
    );
}

// create parses with its required --name and --tenant-organization-id,
// threading both through to the Create variant.
#[test]
fn parse_create() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (args.name, args.tenant_organization_id),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        };
        "create with required arguments" {
            &[
                "nvl-logical-partition",
                "create",
                "--name",
                "my-partition",
                "--tenant-organization-id",
                "tenant-123",
            ][..] => Yields(("my-partition".to_string(), "tenant-123".to_string())),
        }
    );
}

// delete parses with its required --name, routing to the Delete variant.
#[test]
fn parse_delete() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.name,
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        };
        "delete with required --name" {
            &["nvl-logical-partition", "delete", "--name", "my-partition"][..] => Yields("my-partition".to_string()),
        }
    );
}

// Every malformed invocation is rejected at parse time -- create
// without its required --name/--tenant-organization-id, and delete
// without its required --name.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create without --name and --tenant-organization-id" {
            &["nvl-logical-partition", "create"][..] => Fails,
        }

        "delete without --name" {
            &["nvl-logical-partition", "delete"][..] => Fails,
        }
    );
}
