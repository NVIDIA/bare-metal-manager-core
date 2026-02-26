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

// parse_show_no_args ensures show parses with no
// arguments (all partitions).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["nvl-partition", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_empty());
            assert!(args.tenant_org_id.is_none());
            assert!(args.name.is_none());
        }
    }
}

// parse_show_with_tenant ensures show parses with
// --tenant-org-id.
#[test]
fn parse_show_with_tenant() {
    let cmd = Cmd::try_parse_from(["nvl-partition", "show", "--tenant-org-id", "tenant-123"])
        .expect("should parse show with tenant");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.tenant_org_id, Some("tenant-123".to_string()));
        }
    }
}

// parse_show_with_name ensures show parses with --name.
#[test]
fn parse_show_with_name() {
    let cmd = Cmd::try_parse_from(["nvl-partition", "show", "--name", "my-partition"])
        .expect("should parse show with name");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.name, Some("my-partition".to_string()));
        }
    }
}

// parse_show_with_id ensures show parses with positional ID.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["nvl-partition", "show", "partition-123"])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.id, "partition-123");
        }
    }
}
