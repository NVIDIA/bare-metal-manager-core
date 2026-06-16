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

// create routes to the Create variant. A bare invocation leaves the optional
// fields unset; supplying every flag fills them in. Each row yields the parsed
// (script_filename, retries, meta_name, meta_description, has_labels).
#[test]
fn parse_create_routes_and_fills_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (
                        args.script_filename,
                        args.retries,
                        args.meta_name,
                        args.meta_description,
                        args.labels.is_some(),
                    ),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        };
        "required script-filename only" {
            &[
                "dpu-remediation",
                "create",
                "--script-filename",
                "/path/to/script.sh",
            ][..] => Yields(("/path/to/script.sh".to_string(), None, None, None, false)),
        }

        "all options supplied" {
            &[
                "dpu-remediation",
                "create",
                "--script-filename",
                "/path/to/script.sh",
                "--retries",
                "3",
                "--meta-name",
                "My Remediation",
                "--meta-description",
                "Fixes a bug",
                "--label",
                "env:prod",
            ][..] => Yields((
                "/path/to/script.sh".to_string(),
                Some(3),
                Some("My Remediation".to_string()),
                Some("Fixes a bug".to_string()),
                true,
            )),
        }
    );
}

// show routes to the Show variant. Each row yields (id_present, display_script):
// a bare invocation leaves the id unset and the flag off, and --display-script
// turns the flag on.
#[test]
fn parse_show_routes_and_fills_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.id.is_some(), args.display_script),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "no arguments" {
            &["dpu-remediation", "show"][..] => Yields((false, false)),
        }

        "with --display-script" {
            &["dpu-remediation", "show", "--display-script"][..] => Yields((false, true)),
        }
    );
}

// list-applied routes to the ListApplied variant. A bare invocation leaves both
// optional filters unset; the row yields (remediation_id_present, machine_id_present).
#[test]
fn parse_list_applied_routes_and_fills_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::ListApplied(args) => {
                        (args.remediation_id.is_some(), args.machine_id.is_some())
                    }
                    _ => panic!("expected ListApplied variant"),
                })
                .map_err(drop)
        };
        "no arguments" {
            &["dpu-remediation", "list-applied"][..] => Yields((false, false)),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, create without
// its required --script-filename.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create without --script-filename" {
            &["dpu-remediation", "create"][..] => Fails,
        }
    );
}
