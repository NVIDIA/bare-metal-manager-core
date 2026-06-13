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
use carbide_test_support::{Case, check_cases, scenarios};
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

// `show` accepts every selector slot as optional: bare, by id, and by each
// of --tenant-org-id, --name, and the --label-key/--label-value pair. Each
// row checks whether `id` is present plus the four optional string filters.
#[test]
fn parse_show_routes_and_captures_filters() {
    fn show_fields(
        argv: &[&str],
    ) -> (
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        match Cmd::try_parse_from(argv.iter().copied()).expect("should parse show") {
            Cmd::Show(args) => (
                args.id.is_some(),
                args.tenant_org_id,
                args.name,
                args.label_key,
                args.label_value,
            ),
            _ => panic!("expected Show variant"),
        }
    }

    check_cases(
        [
            Case {
                scenario: "no arguments",
                input: &["vpc", "show"][..],
                expect: Yields((false, None, None, None, None)),
            },
            Case {
                scenario: "with VPC id",
                input: &["vpc", "show", TEST_VPC_ID][..],
                expect: Yields((true, None, None, None, None)),
            },
            Case {
                scenario: "with --tenant-org-id",
                input: &["vpc", "show", "--tenant-org-id", "org-123"][..],
                expect: Yields((false, Some("org-123".to_string()), None, None, None)),
            },
            Case {
                scenario: "with --name",
                input: &["vpc", "show", "--name", "my-vpc"][..],
                expect: Yields((false, None, Some("my-vpc".to_string()), None, None)),
            },
            Case {
                scenario: "with label key and value",
                input: &["vpc", "show", "--label-key", "env", "--label-value", "prod"][..],
                expect: Yields((
                    false,
                    None,
                    None,
                    Some("env".to_string()),
                    Some("prod".to_string()),
                )),
            },
        ],
        |argv| Ok::<_, ()>(show_fields(argv)),
    );
}

// `set-virtualizer` takes a VPC id and a virtualizer name; fnn, etv, and
// etv_nvue all parse to the SetVirtualizer variant carrying the id.
#[test]
fn parse_set_virtualizer_routes_with_id() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied())
            .expect("should parse set-virtualizer")
        {
            Cmd::SetVirtualizer(args) => Ok::<_, ()>(args.id.to_string()),
            _ => panic!("expected SetVirtualizer variant"),
        };
        "fnn virtualizer" {
            &["vpc", "set-virtualizer", TEST_VPC_ID, "fnn"][..] => Yields(TEST_VPC_ID.to_string()),
        }

        "etv virtualizer" {
            &["vpc", "set-virtualizer", TEST_VPC_ID, "etv"][..] => Yields(TEST_VPC_ID.to_string()),
        }

        "etv_nvue virtualizer" {
            &["vpc", "set-virtualizer", TEST_VPC_ID, "etv_nvue"][..] => Yields(TEST_VPC_ID.to_string()),
        }
    );
}

// Malformed `set-virtualizer` invocations are rejected at parse time:
// missing both positional arguments, or an unknown virtualizer name.
#[test]
fn invalid_set_virtualizer_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "missing id and virtualizer" {
            &["vpc", "set-virtualizer"][..] => Fails,
        }

        "invalid virtualizer name" {
            &["vpc", "set-virtualizer", TEST_VPC_ID, "invalid"][..] => Fails,
        }
    );
}
