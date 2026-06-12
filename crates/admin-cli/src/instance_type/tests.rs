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
use carbide_test_support::{Case, check_cases};
use clap::{CommandFactory, Parser};

use super::*;

// Define a basic/working MachineId for testing.
const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

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

// The `create` subcommand: every field is optional, so a bare `create` leaves
// id/name/description unset, while supplying them threads each value through.
#[test]
fn parse_create_routes_and_binds_fields() {
    check_cases(
        [
            Case {
                scenario: "create with no arguments leaves every field unset",
                input: &["instance-type", "create"][..],
                expect: Yields((None, None, None)),
            },
            Case {
                scenario: "create with all options binds each field",
                input: &[
                    "instance-type",
                    "create",
                    "--id",
                    "type-123",
                    "--name",
                    "GPU Instance",
                    "--description",
                    "High-performance GPU instance",
                    "--labels",
                    r#"{"gpu":"true"}"#,
                ][..],
                expect: Yields((
                    Some("type-123".to_string()),
                    Some("GPU Instance".to_string()),
                    Some("High-performance GPU instance".to_string()),
                )),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (args.id, args.name, args.description),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        },
    );
}

// The `show` subcommand: `--id` is optional, so a bare `show` lists all types
// while supplying `--id` narrows to one.
#[test]
fn parse_show_routes_and_binds_id() {
    check_cases(
        [
            Case {
                scenario: "show with no arguments leaves id unset",
                input: &["instance-type", "show"][..],
                expect: Yields(None),
            },
            Case {
                scenario: "show with --id binds the id",
                input: &["instance-type", "show", "--id", "type-123"][..],
                expect: Yields(Some("type-123".to_string())),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => args.id,
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// The `delete` subcommand binds its required `--id`.
#[test]
fn parse_delete_binds_id() {
    check_cases(
        [Case {
            scenario: "delete with required --id",
            input: &["instance-type", "delete", "--id", "type-123"][..],
            expect: Yields("type-123".to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => args.id,
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        },
    );
}

// The `update` subcommand binds its required `--id` and any optional fields.
#[test]
fn parse_update_binds_fields() {
    check_cases(
        [Case {
            scenario: "update with required --id and a new name",
            input: &[
                "instance-type",
                "update",
                "--id",
                "type-123",
                "--name",
                "Updated Name",
            ][..],
            expect: Yields(("type-123".to_string(), Some("Updated Name".to_string()))),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Update(args) => (args.id, args.name),
                    _ => panic!("expected Update variant"),
                })
                .map_err(drop)
        },
    );
}

// The `associate` subcommand binds the type id and its machine list, which
// accepts a single machine or a comma-separated set.
#[test]
fn parse_associate_binds_type_and_machines() {
    let two_machines = format!("{TEST_MACHINE_ID},{TEST_MACHINE_ID}");
    check_cases(
        [
            Case {
                scenario: "associate a single machine",
                input: &["instance-type", "associate", "type-123", TEST_MACHINE_ID][..],
                expect: Yields(("type-123".to_string(), 1)),
            },
            Case {
                scenario: "associate comma-separated machines",
                input: &["instance-type", "associate", "type-123", &two_machines][..],
                expect: Yields(("type-123".to_string(), 2)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Associate(args) => (args.instance_type_id, args.machine_ids.len()),
                    _ => panic!("expected Associate variant"),
                })
                .map_err(drop)
        },
    );
}

// The `disassociate` subcommand binds its required machine id.
#[test]
fn parse_disassociate_binds_machine_id() {
    check_cases(
        [Case {
            scenario: "disassociate with a machine id",
            input: &["instance-type", "disassociate", TEST_MACHINE_ID][..],
            expect: Yields(TEST_MACHINE_ID.to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Disassociate(args) => args.machine_id.to_string(),
                    _ => panic!("expected Disassociate variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- here, a subcommand
// whose required `--id` is missing.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "delete without --id",
                input: &["instance-type", "delete"][..],
                expect: Fails,
            },
            Case {
                scenario: "update without --id",
                input: &["instance-type", "update"][..],
                expect: Fails,
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
