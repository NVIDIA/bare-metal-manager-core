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
use carbide_uuid::machine::MachineId;
use clap::{CommandFactory, Parser};

use super::*;
use crate::test_support::{parse_leaf, raw_value, raw_values};

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
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["create"])
                .map(|matches| {
                    (
                        raw_value(&matches, "id"),
                        raw_value(&matches, "name"),
                        raw_value(&matches, "description"),
                    )
                })
                .map_err(drop)
        };
        "create with no arguments leaves every field unset" {
            &["instance-type", "create"][..] => Yields((None, None, None)),
        }

        "create with all options binds each field" {
            &[
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
            ][..] => Yields((
                Some("type-123".to_string()),
                Some("GPU Instance".to_string()),
                Some("High-performance GPU instance".to_string()),
            )),
        }
    );
}

// The `show` subcommand: `--id` is optional, so a bare `show` lists all types
// while supplying `--id` narrows to one.
#[test]
fn parse_show_routes_and_binds_id() {
    scenarios!(
        run = |argv| parse_leaf::<Cmd>(argv, &["show"])
            .map(|matches| raw_value(&matches, "id"))
            .map_err(drop);
        "show with no arguments leaves id unset" {
            &["instance-type", "show"][..] => Yields(None),
        }

        "show with --id binds the id" {
            &["instance-type", "show", "--id", "type-123"][..] => Yields(Some("type-123".to_string())),
        }
    );
}

// The `delete` subcommand binds its required `--id`.
#[test]
fn parse_delete_binds_id() {
    scenarios!(
        run = |argv| parse_leaf::<Cmd>(argv, &["delete"])
            .map(|matches| {
                raw_value(&matches, "id").expect("ID is required")
            })
            .map_err(drop);
        "delete with required --id" {
            &["instance-type", "delete", "--id", "type-123"][..] => Yields("type-123".to_string()),
        }
    );
}

// The `update` subcommand binds its required `--id` and any optional fields.
#[test]
fn parse_update_binds_fields() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["update"])
                .map(|matches| {
                    (
                        raw_value(&matches, "id").expect("ID is required"),
                        raw_value(&matches, "name"),
                    )
                })
                .map_err(drop)
        };
        "update with required --id and a new name" {
            &[
                "instance-type",
                "update",
                "--id",
                "type-123",
                "--name",
                "Updated Name",
            ][..] => Yields(("type-123".to_string(), Some("Updated Name".to_string()))),
        }
    );
}

// The `associate` subcommand binds the type id and its machine list, which
// accepts a single machine or a comma-separated set.
#[test]
fn parse_associate_binds_type_and_machines() {
    let two_machines = format!("{TEST_MACHINE_ID},{TEST_MACHINE_ID}");
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["associate"])
                .map(|matches| {
                    (
                        raw_value(&matches, "instance_type_id")
                            .expect("instance type ID is required"),
                        raw_values(&matches, "machine_ids").len(),
                    )
                })
                .map_err(drop)
        };
        "associate a single machine" {
            &["instance-type", "associate", "type-123", TEST_MACHINE_ID][..] => Yields(("type-123".to_string(), 1)),
        }

        "associate comma-separated machines" {
            &["instance-type", "associate", "type-123", &two_machines][..] => Yields(("type-123".to_string(), 2)),
        }
    );
}

// The `disassociate` subcommand binds its required machine id.
#[test]
fn parse_disassociate_binds_machine_id() {
    scenarios!(
        run = |argv| parse_leaf::<Cmd>(argv, &["disassociate"])
            .map(|matches| {
                matches
                    .get_one::<MachineId>("machine_id")
                    .expect("machine ID is required")
                    .to_string()
            })
            .map_err(drop);
        "disassociate with a machine id" {
            &["instance-type", "disassociate", TEST_MACHINE_ID][..] => Yields(TEST_MACHINE_ID.to_string()),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, a subcommand
// whose required `--id` is missing.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "delete without --id" {
            &["instance-type", "delete"][..] => Fails,
        }

        "update without --id" {
            &["instance-type", "update"][..] => Fails,
        }
    );
}
