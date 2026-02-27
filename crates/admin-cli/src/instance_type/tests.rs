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

// parse_create ensures create parses with no required
// arguments.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from(["instance-type", "create"]).expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert!(args.id.is_none());
            assert!(args.name.is_none());
            assert!(args.description.is_none());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_options ensures create parses with
// all options.
#[test]
fn parse_create_with_options() {
    let cmd = Cmd::try_parse_from([
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
    ])
    .expect("should parse create with options");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.id, Some("type-123".to_string()));
            assert_eq!(args.name, Some("GPU Instance".to_string()));
            assert_eq!(
                args.description,
                Some("High-performance GPU instance".to_string())
            );
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_show_no_args ensures show parses with no
// arguments (all types).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["instance-type", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_id ensures show parses with --id.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["instance-type", "show", "--id", "type-123"])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.id, Some("type-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_delete ensures delete parses with required ID.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["instance-type", "delete", "--id", "type-123"])
        .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.id, "type-123");
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_update ensures update parses with required ID.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from([
        "instance-type",
        "update",
        "--id",
        "type-123",
        "--name",
        "Updated Name",
    ])
    .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.id, "type-123");
            assert_eq!(args.name, Some("Updated Name".to_string()));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_associate ensures associate parses with
// required arguments.
#[test]
fn parse_associate() {
    let cmd = Cmd::try_parse_from(["instance-type", "associate", "type-123", TEST_MACHINE_ID])
        .expect("should parse associate");

    match cmd {
        Cmd::Associate(args) => {
            assert_eq!(args.instance_type_id, "type-123");
            assert_eq!(args.machine_ids, vec![TEST_MACHINE_ID]);
        }
        _ => panic!("expected Associate variant"),
    }
}

// parse_associate_multiple_machines ensures associate
// parses with comma-separated machines.
#[test]
fn parse_associate_multiple_machines() {
    let machine_ids = format!("{},{}", TEST_MACHINE_ID, TEST_MACHINE_ID);
    let cmd = Cmd::try_parse_from(["instance-type", "associate", "type-123", &machine_ids])
        .expect("should parse associate with multiple machines");

    match cmd {
        Cmd::Associate(args) => {
            assert_eq!(args.machine_ids.len(), 2);
        }
        _ => panic!("expected Associate variant"),
    }
}

// parse_disassociate ensures disassociate parses with
// machine ID.
#[test]
fn parse_disassociate() {
    let cmd = Cmd::try_parse_from(["instance-type", "disassociate", TEST_MACHINE_ID])
        .expect("should parse disassociate");

    match cmd {
        Cmd::Disassociate(args) => {
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Disassociate variant"),
    }
}

// parse_delete_missing_id_fails ensures delete fails without --id.
#[test]
fn parse_delete_missing_id_fails() {
    let result = Cmd::try_parse_from(["instance-type", "delete"]);
    assert!(result.is_err(), "should fail without --id");
}

// parse_update_missing_id_fails ensures update fails without --id.
#[test]
fn parse_update_missing_id_fails() {
    let result = Cmd::try_parse_from(["instance-type", "update"]);
    assert!(result.is_err(), "should fail without --id");
}
