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

// parse_show_no_args ensures show parses with no arguments.
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["sku", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.sku_id.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_sku_id ensures show parses with sku_id.
#[test]
fn parse_show_with_sku_id() {
    let cmd =
        Cmd::try_parse_from(["sku", "show", "sku-123"]).expect("should parse show with sku_id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.sku_id, Some("sku-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_machines ensures show-machines parses.
#[test]
fn parse_show_machines() {
    let cmd = Cmd::try_parse_from(["sku", "show-machines", "sku-123"])
        .expect("should parse show-machines");

    match cmd {
        Cmd::ShowMachines(args) => {
            assert_eq!(args.inner.sku_id, Some("sku-123".to_string()));
        }
        _ => panic!("expected ShowMachines variant"),
    }
}

// parse_generate ensures generate parses with machine_id.
#[test]
fn parse_generate() {
    let cmd =
        Cmd::try_parse_from(["sku", "generate", TEST_MACHINE_ID]).expect("should parse generate");

    match cmd {
        Cmd::Generate(args) => {
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
            assert!(args.id.is_none());
        }
        _ => panic!("expected Generate variant"),
    }
}

// parse_generate_with_id_override ensures generate parses
// with --id override.
#[test]
fn parse_generate_with_id_override() {
    let cmd = Cmd::try_parse_from(["sku", "generate", TEST_MACHINE_ID, "--id", "custom-sku"])
        .expect("should parse generate with id");

    match cmd {
        Cmd::Generate(args) => {
            assert_eq!(args.id, Some("custom-sku".to_string()));
        }
        _ => panic!("expected Generate variant"),
    }
}

// parse_create ensures create parses with filename.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from(["sku", "create", "sku.json"]).expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.filename, "sku.json");
            assert!(args.id.is_none());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_delete ensures delete parses with sku_id.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["sku", "delete", "sku-123"]).expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.sku_id, "sku-123");
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_assign ensures assign parses with sku_id and machine_id.
#[test]
fn parse_assign() {
    let cmd = Cmd::try_parse_from(["sku", "assign", "sku-123", TEST_MACHINE_ID])
        .expect("should parse assign");

    match cmd {
        Cmd::Assign(args) => {
            assert_eq!(args.sku_id, "sku-123");
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
            assert!(!args.force);
        }
        _ => panic!("expected Assign variant"),
    }
}

// parse_assign_with_force ensures assign parses with --force flag.
#[test]
fn parse_assign_with_force() {
    let cmd = Cmd::try_parse_from(["sku", "assign", "sku-123", TEST_MACHINE_ID, "--force"])
        .expect("should parse assign with force");

    match cmd {
        Cmd::Assign(args) => {
            assert!(args.force);
        }
        _ => panic!("expected Assign variant"),
    }
}

// parse_unassign ensures unassign parses with machine_id.
#[test]
fn parse_unassign() {
    let cmd =
        Cmd::try_parse_from(["sku", "unassign", TEST_MACHINE_ID]).expect("should parse unassign");

    match cmd {
        Cmd::Unassign(args) => {
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
            assert!(!args.force);
        }
        _ => panic!("expected Unassign variant"),
    }
}

// parse_verify ensures verify parses with machine_id.
#[test]
fn parse_verify() {
    let cmd = Cmd::try_parse_from(["sku", "verify", TEST_MACHINE_ID]).expect("should parse verify");

    match cmd {
        Cmd::Verify(args) => {
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Verify variant"),
    }
}

// parse_update_metadata ensures update-metadata parses
// with required args.
#[test]
fn parse_update_metadata() {
    let cmd = Cmd::try_parse_from([
        "sku",
        "update-metadata",
        "sku-123",
        "--description",
        "New desc",
    ])
    .expect("should parse update-metadata");

    match cmd {
        Cmd::UpdateMetadata(args) => {
            assert_eq!(args.sku_id, "sku-123");
            assert_eq!(args.description, Some("New desc".to_string()));
            assert!(args.device_type.is_none());
        }
        _ => panic!("expected UpdateMetadata variant"),
    }
}

// parse_bulk_update_metadata ensures bulk-update-metadata
// parses with filename.
#[test]
fn parse_bulk_update_metadata() {
    let cmd = Cmd::try_parse_from(["sku", "bulk-update-metadata", "updates.csv"])
        .expect("should parse bulk-update-metadata");

    match cmd {
        Cmd::BulkUpdateMetadata(args) => {
            assert_eq!(args.filename, "updates.csv");
        }
        _ => panic!("expected BulkUpdateMetadata variant"),
    }
}

// parse_replace ensures replace parses with filename.
#[test]
fn parse_replace() {
    let cmd = Cmd::try_parse_from(["sku", "replace", "sku.json"]).expect("should parse replace");

    match cmd {
        Cmd::Replace(args) => {
            assert_eq!(args.inner.filename, "sku.json");
        }
        _ => panic!("expected Replace variant"),
    }
}

// parse_generate_missing_machine_id_fails ensures generate
// fails without machine_id.
#[test]
fn parse_generate_missing_machine_id_fails() {
    let result = Cmd::try_parse_from(["sku", "generate"]);
    assert!(result.is_err(), "should fail without machine_id");
}

// parse_update_metadata_missing_field_fails ensures
// update-metadata fails without description or device_type.
#[test]
fn parse_update_metadata_missing_field_fails() {
    let result = Cmd::try_parse_from(["sku", "update-metadata", "sku-123"]);
    assert!(
        result.is_err(),
        "should fail without description or device_type"
    );
}
