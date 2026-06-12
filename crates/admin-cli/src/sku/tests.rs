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

// show parses with no arguments (sku_id absent) and with a
// positional sku_id (present).
#[test]
fn parse_show() {
    check_cases(
        [
            Case {
                scenario: "no args leaves sku_id unset",
                input: &["sku", "show"][..],
                expect: Yields(None),
            },
            Case {
                scenario: "positional sku_id is captured",
                input: &["sku", "show", "sku-123"][..],
                expect: Yields(Some("sku-123".to_string())),
            },
        ],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Show(args)) => Ok(args.sku_id),
            Ok(_) => panic!("expected Show variant"),
            Err(_) => Err(()),
        },
    );
}

// show-machines parses with a positional sku_id, captured on the
// inner args.
#[test]
fn parse_show_machines() {
    check_cases(
        [Case {
            scenario: "positional sku_id is captured on inner",
            input: &["sku", "show-machines", "sku-123"][..],
            expect: Yields(Some("sku-123".to_string())),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::ShowMachines(args)) => Ok(args.inner.sku_id),
            Ok(_) => panic!("expected ShowMachines variant"),
            Err(_) => Err(()),
        },
    );
}

// generate parses with a required machine_id and an optional --id
// override; the tuple is (machine_id, id).
#[test]
fn parse_generate() {
    check_cases(
        [
            Case {
                scenario: "machine_id only leaves id unset",
                input: &["sku", "generate", TEST_MACHINE_ID][..],
                expect: Yields((TEST_MACHINE_ID.to_string(), None)),
            },
            Case {
                scenario: "--id override is captured",
                input: &["sku", "generate", TEST_MACHINE_ID, "--id", "custom-sku"][..],
                expect: Yields((TEST_MACHINE_ID.to_string(), Some("custom-sku".to_string()))),
            },
        ],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Generate(args)) => Ok((args.machine_id.to_string(), args.id)),
            Ok(_) => panic!("expected Generate variant"),
            Err(_) => Err(()),
        },
    );
}

// create parses with a positional filename; --id defaults to unset.
// The tuple is (filename, id).
#[test]
fn parse_create() {
    check_cases(
        [Case {
            scenario: "filename captured, id unset",
            input: &["sku", "create", "sku.json"][..],
            expect: Yields(("sku.json".to_string(), None)),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Create(args)) => Ok((args.filename, args.id)),
            Ok(_) => panic!("expected Create variant"),
            Err(_) => Err(()),
        },
    );
}

// delete parses with a positional sku_id.
#[test]
fn parse_delete() {
    check_cases(
        [Case {
            scenario: "positional sku_id is captured",
            input: &["sku", "delete", "sku-123"][..],
            expect: Yields("sku-123".to_string()),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Delete(args)) => Ok(args.sku_id),
            Ok(_) => panic!("expected Delete variant"),
            Err(_) => Err(()),
        },
    );
}

// assign parses with sku_id and machine_id, with an optional --force
// flag. The tuple is (sku_id, machine_id, force).
#[test]
fn parse_assign() {
    check_cases(
        [
            Case {
                scenario: "force defaults off",
                input: &["sku", "assign", "sku-123", TEST_MACHINE_ID][..],
                expect: Yields(("sku-123".to_string(), TEST_MACHINE_ID.to_string(), false)),
            },
            Case {
                scenario: "--force flag sets force",
                input: &["sku", "assign", "sku-123", TEST_MACHINE_ID, "--force"][..],
                expect: Yields(("sku-123".to_string(), TEST_MACHINE_ID.to_string(), true)),
            },
        ],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Assign(args)) => Ok((args.sku_id, args.machine_id.to_string(), args.force)),
            Ok(_) => panic!("expected Assign variant"),
            Err(_) => Err(()),
        },
    );
}

// unassign parses with a machine_id; --force defaults off. The tuple
// is (machine_id, force).
#[test]
fn parse_unassign() {
    check_cases(
        [Case {
            scenario: "machine_id captured, force defaults off",
            input: &["sku", "unassign", TEST_MACHINE_ID][..],
            expect: Yields((TEST_MACHINE_ID.to_string(), false)),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Unassign(args)) => Ok((args.machine_id.to_string(), args.force)),
            Ok(_) => panic!("expected Unassign variant"),
            Err(_) => Err(()),
        },
    );
}

// verify parses with a machine_id.
#[test]
fn parse_verify() {
    check_cases(
        [Case {
            scenario: "machine_id is captured",
            input: &["sku", "verify", TEST_MACHINE_ID][..],
            expect: Yields(TEST_MACHINE_ID.to_string()),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Verify(args)) => Ok(args.machine_id.to_string()),
            Ok(_) => panic!("expected Verify variant"),
            Err(_) => Err(()),
        },
    );
}

// update-metadata parses with a sku_id and a --description; --device-type
// defaults to unset. The tuple is (sku_id, description, device_type).
#[test]
fn parse_update_metadata() {
    check_cases(
        [Case {
            scenario: "sku_id and description captured, device_type unset",
            input: &[
                "sku",
                "update-metadata",
                "sku-123",
                "--description",
                "New desc",
            ][..],
            expect: Yields(("sku-123".to_string(), Some("New desc".to_string()), true)),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::UpdateMetadata(args)) => {
                Ok((args.sku_id, args.description, args.device_type.is_none()))
            }
            Ok(_) => panic!("expected UpdateMetadata variant"),
            Err(_) => Err(()),
        },
    );
}

// bulk-update-metadata parses with a positional filename.
#[test]
fn parse_bulk_update_metadata() {
    check_cases(
        [Case {
            scenario: "filename is captured",
            input: &["sku", "bulk-update-metadata", "updates.csv"][..],
            expect: Yields("updates.csv".to_string()),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::BulkUpdateMetadata(args)) => Ok(args.filename),
            Ok(_) => panic!("expected BulkUpdateMetadata variant"),
            Err(_) => Err(()),
        },
    );
}

// replace parses with a positional filename, captured on the inner args.
#[test]
fn parse_replace() {
    check_cases(
        [Case {
            scenario: "filename is captured on inner",
            input: &["sku", "replace", "sku.json"][..],
            expect: Yields("sku.json".to_string()),
        }],
        |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Replace(args)) => Ok(args.inner.filename),
            Ok(_) => panic!("expected Replace variant"),
            Err(_) => Err(()),
        },
    );
}

// Every malformed invocation is rejected at parse time -- generate
// without its required machine_id, and update-metadata with neither a
// description nor a device_type to change.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "generate without machine_id",
                input: &["sku", "generate"][..],
                expect: Fails,
            },
            Case {
                scenario: "update-metadata without description or device_type",
                input: &["sku", "update-metadata", "sku-123"][..],
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
