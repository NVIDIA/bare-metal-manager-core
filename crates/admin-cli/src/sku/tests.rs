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
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Show(args)) => Ok(args.sku_id),
            Ok(_) => panic!("expected Show variant"),
            Err(_) => Err(()),
        };
        "no args leaves sku_id unset" {
            &["sku", "show"][..] => Yields(None),
        }

        "positional sku_id is captured" {
            &["sku", "show", "sku-123"][..] => Yields(Some("sku-123".to_string())),
        }
    );
}

// show-machines parses with a positional sku_id, captured on the
// inner args.
#[test]
fn parse_show_machines() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::ShowMachines(args)) => Ok(args.inner.sku_id),
            Ok(_) => panic!("expected ShowMachines variant"),
            Err(_) => Err(()),
        };
        "positional sku_id is captured on inner" {
            &["sku", "show-machines", "sku-123"][..] => Yields(Some("sku-123".to_string())),
        }
    );
}

// generate parses with a required machine_id and an optional --id
// override; the tuple is (machine_id, id).
#[test]
fn parse_generate() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Generate(args)) => Ok((args.machine_id.to_string(), args.id)),
            Ok(_) => panic!("expected Generate variant"),
            Err(_) => Err(()),
        };
        "machine_id only leaves id unset" {
            &["sku", "generate", TEST_MACHINE_ID][..] => Yields((TEST_MACHINE_ID.to_string(), None)),
        }

        "--id override is captured" {
            &["sku", "generate", TEST_MACHINE_ID, "--id", "custom-sku"][..] => Yields((TEST_MACHINE_ID.to_string(), Some("custom-sku".to_string()))),
        }
    );
}

// create parses with a positional filename; --id defaults to unset.
// The tuple is (filename, id).
#[test]
fn parse_create() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Create(args)) => Ok((args.filename, args.id)),
            Ok(_) => panic!("expected Create variant"),
            Err(_) => Err(()),
        };
        "filename captured, id unset" {
            &["sku", "create", "sku.json"][..] => Yields(("sku.json".to_string(), None)),
        }
    );
}

// delete parses with a positional sku_id.
#[test]
fn parse_delete() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Delete(args)) => Ok(args.sku_id),
            Ok(_) => panic!("expected Delete variant"),
            Err(_) => Err(()),
        };
        "positional sku_id is captured" {
            &["sku", "delete", "sku-123"][..] => Yields("sku-123".to_string()),
        }
    );
}

// assign parses with sku_id and machine_id, with an optional --force
// flag. The tuple is (sku_id, machine_id, force).
#[test]
fn parse_assign() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Assign(args)) => Ok((args.sku_id, args.machine_id.to_string(), args.force)),
            Ok(_) => panic!("expected Assign variant"),
            Err(_) => Err(()),
        };
        "force defaults off" {
            &["sku", "assign", "sku-123", TEST_MACHINE_ID][..] => Yields(("sku-123".to_string(), TEST_MACHINE_ID.to_string(), false)),
        }

        "--force flag sets force" {
            &["sku", "assign", "sku-123", TEST_MACHINE_ID, "--force"][..] => Yields(("sku-123".to_string(), TEST_MACHINE_ID.to_string(), true)),
        }
    );
}

// unassign parses with a machine_id; --force defaults off. The tuple
// is (machine_id, force).
#[test]
fn parse_unassign() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Unassign(args)) => Ok((args.machine_id.to_string(), args.force)),
            Ok(_) => panic!("expected Unassign variant"),
            Err(_) => Err(()),
        };
        "machine_id captured, force defaults off" {
            &["sku", "unassign", TEST_MACHINE_ID][..] => Yields((TEST_MACHINE_ID.to_string(), false)),
        }
    );
}

// verify parses with a machine_id.
#[test]
fn parse_verify() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Verify(args)) => Ok(args.machine_id.to_string()),
            Ok(_) => panic!("expected Verify variant"),
            Err(_) => Err(()),
        };
        "machine_id is captured" {
            &["sku", "verify", TEST_MACHINE_ID][..] => Yields(TEST_MACHINE_ID.to_string()),
        }
    );
}

// update-metadata parses with a sku_id and a --description; --device-type
// defaults to unset. The tuple is (sku_id, description, device_type).
#[test]
fn parse_update_metadata() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::UpdateMetadata(args)) => {
                Ok((args.sku_id, args.description, args.device_type.is_none()))
            }
            Ok(_) => panic!("expected UpdateMetadata variant"),
            Err(_) => Err(()),
        };
        "sku_id and description captured, device_type unset" {
            &[
                "sku",
                "update-metadata",
                "sku-123",
                "--description",
                "New desc",
            ][..] => Yields(("sku-123".to_string(), Some("New desc".to_string()), true)),
        }
    );
}

// bulk-update-metadata parses with a positional filename.
#[test]
fn parse_bulk_update_metadata() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::BulkUpdateMetadata(args)) => Ok(args.filename),
            Ok(_) => panic!("expected BulkUpdateMetadata variant"),
            Err(_) => Err(()),
        };
        "filename is captured" {
            &["sku", "bulk-update-metadata", "updates.csv"][..] => Yields("updates.csv".to_string()),
        }
    );
}

// replace parses with a positional filename, captured on the inner args.
#[test]
fn parse_replace() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Replace(args)) => Ok(args.inner.filename),
            Ok(_) => panic!("expected Replace variant"),
            Err(_) => Err(()),
        };
        "filename is captured on inner" {
            &["sku", "replace", "sku.json"][..] => Yields("sku.json".to_string()),
        }
    );
}

// Every malformed invocation is rejected at parse time -- generate
// without its required machine_id, and update-metadata with neither a
// description nor a device_type to change.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "generate without machine_id" {
            &["sku", "generate"][..] => Fails,
        }

        "update-metadata without description or device_type" {
            &["sku", "update-metadata", "sku-123"][..] => Fails,
        }
    );
}
