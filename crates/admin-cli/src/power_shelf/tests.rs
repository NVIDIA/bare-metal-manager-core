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
// arguments (all shelves).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["power-shelf", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.identifier.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_identifier ensures show parses with identifier.
#[test]
fn parse_show_with_identifier() {
    let cmd = Cmd::try_parse_from(["power-shelf", "show", "shelf-123"])
        .expect("should parse show with identifier");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.identifier, Some("shelf-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_list ensures list parses with no arguments.
#[test]
fn parse_list() {
    let cmd = Cmd::try_parse_from(["power-shelf", "list"]).expect("should parse list");

    assert!(matches!(cmd, Cmd::List(_)));
}

// parse_list_with_filters ensures list parses with filter flags.
#[test]
fn parse_list_with_filters() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "list",
        "--deleted",
        "only",
        "--controller-state",
        "ready",
        "--bmc-mac",
        "AA:BB:CC:DD:EE:FF",
    ])
    .expect("should parse list with filters");

    match cmd {
        Cmd::List(args) => {
            assert!(matches!(args.deleted, rpc::forge::DeletedFilter::Only));
            assert_eq!(args.controller_state, Some("ready".to_string()));
            assert!(args.bmc_mac.is_some());
        }
        _ => panic!("expected List variant"),
    }
}

// parse_list_invalid_deleted ensures invalid deleted value is rejected.
#[test]
fn parse_list_invalid_deleted() {
    let result = Cmd::try_parse_from(["power-shelf", "list", "--deleted", "bogus"]);
    assert!(result.is_err());
}

// parse_list_invalid_bmc_mac ensures invalid MAC is rejected.
#[test]
fn parse_list_invalid_bmc_mac() {
    let result = Cmd::try_parse_from(["power-shelf", "list", "--bmc-mac", "not-a-mac"]);
    assert!(result.is_err());
}

/////////////////////////////////////////////////////////////////////////////
// Maintenance subcommand
//
// Tests for the `power-shelf maintenance` subcommand, covering both
// `power-on` and `power-off`. These tests:
//   - parse a representative `power-shelf maintenance ...` invocation,
//   - verify the matching `Args` variant and ID list,
//   - convert the parsed `Args` to a gRPC `PowerShelfMaintenanceRequest`
//     via `into_request()` and assert the operation enum on the wire.

use carbide_uuid::power_shelf::PowerShelfId;

use super::maintenance;

/// Sample power-shelf id used in CLI parse tests. Must round-trip through
/// `PowerShelfId::from_str`, which `clap` uses to coerce the `--power-shelf-id`
/// argument values.
const SAMPLE_PS_ID_1: &str = "ps100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";
const SAMPLE_PS_ID_2: &str = "ps100hsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";

fn parse_ps_id(id: &str) -> PowerShelfId {
    use std::str::FromStr;
    PowerShelfId::from_str(id).unwrap_or_else(|e| panic!("invalid sample power-shelf id {id}: {e}"))
}

/// `power-shelf maintenance power-on --power-shelf-id <id>` parses to
/// `Args::PowerOn` carrying the supplied id.
#[test]
fn parse_maintenance_power_on_single_id() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-on",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
    ])
    .expect("should parse maintenance power-on");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOn(args)) => {
            assert_eq!(args.power_shelf_ids, vec![parse_ps_id(SAMPLE_PS_ID_1)]);
            assert!(args.reference.is_none());
        }
        other => panic!("expected Maintenance(PowerOn(_)), got: {other:?}"),
    }
}

/// `power-shelf maintenance power-off --power-shelf-id <id1> --power-shelf-id <id2>`
/// parses to `Args::PowerOff` carrying both ids.
#[test]
fn parse_maintenance_power_off_multiple_ids_repeated_flag() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-off",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
        "--power-shelf-id",
        SAMPLE_PS_ID_2,
    ])
    .expect("should parse maintenance power-off with two ids");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOff(args)) => {
            assert_eq!(
                args.power_shelf_ids,
                vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
            );
        }
        other => panic!("expected Maintenance(PowerOff(_)), got: {other:?}"),
    }
}

/// `--power-shelf-id` accepts space-separated values in a single occurrence
/// (per its `num_args = 1..` configuration). Both ids must round-trip.
#[test]
fn parse_maintenance_power_on_multiple_ids_single_flag() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-on",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
        SAMPLE_PS_ID_2,
    ])
    .expect("should parse maintenance power-on with two ids on one flag");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOn(args)) => {
            assert_eq!(
                args.power_shelf_ids,
                vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
            );
        }
        other => panic!("expected Maintenance(PowerOn(_)), got: {other:?}"),
    }
}

/// The `--reference` flag (with `--ref` alias) is captured.
#[test]
fn parse_maintenance_with_reference() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-on",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
        "--reference",
        "https://issues.example.com/TICKET-1",
    ])
    .expect("should parse maintenance with reference");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOn(args)) => {
            assert_eq!(
                args.reference.as_deref(),
                Some("https://issues.example.com/TICKET-1"),
            );
        }
        other => panic!("expected Maintenance(PowerOn(_)), got: {other:?}"),
    }
}

/// Maintenance subcommand requires at least one `--power-shelf-id`.
#[test]
fn parse_maintenance_rejects_missing_id() {
    let result = Cmd::try_parse_from(["power-shelf", "maintenance", "power-on"]);
    assert!(
        result.is_err(),
        "missing required --power-shelf-id should fail to parse"
    );
}

/// Unknown subcommand under maintenance is rejected.
#[test]
fn parse_maintenance_rejects_unknown_action() {
    let result = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-cycle",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
    ]);
    assert!(
        result.is_err(),
        "unknown subcommand `power-cycle` should fail to parse"
    );
}

/// `Args::PowerOn::into_request()` must produce a gRPC request with the
/// `PowerOn` operation discriminant and the provided id list.
#[test]
fn power_on_into_request_uses_power_on_operation() {
    let args = maintenance::Args::PowerOn(maintenance::args::MaintenancePowerArgs {
        power_shelf_ids: vec![parse_ps_id(SAMPLE_PS_ID_1)],
        reference: Some("ref-1".to_string()),
    });
    let req = args.into_request();
    assert_eq!(
        req.operation,
        rpc::forge::PowerShelfMaintenanceOperation::PowerOn as i32,
    );
    assert_eq!(req.power_shelf_ids, vec![parse_ps_id(SAMPLE_PS_ID_1)]);
    assert_eq!(req.reference.as_deref(), Some("ref-1"));
}

/// `Args::PowerOff::into_request()` must produce a gRPC request with the
/// `PowerOff` operation discriminant.
#[test]
fn power_off_into_request_uses_power_off_operation() {
    let args = maintenance::Args::PowerOff(maintenance::args::MaintenancePowerArgs {
        power_shelf_ids: vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
        reference: None,
    });
    let req = args.into_request();
    assert_eq!(
        req.operation,
        rpc::forge::PowerShelfMaintenanceOperation::PowerOff as i32,
    );
    assert_eq!(
        req.power_shelf_ids,
        vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
    );
    assert!(req.reference.is_none());
}

/// `--ref` is a documented visible alias of `--reference`; verify it
/// captures the same value.
#[test]
fn parse_maintenance_ref_alias_captures_reference() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-off",
        "--power-shelf-id",
        SAMPLE_PS_ID_1,
        "--ref",
        "TICKET-2",
    ])
    .expect("should parse maintenance with --ref alias");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOff(args)) => {
            assert_eq!(args.reference.as_deref(), Some("TICKET-2"));
        }
        other => panic!("expected Maintenance(PowerOff(_)), got: {other:?}"),
    }
}

/// `id` is a documented visible alias of `--power-shelf-id`; verify it
/// captures the same value.
#[test]
fn parse_maintenance_id_alias_captures_power_shelf_id() {
    let cmd = Cmd::try_parse_from([
        "power-shelf",
        "maintenance",
        "power-on",
        "--id",
        SAMPLE_PS_ID_1,
    ])
    .expect("should parse maintenance with --id alias");

    match cmd {
        Cmd::Maintenance(maintenance::Args::PowerOn(args)) => {
            assert_eq!(args.power_shelf_ids, vec![parse_ps_id(SAMPLE_PS_ID_1)]);
        }
        other => panic!("expected Maintenance(PowerOn(_)), got: {other:?}"),
    }
}
