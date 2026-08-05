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
use carbide_uuid::power_shelf::PowerShelfId;
use clap::{CommandFactory, Parser};
use mac_address::MacAddress;

use super::*;
use crate::test_support::{parse_leaf, raw_value};

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

// `show` parses with and without an identifier; the parsed identifier is the
// supplied value or `None` when omitted (all shelves).
#[test]
fn parse_show_identifier() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["show"]).map_err(drop)?;
            Ok::<_, ()>(raw_value(&matches, "identifier"))
        };
        "no identifier (all shelves)" {
            &["power-shelf", "show"][..] => Yields(None),
        }

        "with identifier" {
            &["power-shelf", "show", "shelf-123"][..] => Yields(Some("shelf-123".to_string())),
        }
    );
}

// `list` with no arguments routes to the `List` variant.
#[test]
fn parse_list() {
    parse_leaf::<Cmd>(&["power-shelf", "list"], &["list"]).expect("should parse list");
}

// `list` with all filter flags captures each one: the `--deleted only` filter,
// the controller-state string, and a parsed `--bmc-mac`.
#[test]
fn parse_list_with_filters() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["list"]).map_err(drop)?;
            Ok::<_, ()>((
                matches!(
                    matches.get_one::<rpc::forge::DeletedFilter>("deleted"),
                    Some(rpc::forge::DeletedFilter::Only)
                ),
                raw_value(&matches, "controller_state"),
                matches.get_one::<MacAddress>("bmc_mac").is_some(),
            ))
        };
        "deleted + controller-state + bmc-mac" {
            &[
                "power-shelf",
                "list",
                "--deleted",
                "only",
                "--controller-state",
                "ready",
                "--bmc-mac",
                "AA:BB:CC:DD:EE:FF",
            ][..] => Yields((true, Some("ready".to_string()), true)),
        }
    );
}

// Every malformed invocation is rejected at parse time -- an out-of-range
// `--deleted` value, a malformed MAC, a maintenance action missing its required
// id, and an unknown maintenance subcommand.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "list with an invalid --deleted value" {
            &["power-shelf", "list", "--deleted", "bogus"][..] => Fails,
        }

        "list with an invalid --bmc-mac" {
            &["power-shelf", "list", "--bmc-mac", "not-a-mac"][..] => Fails,
        }

        "maintenance power-on missing required --power-shelf-id" {
            &["power-shelf", "maintenance", "power-on"][..] => Fails,
        }

        "maintenance unknown subcommand power-cycle" {
            &[
                "power-shelf",
                "maintenance",
                "power-cycle",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
            ][..] => Fails,
        }
    );
}

/////////////////////////////////////////////////////////////////////////////
// Maintenance subcommand
//
// Tests for the `power-shelf maintenance` subcommand, covering both
// `power-on` and `power-off`. These tests:
//   - parse a representative `power-shelf maintenance ...` invocation,
//   - verify the matching action and ID list.

/// Sample power-shelf id used in CLI parse tests. Must round-trip through
/// `PowerShelfId::from_str`, which `clap` uses to coerce the `--power-shelf-id`
/// argument values.
const SAMPLE_PS_ID_1: &str = "ps100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";
const SAMPLE_PS_ID_2: &str = "ps100hsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";

fn parse_ps_id(id: &str) -> PowerShelfId {
    id.parse()
        .unwrap_or_else(|error| panic!("invalid sample power-shelf id {id}: {error}"))
}

fn power_shelf_ids(matches: &clap::ArgMatches) -> Vec<PowerShelfId> {
    matches
        .get_many::<PowerShelfId>("power_shelf_ids")
        .expect("power shelf IDs are required")
        .copied()
        .collect()
}

/// `power-shelf maintenance power-on ...` parses to `Args::PowerOn`. Covers a
/// single id, multiple ids via repeated flags or a single space-separated flag,
/// the captured `--reference`, and the `--id` alias for `--power-shelf-id`. Each
/// row yields the parsed `(power_shelf_ids, reference)`.
#[test]
fn parse_maintenance_power_on() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["maintenance", "power-on"])
                .map_err(drop)?;
            Ok::<_, ()>((
                power_shelf_ids(&matches),
                raw_value(&matches, "reference"),
            ))
        };
        "single id" {
            &[
                "power-shelf",
                "maintenance",
                "power-on",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
            ][..] => Yields((vec![parse_ps_id(SAMPLE_PS_ID_1)], None)),
        }

        "two ids on a single flag occurrence (num_args = 1..)" {
            &[
                "power-shelf",
                "maintenance",
                "power-on",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
                SAMPLE_PS_ID_2,
            ][..] => Yields((
                vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
                None,
            )),
        }

        "--reference is captured" {
            &[
                "power-shelf",
                "maintenance",
                "power-on",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
                "--reference",
                "https://issues.example.com/TICKET-1",
            ][..] => Yields((
                vec![parse_ps_id(SAMPLE_PS_ID_1)],
                Some("https://issues.example.com/TICKET-1".to_string()),
            )),
        }

        "--id alias captures the power-shelf id" {
            &[
                "power-shelf",
                "maintenance",
                "power-on",
                "--id",
                SAMPLE_PS_ID_1,
            ][..] => Yields((vec![parse_ps_id(SAMPLE_PS_ID_1)], None)),
        }
    );
}

/// `power-shelf maintenance power-off ...` parses to `Args::PowerOff`. Covers
/// two ids via repeated `--power-shelf-id` flags and the `--ref` alias for
/// `--reference`. Each row yields the parsed `(power_shelf_ids, reference)`.
#[test]
fn parse_maintenance_power_off() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["maintenance", "power-off"])
                .map_err(drop)?;
            Ok::<_, ()>((
                power_shelf_ids(&matches),
                raw_value(&matches, "reference"),
            ))
        };
        "two ids via repeated --power-shelf-id flags" {
            &[
                "power-shelf",
                "maintenance",
                "power-off",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
                "--power-shelf-id",
                SAMPLE_PS_ID_2,
            ][..] => Yields((
                vec![parse_ps_id(SAMPLE_PS_ID_1), parse_ps_id(SAMPLE_PS_ID_2)],
                None,
            )),
        }

        "--ref alias captures the reference" {
            &[
                "power-shelf",
                "maintenance",
                "power-off",
                "--power-shelf-id",
                SAMPLE_PS_ID_1,
                "--ref",
                "TICKET-2",
            ][..] => Yields((
                vec![parse_ps_id(SAMPLE_PS_ID_1)],
                Some("TICKET-2".to_string()),
            )),
        }
    );
}
