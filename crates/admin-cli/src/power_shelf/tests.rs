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
use clap::CommandFactory;

use super::*;
use crate::test_support::parse_leaf;

/// Sample power-shelf id used in CLI parse tests. Must round-trip through
/// `PowerShelfId::from_str`, which `clap` uses to coerce identifier arguments.
const SAMPLE_PS_ID_1: &str = "ps100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";

// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

#[test]
fn parse_decommission_lifecycle_commands() {
    scenarios!(
        run = |argv| {
            let operation = argv[1];
            let matches = parse_leaf::<Cmd>(argv, &[operation]).map_err(drop)?;
            let power_shelf_id = matches
                .get_one::<PowerShelfId>("power_shelf_id")
                .expect("power shelf ID is required");
            Ok::<_, ()>((operation.to_string(), power_shelf_id.to_string()))
        };
        "start decommissioning" {
            &["power-shelf", "decommission", SAMPLE_PS_ID_1][..] =>
                Yields(("decommission".to_string(), SAMPLE_PS_ID_1.to_string())),
        }
    );
}

#[test]
fn parse_force_delete_cleanup_flags() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["force-delete"]).map_err(drop)?;
            Ok::<_, ()>((
                matches
                    .get_one::<PowerShelfId>("power_shelf_id")
                    .expect("power shelf ID is required")
                    .to_string(),
                matches.get_flag("delete_interfaces"),
                matches.get_flag("delete_bmc_suppressions"),
            ))
        };
        "id only" {
            &["power-shelf", "force-delete", SAMPLE_PS_ID_1][..] =>
                Yields((SAMPLE_PS_ID_1.to_string(), false, false)),
        }

        "with full cleanup flags" {
            &[
                "power-shelf",
                "force-delete",
                SAMPLE_PS_ID_1,
                "--delete-interfaces",
                "--delete-bmc-suppressions",
            ][..] => Yields((SAMPLE_PS_ID_1.to_string(), true, true)),
        }
    );
}
