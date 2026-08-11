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
use carbide_uuid::dpa_interface::DpaInterfaceId;
use carbide_uuid::machine::MachineId;
use clap::CommandFactory;
use rpc::forge::DpaInterfaceType;

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

// show routes to the Show variant; with no positional argument its `id`
// is left unset (the "all DPAs" case).
#[test]
fn parse_show() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["show"])
                .map(|matches| matches.get_one::<DpaInterfaceId>("id").is_none())
                .map_err(drop)
        };
        "show with no arguments leaves id unset" {
            &["dpa", "show"][..] => Yields(true),
        }
    );
}

// ensure routes to the Ensure variant, threading every positional through
// to the parsed fields (machine id, MAC, device type, PCI name, interface).
#[test]
fn parse_ensure() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["ensure"])
                .map(|matches| {
                    (
                        matches
                            .get_one::<MachineId>("machine_id")
                            .expect("machine_id is required")
                            .to_string(),
                        raw_value(&matches, "mac_addr").expect("mac_addr is required"),
                        raw_value(&matches, "device_type").expect("device_type is required"),
                        raw_value(&matches, "pci_name").expect("pci_name is required"),
                        matches
                            .get_one::<DpaInterfaceType>("interface_type")
                            .copied()
                            .expect("interface_type is required"),
                    )
                })
                .map_err(drop)
        };
        "ensure with all positional arguments" {
            &[
                "dpa",
                "ensure",
                "fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30",
                "00:11:22:33:44:55",
                "BlueField3",
                "01:00.0",
                "svpc",
            ][..] => Yields((
                "fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30".to_string(),
                "00:11:22:33:44:55".to_string(),
                "BlueField3".to_string(),
                "01:00.0".to_string(),
                DpaInterfaceType::Svpc,
            )),
        }
    );
}
