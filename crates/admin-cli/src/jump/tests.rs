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

use super::args::Cmd;

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

// parse_with_machine_id ensures parses machine ID format.
#[test]
fn parse_with_machine_id() {
    let cmd = Cmd::try_parse_from(["jump", "machine-123"]).expect("should parse machine ID");
    assert_eq!(cmd.id, "machine-123");
}

// parse_with_ip_address ensures parses IP address format.
#[test]
fn parse_with_ip_address() {
    let cmd = Cmd::try_parse_from(["jump", "192.168.1.100"]).expect("should parse IP");
    assert_eq!(cmd.id, "192.168.1.100");
}

// parse_with_uuid ensures parses UUID format.
#[test]
fn parse_with_uuid() {
    let cmd = Cmd::try_parse_from(["jump", "550e8400-e29b-41d4-a716-446655440000"])
        .expect("should parse UUID");
    assert_eq!(cmd.id, "550e8400-e29b-41d4-a716-446655440000");
}

// parse_with_mac_address ensures parses MAC address format.
#[test]
fn parse_with_mac_address() {
    let cmd = Cmd::try_parse_from(["jump", "00:11:22:33:44:55"]).expect("should parse MAC");
    assert_eq!(cmd.id, "00:11:22:33:44:55");
}

// parse_requires_id_argument ensures fails without
// required id.
#[test]
fn parse_requires_id_argument() {
    let result = Cmd::try_parse_from(["jump"]);
    assert!(result.is_err(), "should fail without required id argument");
}
