/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
    ScoutStreamAction::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_show ensures show parses with no arguments.
#[test]
fn parse_show() {
    let action =
        ScoutStreamAction::try_parse_from(["scout-stream", "show"]).expect("should parse show");

    assert!(matches!(action, ScoutStreamAction::Show(_)));
}

// parse_disconnect ensures disconnect parses with machine_id.
#[test]
fn parse_disconnect() {
    let action = ScoutStreamAction::try_parse_from(["scout-stream", "disconnect", TEST_MACHINE_ID])
        .expect("should parse disconnect");

    match action {
        ScoutStreamAction::Disconnect(cmd) => {
            assert_eq!(cmd.machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Disconnect variant"),
    }
}

// parse_ping ensures ping parses with machine_id.
#[test]
fn parse_ping() {
    let action = ScoutStreamAction::try_parse_from(["scout-stream", "ping", TEST_MACHINE_ID])
        .expect("should parse ping");

    match action {
        ScoutStreamAction::Ping(cmd) => {
            assert_eq!(cmd.machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Ping variant"),
    }
}

// parse_disconnect_missing_machine_id_fails ensures
// disconnect fails without machine_id.
#[test]
fn parse_disconnect_missing_machine_id_fails() {
    let result = ScoutStreamAction::try_parse_from(["scout-stream", "disconnect"]);
    assert!(result.is_err(), "should fail without machine_id");
}

// parse_ping_missing_machine_id_fails ensures ping fails
// without machine_id.
#[test]
fn parse_ping_missing_machine_id_fails() {
    let result = ScoutStreamAction::try_parse_from(["scout-stream", "ping"]);
    assert!(result.is_err(), "should fail without machine_id");
}
