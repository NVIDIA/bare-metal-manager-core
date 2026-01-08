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

use super::args::*;

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
// arguments (all devices).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["network-device", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_empty());
            assert!(!args.all);
        }
    }
}

// parse_show_with_id ensures show parses with device ID.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["network-device", "show", "mac=00:11:22:33:44:55"])
        .expect("should parse show with id");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.id, "mac=00:11:22:33:44:55");
        }
    }
}

// parse_show_with_all ensures show parses with
// --all flag (deprecated).
#[test]
fn parse_show_with_all() {
    let cmd =
        Cmd::try_parse_from(["network-device", "show", "--all"]).expect("should parse show --all");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.all);
        }
    }
}
