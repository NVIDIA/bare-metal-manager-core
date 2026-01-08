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

// parse_list ensures list parses with no arguments.
#[test]
fn parse_list() {
    let cmd = Cmd::try_parse_from(["resource-pool", "list"]).expect("should parse list");

    assert!(matches!(cmd, Cmd::List));
}

// parse_grow ensures grow parses with filename.
#[test]
fn parse_grow() {
    let cmd = Cmd::try_parse_from(["resource-pool", "grow", "--filename", "config.toml"])
        .expect("should parse grow");

    match cmd {
        Cmd::Grow(args) => {
            assert_eq!(args.filename, "config.toml");
        }
        _ => panic!("expected Grow variant"),
    }
}

// parse_grow_missing_filename_fails ensures grow fails
// without --filename.
#[test]
fn parse_grow_missing_filename_fails() {
    let result = Cmd::try_parse_from(["resource-pool", "grow"]);
    assert!(result.is_err(), "should fail without --filename");
}
