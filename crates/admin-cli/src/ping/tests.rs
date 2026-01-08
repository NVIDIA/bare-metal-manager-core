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

// verify_cmd_structure runs the underlying clap debug_assert()
#[test]
fn verify_cmd_structure() {
    Opts::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_default_interval ensures ping parses with default interval.
#[test]
fn parse_default_interval() {
    let opts = Opts::try_parse_from(["ping"]).expect("should parse ping");

    assert!((opts.interval - 1.0).abs() < f32::EPSILON);
}

// parse_custom_interval ensures ping parses with a custom interval.
#[test]
fn parse_custom_interval() {
    let opts = Opts::try_parse_from(["ping", "--interval", "2.5"])
        .expect("should parse ping with interval");

    assert!((opts.interval - 2.5).abs() < f32::EPSILON);
}

// parse_short_interval_flag ensures ping parses with -i short flag.
#[test]
fn parse_short_interval_flag() {
    let opts = Opts::try_parse_from(["ping", "-i", "0.5"]).expect("should parse ping with -i");

    assert!((opts.interval - 0.5).abs() < f32::EPSILON);
}
