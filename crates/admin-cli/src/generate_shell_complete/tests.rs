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

// parse_bash ensures bash subcommand parses.
#[test]
fn parse_bash() {
    let cmd = Cmd::try_parse_from(["generate-shell-complete", "bash"]).expect("should parse bash");
    assert!(matches!(cmd.shell, Shell::Bash));
}

// parse_fish ensures fish subcommand parses.
#[test]
fn parse_fish() {
    let cmd = Cmd::try_parse_from(["generate-shell-complete", "fish"]).expect("should parse fish");
    assert!(matches!(cmd.shell, Shell::Fish));
}

// parse_zsh ensures zsh subcommand parses.
#[test]
fn parse_zsh() {
    let cmd = Cmd::try_parse_from(["generate-shell-complete", "zsh"]).expect("should parse zsh");
    assert!(matches!(cmd.shell, Shell::Zsh));
}

// parse_missing_shell_fails ensures requires shell
// subcommand.
#[test]
fn parse_missing_shell_fails() {
    let result = Cmd::try_parse_from(["generate-shell-complete"]);
    assert!(result.is_err(), "should fail without shell subcommand");
}

// parse_invalid_shell_fails ensures fails with unknown
// shell.
#[test]
fn parse_invalid_shell_fails() {
    let result = Cmd::try_parse_from(["generate-shell-complete", "powershell"]);
    assert!(result.is_err(), "should fail with unknown shell");
}
