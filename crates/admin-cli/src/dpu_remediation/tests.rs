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

// parse_create ensures create parses with required
// script_filename.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from([
        "dpu-remediation",
        "create",
        "--script-filename",
        "/path/to/script.sh",
    ])
    .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.script_filename, "/path/to/script.sh");
            assert!(args.retries.is_none());
            assert!(args.meta_name.is_none());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_options ensures create parses with
// all options.
#[test]
fn parse_create_with_options() {
    let cmd = Cmd::try_parse_from([
        "dpu-remediation",
        "create",
        "--script-filename",
        "/path/to/script.sh",
        "--retries",
        "3",
        "--meta-name",
        "My Remediation",
        "--meta-description",
        "Fixes a bug",
        "--label",
        "env:prod",
    ])
    .expect("should parse create with options");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.retries, Some(3));
            assert_eq!(args.meta_name, Some("My Remediation".to_string()));
            assert_eq!(args.meta_description, Some("Fixes a bug".to_string()));
            assert!(args.labels.is_some());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_show_no_args ensures show parses with no arguments.
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["dpu-remediation", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(!args.display_script);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_display_script ensures show parses
// with --display-script.
#[test]
fn parse_show_with_display_script() {
    let cmd = Cmd::try_parse_from(["dpu-remediation", "show", "--display-script"])
        .expect("should parse show --display-script");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.display_script);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_list_applied_no_args ensures list-applied
// parses with no arguments.
#[test]
fn parse_list_applied_no_args() {
    let cmd = Cmd::try_parse_from(["dpu-remediation", "list-applied"])
        .expect("should parse list-applied");

    match cmd {
        Cmd::ListApplied(args) => {
            assert!(args.remediation_id.is_none());
            assert!(args.machine_id.is_none());
        }
        _ => panic!("expected ListApplied variant"),
    }
}

// parse_create_missing_script_fails ensures create
// fails without --script-filename.
#[test]
fn parse_create_missing_script_fails() {
    let result = Cmd::try_parse_from(["dpu-remediation", "create"]);
    assert!(result.is_err(), "should fail without --script-filename");
}
