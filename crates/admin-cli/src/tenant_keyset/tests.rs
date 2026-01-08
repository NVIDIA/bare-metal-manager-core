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
// arguments (all keysets).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["tenant-keyset", "show"]).expect("should parse show");
    let Cmd::Show(args) = cmd;

    assert_eq!(args.id, "");
    assert!(args.tenant_org_id.is_none());
}

// parse_show_with_id ensures show parses with keyset id.
#[test]
fn parse_show_with_id() {
    let cmd = Cmd::try_parse_from(["tenant-keyset", "show", "org-123/keyset-456"])
        .expect("should parse show with id");
    let Cmd::Show(args) = cmd;

    assert_eq!(args.id, "org-123/keyset-456");
}

// parse_show_with_tenant_org_id ensures show parses with
// --tenant-org-id.
#[test]
fn parse_show_with_tenant_org_id() {
    let cmd = Cmd::try_parse_from(["tenant-keyset", "show", "--tenant-org-id", "org-123"])
        .expect("should parse show with tenant-org-id");
    let Cmd::Show(args) = cmd;

    assert_eq!(args.tenant_org_id, Some("org-123".to_string()));
}

// parse_show_with_both_args ensures show parses with both
// id and tenant-org-id.
#[test]
fn parse_show_with_both_args() {
    let cmd = Cmd::try_parse_from([
        "tenant-keyset",
        "show",
        "org-123/keyset-456",
        "--tenant-org-id",
        "org-123",
    ])
    .expect("should parse show with both args");
    let Cmd::Show(args) = cmd;

    assert_eq!(args.id, "org-123/keyset-456");
    assert_eq!(args.tenant_org_id, Some("org-123".to_string()));
}
