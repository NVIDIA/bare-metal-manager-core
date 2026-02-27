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

use super::*;

// Valid InstanceId format for tests (standard UUID format)
const TEST_INSTANCE_ID: &str = "00000000-0000-0000-0000-000000000001";

// Define a basic/working MachineId for testing.
const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

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
// arguments (all instances).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["instance", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_empty());
            assert!(!args.extrainfo);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_filters ensures show parses with
// filter options.
#[test]
fn parse_show_with_filters() {
    let cmd = Cmd::try_parse_from([
        "instance",
        "show",
        "--tenant-org-id",
        "tenant-123",
        "--vpc-id",
        "vpc-456",
        "--extrainfo",
    ])
    .expect("should parse show with filters");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.tenant_org_id, Some("tenant-123".to_string()));
            assert_eq!(args.vpc_id, Some("vpc-456".to_string()));
            assert!(args.extrainfo);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_reboot ensures reboot parses with instance ID.
#[test]
fn parse_reboot() {
    let cmd = Cmd::try_parse_from(["instance", "reboot", "--instance", TEST_INSTANCE_ID])
        .expect("should parse reboot");

    match cmd {
        Cmd::Reboot(args) => {
            assert_eq!(args.instance.to_string(), TEST_INSTANCE_ID);
            assert!(!args.custom_pxe);
            assert!(!args.apply_updates_on_reboot);
        }
        _ => panic!("expected Reboot variant"),
    }
}

// parse_reboot_with_options ensures reboot parses with
// all options.
#[test]
fn parse_reboot_with_options() {
    let cmd = Cmd::try_parse_from([
        "instance",
        "reboot",
        "--instance",
        TEST_INSTANCE_ID,
        "--custom-pxe",
        "--apply-updates-on-reboot",
    ])
    .expect("should parse reboot with options");

    match cmd {
        Cmd::Reboot(args) => {
            assert!(args.custom_pxe);
            assert!(args.apply_updates_on_reboot);
        }
        _ => panic!("expected Reboot variant"),
    }
}

// parse_release_by_instance ensures release parses with
// --instance.
#[test]
fn parse_release_by_instance() {
    let cmd = Cmd::try_parse_from(["instance", "release", "--instance", TEST_INSTANCE_ID])
        .expect("should parse release");

    match cmd {
        Cmd::Release(args) => {
            assert_eq!(args.instance, Some(TEST_INSTANCE_ID.to_string()));
            assert!(args.machine.is_none());
        }
        _ => panic!("expected Release variant"),
    }
}

// parse_release_by_machine ensures release parses with
// --machine.
#[test]
fn parse_release_by_machine() {
    let cmd = Cmd::try_parse_from(["instance", "release", "--machine", TEST_MACHINE_ID])
        .expect("should parse release by machine");

    match cmd {
        Cmd::Release(args) => {
            assert!(args.instance.is_none());
            assert!(args.machine.is_some());
        }
        _ => panic!("expected Release variant"),
    }
}

// parse_allocate ensures allocate parses with required
// arguments.
#[test]
fn parse_allocate() {
    let cmd = Cmd::try_parse_from([
        "instance",
        "allocate",
        "--subnet",
        "10.0.0.0/24",
        "--prefix-name",
        "my-prefix",
    ])
    .expect("should parse allocate");

    match cmd {
        Cmd::Allocate(args) => {
            assert_eq!(args.subnet, vec!["10.0.0.0/24"]);
            assert_eq!(args.prefix_name, "my-prefix");
        }
        _ => panic!("expected Allocate variant"),
    }
}

// parse_allocate_with_options ensures allocate parses
// with all options.
#[test]
fn parse_allocate_with_options() {
    let cmd = Cmd::try_parse_from([
        "instance",
        "allocate",
        "--subnet",
        "10.0.0.0/24",
        "--prefix-name",
        "my-prefix",
        "--number",
        "5",
        "--tenant-org",
        "tenant-123",
        "--transactional",
    ])
    .expect("should parse allocate with options");

    match cmd {
        Cmd::Allocate(args) => {
            assert_eq!(args.number, Some(5));
            assert_eq!(args.tenant_org, Some("tenant-123".to_string()));
            assert!(args.transactional);
        }
        _ => panic!("expected Allocate variant"),
    }
}

// parse_release_missing_required_fails ensures release
// fails without required arguments.
#[test]
fn parse_release_missing_required_fails() {
    let result = Cmd::try_parse_from(["instance", "release"]);
    assert!(
        result.is_err(),
        "should fail without instance/machine/label"
    );
}

// parse_allocate_missing_required_fails ensures
// allocate fails without required arguments.
#[test]
fn parse_allocate_missing_required_fails() {
    let result = Cmd::try_parse_from(["instance", "allocate"]);
    assert!(
        result.is_err(),
        "should fail without subnet/vpc_prefix and prefix-name"
    );
}
