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

// Show parses with no arguments (all instances) and with filter options;
// the tuple is (id.is_empty(), tenant_org_id, vpc_id, extrainfo).
#[test]
fn parse_show_routes_and_carries_filters() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (
                        args.id.is_empty(),
                        args.tenant_org_id,
                        args.vpc_id,
                        args.extrainfo,
                    ),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "show with no arguments" {
            &["instance", "show"][..] => Yields((true, None, None, false)),
        }

        "show with filter options" {
            &[
                "instance",
                "show",
                "--tenant-org-id",
                "tenant-123",
                "--vpc-id",
                "vpc-456",
                "--extrainfo",
            ][..] => Yields((
                true,
                Some("tenant-123".to_string()),
                Some("vpc-456".to_string()),
                true,
            )),
        }
    );
}

// Reboot parses with just the instance ID and with all optional flags;
// the tuple is (instance, custom_pxe, apply_updates_on_reboot).
#[test]
fn parse_reboot_routes_and_carries_options() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reboot(args) => (
                        args.instance.to_string(),
                        args.custom_pxe,
                        args.apply_updates_on_reboot,
                    ),
                    _ => panic!("expected Reboot variant"),
                })
                .map_err(drop)
        };
        "reboot with instance only" {
            &["instance", "reboot", "--instance", TEST_INSTANCE_ID][..] => Yields((TEST_INSTANCE_ID.to_string(), false, false)),
        }

        "reboot with all options" {
            &[
                "instance",
                "reboot",
                "--instance",
                TEST_INSTANCE_ID,
                "--custom-pxe",
                "--apply-updates-on-reboot",
            ][..] => Yields((TEST_INSTANCE_ID.to_string(), true, true)),
        }
    );
}

// Release parses by --instance or by --machine; the tuple is
// (instance, machine.is_some()).
#[test]
fn parse_release_routes_by_target() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Release(args) => (args.instance, args.machine.is_some()),
                    _ => panic!("expected Release variant"),
                })
                .map_err(drop)
        };
        "release by --instance" {
            &["instance", "release", "--instance", TEST_INSTANCE_ID][..] => Yields((Some(TEST_INSTANCE_ID.to_string()), false)),
        }

        "release by --machine" {
            &["instance", "release", "--machine", TEST_MACHINE_ID][..] => Yields((None, true)),
        }
    );
}

// Allocate parses with just its required arguments and with all options;
// the tuple is (subnet, prefix_name, number, tenant_org, transactional).
#[test]
fn parse_allocate_routes_and_carries_options() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Allocate(args) => (
                        args.subnet,
                        args.prefix_name,
                        args.number,
                        args.tenant_org,
                        args.transactional,
                    ),
                    _ => panic!("expected Allocate variant"),
                })
                .map_err(drop)
        };
        "allocate with required arguments" {
            &[
                "instance",
                "allocate",
                "--subnet",
                "10.0.0.0/24",
                "--prefix-name",
                "my-prefix",
            ][..] => Yields((
                vec!["10.0.0.0/24".to_string()],
                "my-prefix".to_string(),
                None,
                None,
                false,
            )),
        }

        "allocate with all options" {
            &[
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
            ][..] => Yields((
                vec!["10.0.0.0/24".to_string()],
                "my-prefix".to_string(),
                Some(5),
                Some("tenant-123".to_string()),
                true,
            )),
        }
    );
}

// Every malformed invocation is rejected at parse time -- a subcommand
// invoked without the required arguments it needs to act on.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "release without instance/machine/label" {
            &["instance", "release"][..] => Fails,
        }

        "allocate without subnet/vpc_prefix and prefix-name" {
            &["instance", "allocate"][..] => Fails,
        }
    );
}
