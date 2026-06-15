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

// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

// Define a basic/working MachineId for testing.
const TEST_MACHINE_ID: &str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// variant names the top-level Cmd subcommand a valid argv routed to, so
// "routes to the right variant" rows can yield a stable label.
fn variant(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::SetUefiPassword(_) => "set-uefi-password",
        Cmd::ClearUefiPassword(_) => "clear-uefi-password",
        Cmd::GenerateHostUefiPassword(_) => "generate-host-uefi-password",
        _ => "other",
    }
}

// The UEFI-password subcommands each route to their own top-level variant:
// set/clear take a machine query, generate takes no args.
#[test]
fn uefi_password_subcommands_route_to_their_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "set-uefi-password with machine query" {
            &["host", "set-uefi-password", "--query", "machine-123"][..] => Yields("set-uefi-password"),
        }

        "clear-uefi-password with machine query" {
            &["host", "clear-uefi-password", "--query", "machine-123"][..] => Yields("clear-uefi-password"),
        }

        "generate-host-uefi-password with no args" {
            &["host", "generate-host-uefi-password"][..] => Yields("generate-host-uefi-password"),
        }
    );
}

// reprovision set parses to the Set variant. With only --id the optional
// flags stay at their defaults; with --update-firmware and --update-message
// supplied they carry through. The asserted tuple is
// (id, update_firmware, update_message).
#[test]
fn reprovision_set_parses_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reprovision(reprovision::args::Args::Set(args)) => (
                        args.id.to_string(),
                        args.update_firmware,
                        args.update_message,
                    ),
                    _ => panic!("expected Reprovision Set variant"),
                })
                .map_err(drop)
        };
        "set with only required --id" {
            &["host", "reprovision", "set", "--id", TEST_MACHINE_ID][..] => Yields((TEST_MACHINE_ID.to_string(), false, None)),
        }

        "set with all options" {
            &[
                "host",
                "reprovision",
                "set",
                "--id",
                TEST_MACHINE_ID,
                "--update-firmware",
                "--update-message",
                "Maintenance in progress",
            ][..] => Yields((
                TEST_MACHINE_ID.to_string(),
                true,
                Some("Maintenance in progress".to_string()),
            )),
        }
    );
}

// reprovision clear parses to the Clear variant with required --id; the
// update_firmware flag defaults off. The asserted tuple is
// (id, update_firmware).
#[test]
fn reprovision_clear_parses_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reprovision(reprovision::args::Args::Clear(args)) => {
                        (args.id.to_string(), args.update_firmware)
                    }
                    _ => panic!("expected Reprovision Clear variant"),
                })
                .map_err(drop)
        };
        "clear with required --id" {
            &["host", "reprovision", "clear", "--id", TEST_MACHINE_ID][..] => Yields((TEST_MACHINE_ID.to_string(), false)),
        }
    );
}

// reprovision mark-manual-upgrade-complete parses to its variant with the
// required --id; the asserted value is the id.
#[test]
fn reprovision_mark_manual_upgrade_complete_parses_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reprovision(reprovision::args::Args::MarkManualUpgradeComplete(args)) => {
                        args.id.to_string()
                    }
                    _ => panic!("expected Reprovision MarkManualUpgradeComplete variant"),
                })
                .map_err(drop)
        };
        "mark-manual-upgrade-complete with required --id" {
            &[
                "host",
                "reprovision",
                "mark-manual-upgrade-complete",
                "--id",
                TEST_MACHINE_ID,
            ][..] => Yields(TEST_MACHINE_ID.to_string()),
        }
    );
}

// reprovision list parses to the List variant with no args.
#[test]
fn reprovision_list_parses() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reprovision(reprovision::args::Args::List) => "list",
                    _ => panic!("expected Reprovision List variant"),
                })
                .map_err(drop)
        };
        "list with no args" {
            &["host", "reprovision", "list"][..] => Yields("list"),
        }
    );
}

// Each malformed reprovision invocation is rejected at parse time: the
// subcommands that need --id refuse to parse without it.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "reprovision set without --id" {
            &["host", "reprovision", "set"][..] => Fails,
        }

        "reprovision mark-manual-upgrade-complete without --id" {
            &["host", "reprovision", "mark-manual-upgrade-complete"][..] => Fails,
        }
    );
}
