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
// ValueEnum Parsing - Test string parsing for types deriving claps ValueEnum.

use carbide_test_support::Outcome::*;
use carbide_test_support::{Case, check_cases};
use clap::{CommandFactory, Parser};

use super::*;

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

// parse_status ensures status routes to the Status variant
// with no arguments.
#[test]
fn parse_status() {
    let cmd = Cmd::try_parse_from(["dpu", "status"]).expect("should parse status");
    assert!(matches!(cmd, Cmd::Status(_)));
}

// versions parses with and without --updates-only; the parsed flag mirrors
// whether the switch was supplied.
#[test]
fn parse_versions() {
    check_cases(
        [
            Case {
                scenario: "versions with no flags leaves updates_only off",
                input: &["dpu", "versions"][..],
                expect: Yields(false),
            },
            Case {
                scenario: "versions --updates-only sets the flag",
                input: &["dpu", "versions", "--updates-only"][..],
                expect: Yields(true),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Versions(args) => args.updates_only,
                    _ => panic!("expected Versions variant"),
                })
                .map_err(drop)
        },
    );
}

// reprovision routes to its three subcommands: list (no payload), set (an id
// plus the --update-firmware flag), and clear (an id). The closure yields the
// subcommand name, the machine id as a string (empty for list), and the
// update_firmware flag.
#[test]
fn parse_reprovision() {
    check_cases(
        [
            Case {
                scenario: "reprovision list routes to List",
                input: &["dpu", "reprovision", "list"][..],
                expect: Yields(("list", String::new(), false)),
            },
            Case {
                scenario: "reprovision set carries the machine id, firmware off",
                input: &["dpu", "reprovision", "set", "--id", TEST_MACHINE_ID][..],
                expect: Yields(("set", TEST_MACHINE_ID.to_string(), false)),
            },
            Case {
                scenario: "reprovision clear carries the machine id",
                input: &["dpu", "reprovision", "clear", "--id", TEST_MACHINE_ID][..],
                expect: Yields(("clear", TEST_MACHINE_ID.to_string(), false)),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Reprovision(reprovision::Args::List) => ("list", String::new(), false),
                    Cmd::Reprovision(reprovision::Args::Set(args)) => {
                        ("set", args.id.to_string(), args.update_firmware)
                    }
                    Cmd::Reprovision(reprovision::Args::Clear(args)) => {
                        ("clear", args.id.to_string(), false)
                    }
                    _ => panic!("expected Reprovision variant"),
                })
                .map_err(drop)
        },
    );
}

// agent-upgrade-policy parses with no --set (get, leaving set unset) and with
// --set up-only (selecting the UpOnly choice). The closure yields the policy
// name the parsed --set resolves to ("<get>" when unset).
#[test]
fn parse_agent_upgrade_policy() {
    check_cases(
        [
            Case {
                scenario: "no --set is a get and leaves the policy unset",
                input: &["dpu", "agent-upgrade-policy"][..],
                expect: Yields("<get>"),
            },
            Case {
                scenario: "--set up-only selects the UpOnly policy",
                input: &["dpu", "agent-upgrade-policy", "--set", "up-only"][..],
                expect: Yields("up-only"),
            },
        ],
        |argv| {
            use agent_upgrade_policy::args::AgentUpgradePolicyChoice;
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::AgentUpgradePolicy(args) => match args.set {
                        None => "<get>",
                        Some(AgentUpgradePolicyChoice::Off) => "off",
                        Some(AgentUpgradePolicyChoice::UpOnly) => "up-only",
                        Some(AgentUpgradePolicyChoice::UpDown) => "up-down",
                    },
                    _ => panic!("expected AgentUpgradePolicy variant"),
                })
                .map_err(drop)
        },
    );
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// agent_upgrade_policy_choice_value_enum ensures AgentUpgradePolicyChoice
// parses each valid string to its variant and rejects an unknown value. The
// enum is not PartialEq, so the closure yields a discriminant name; rows
// assert that name or a Fails for the unknown value.
#[test]
fn agent_upgrade_policy_choice_value_enum() {
    use agent_upgrade_policy::args::AgentUpgradePolicyChoice;
    use clap::ValueEnum;

    check_cases(
        [
            Case {
                scenario: "\"off\" parses to Off",
                input: "off",
                expect: Yields("off"),
            },
            Case {
                scenario: "\"up-only\" parses to UpOnly",
                input: "up-only",
                expect: Yields("up-only"),
            },
            Case {
                scenario: "\"up-down\" parses to UpDown",
                input: "up-down",
                expect: Yields("up-down"),
            },
            Case {
                scenario: "an unknown value is rejected",
                input: "invalid",
                expect: Fails,
            },
        ],
        |s| {
            AgentUpgradePolicyChoice::from_str(s, false)
                .map(|choice| match choice {
                    AgentUpgradePolicyChoice::Off => "off",
                    AgentUpgradePolicyChoice::UpOnly => "up-only",
                    AgentUpgradePolicyChoice::UpDown => "up-down",
                })
                .map_err(drop)
        },
    );
}
