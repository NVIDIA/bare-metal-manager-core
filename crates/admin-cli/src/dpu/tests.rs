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

// parse_status ensures status parses with no
// arguments.
#[test]
fn parse_status() {
    let cmd = Cmd::try_parse_from(["dpu", "status"]).expect("should parse status");
    assert!(matches!(cmd, Cmd::Status(_)));
}

// parse_versions ensures versions parses with no
// arguments.
#[test]
fn parse_versions() {
    let cmd = Cmd::try_parse_from(["dpu", "versions"]).expect("should parse versions");

    match cmd {
        Cmd::Versions(args) => {
            assert!(!args.updates_only);
        }
        _ => panic!("expected Versions variant"),
    }
}

// parse_versions_updates_only ensures versions parses
// with --updates-only.
#[test]
fn parse_versions_updates_only() {
    let cmd = Cmd::try_parse_from(["dpu", "versions", "--updates-only"])
        .expect("should parse versions --updates-only");

    match cmd {
        Cmd::Versions(args) => {
            assert!(args.updates_only);
        }
        _ => panic!("expected Versions variant"),
    }
}

// parse_reprovision_list ensures reprovision list
// parses.
#[test]
fn parse_reprovision_list() {
    let cmd =
        Cmd::try_parse_from(["dpu", "reprovision", "list"]).expect("should parse reprovision list");

    assert!(matches!(cmd, Cmd::Reprovision(reprovision::Args::List)));
}

// parse_reprovision_set ensures reprovision set parses
// with machine ID.
#[test]
fn parse_reprovision_set() {
    let cmd = Cmd::try_parse_from(["dpu", "reprovision", "set", "--id", TEST_MACHINE_ID])
        .expect("should parse reprovision set");

    match cmd {
        Cmd::Reprovision(reprovision::Args::Set(args)) => {
            assert_eq!(args.id.to_string(), TEST_MACHINE_ID);
            assert!(!args.update_firmware);
        }
        _ => panic!("expected Reprovision Set variant"),
    }
}

// parse_reprovision_clear ensures reprovision clear
// parses with machine ID.
#[test]
fn parse_reprovision_clear() {
    let cmd = Cmd::try_parse_from(["dpu", "reprovision", "clear", "--id", TEST_MACHINE_ID])
        .expect("should parse reprovision clear");

    match cmd {
        Cmd::Reprovision(reprovision::Args::Clear(args)) => {
            assert_eq!(args.id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Reprovision Clear variant"),
    }
}

// parse_agent_upgrade_policy_get ensures
// agent-upgrade-policy parses for get.
#[test]
fn parse_agent_upgrade_policy_get() {
    let cmd = Cmd::try_parse_from(["dpu", "agent-upgrade-policy"])
        .expect("should parse agent-upgrade-policy");

    match cmd {
        Cmd::AgentUpgradePolicy(args) => {
            assert!(args.set.is_none());
        }
        _ => panic!("expected AgentUpgradePolicy variant"),
    }
}

// parse_agent_upgrade_policy_set ensures
// agent-upgrade-policy parses with --set.
#[test]
fn parse_agent_upgrade_policy_set() {
    let cmd = Cmd::try_parse_from(["dpu", "agent-upgrade-policy", "--set", "up-only"])
        .expect("should parse agent-upgrade-policy --set");

    match cmd {
        Cmd::AgentUpgradePolicy(args) => {
            assert!(matches!(
                args.set,
                Some(agent_upgrade_policy::args::AgentUpgradePolicyChoice::UpOnly)
            ));
        }
        _ => panic!("expected AgentUpgradePolicy variant"),
    }
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// agent_upgrade_policy_choice_value_enum ensures AgentUpgradePolicyChoice
// parses from strings.
#[test]
fn agent_upgrade_policy_choice_value_enum() {
    use agent_upgrade_policy::args::AgentUpgradePolicyChoice;
    use clap::ValueEnum;

    assert!(matches!(
        AgentUpgradePolicyChoice::from_str("off", false),
        Ok(AgentUpgradePolicyChoice::Off)
    ));
    assert!(matches!(
        AgentUpgradePolicyChoice::from_str("up-only", false),
        Ok(AgentUpgradePolicyChoice::UpOnly)
    ));
    assert!(matches!(
        AgentUpgradePolicyChoice::from_str("up-down", false),
        Ok(AgentUpgradePolicyChoice::UpDown)
    ));
    assert!(AgentUpgradePolicyChoice::from_str("invalid", false).is_err());
}
