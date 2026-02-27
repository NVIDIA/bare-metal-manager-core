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
use health_override::args::{Args as OverrideCommand, HealthOverrideTemplates};
use metadata::args::Args as MachineMetadataCommand;
use network::args::Args as NetworkCommand;

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

// parse_show_no_args ensures show parses with no
// arguments (all machines).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["machine", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.machine.is_none());
            assert!(!args.all);
            assert!(!args.dpus);
            assert!(!args.hosts);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_dpus ensures show parses with
// --dpus flag.
#[test]
fn parse_show_with_dpus() {
    let cmd = Cmd::try_parse_from(["machine", "show", "--dpus"]).expect("should parse show --dpus");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.dpus);
            assert!(!args.hosts);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_hosts ensures show parses with
// --hosts flag.
#[test]
fn parse_show_with_hosts() {
    let cmd =
        Cmd::try_parse_from(["machine", "show", "--hosts"]).expect("should parse show --hosts");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.hosts);
            assert!(!args.dpus);
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_dpu_ssh_credentials ensures dpu-ssh-credentials
// parses with query.
#[test]
fn parse_dpu_ssh_credentials() {
    let cmd = Cmd::try_parse_from(["machine", "dpu-ssh-credentials", "--query", "machine-123"])
        .expect("should parse dpu-ssh-credentials");

    match cmd {
        Cmd::DpuSshCredentials(args) => {
            assert_eq!(args.inner.query, "machine-123");
        }
        _ => panic!("expected DpuSshCredentials variant"),
    }
}

// parse_network_status ensures network status
// parses.
#[test]
fn parse_network_status() {
    let cmd =
        Cmd::try_parse_from(["machine", "network", "status"]).expect("should parse network status");

    assert!(matches!(cmd, Cmd::Network(NetworkCommand::Status)));
}

// parse_network_config ensures network config parses
// with machine ID.
#[test]
fn parse_network_config() {
    let cmd = Cmd::try_parse_from([
        "machine",
        "network",
        "config",
        "--machine-id",
        TEST_MACHINE_ID,
    ])
    .expect("should parse network config");

    match cmd {
        Cmd::Network(NetworkCommand::Config(args)) => {
            assert_eq!(args.machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Network Config variant"),
    }
}

// parse_health_override_show ensures health-override
// show parses.
#[test]
fn parse_health_override_show() {
    let cmd = Cmd::try_parse_from(["machine", "health-override", "show", TEST_MACHINE_ID])
        .expect("should parse health-override show");

    match cmd {
        Cmd::HealthOverride(OverrideCommand::Show { machine_id }) => {
            assert_eq!(machine_id.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected HealthOverride Show variant"),
    }
}

// parse_health_override_add_with_template ensures
// health-override add parses with template.
#[test]
fn parse_health_override_add_with_template() {
    let cmd = Cmd::try_parse_from([
        "machine",
        "health-override",
        "add",
        TEST_MACHINE_ID,
        "--template",
        "host-update",
    ])
    .expect("should parse health-override add with template");

    match cmd {
        Cmd::HealthOverride(OverrideCommand::Add(args)) => {
            assert!(args.template.is_some());
            assert!(args.health_report.is_none());
        }
        _ => panic!("expected HealthOverride Add variant"),
    }
}

// parse_reboot ensures reboot parses with
// machine.
#[test]
fn parse_reboot() {
    let cmd = Cmd::try_parse_from(["machine", "reboot", "--machine", TEST_MACHINE_ID])
        .expect("should parse reboot");

    match cmd {
        Cmd::Reboot(args) => {
            assert_eq!(args.machine, TEST_MACHINE_ID);
        }
        _ => panic!("expected Reboot variant"),
    }
}

// parse_force_delete ensures force-delete parses with
// machine.
#[test]
fn parse_force_delete() {
    let cmd = Cmd::try_parse_from(["machine", "force-delete", "--machine", TEST_MACHINE_ID])
        .expect("should parse force-delete");

    match cmd {
        Cmd::ForceDelete(args) => {
            assert_eq!(args.machine, TEST_MACHINE_ID);
            assert!(!args.delete_interfaces);
            assert!(!args.allow_delete_with_instance);
        }
        _ => panic!("expected ForceDelete variant"),
    }
}

// parse_auto_update_enable ensures auto-update parses
// with enable flag.
#[test]
fn parse_auto_update_enable() {
    let cmd = Cmd::try_parse_from([
        "machine",
        "auto-update",
        "--machine",
        TEST_MACHINE_ID,
        "--enable",
    ])
    .expect("should parse auto-update --enable");

    match cmd {
        Cmd::AutoUpdate(args) => {
            assert!(args.enable);
            assert!(!args.disable);
            assert!(!args.clear);
        }
        _ => panic!("expected AutoUpdate variant"),
    }
}

// parse_metadata_show ensures metadata show parses
// with machine ID.
#[test]
fn parse_metadata_show() {
    let cmd = Cmd::try_parse_from(["machine", "metadata", "show", TEST_MACHINE_ID])
        .expect("should parse metadata show");

    match cmd {
        Cmd::Metadata(MachineMetadataCommand::Show(args)) => {
            assert_eq!(args.machine.to_string(), TEST_MACHINE_ID);
        }
        _ => panic!("expected Metadata Show variant"),
    }
}

// parse_metadata_set ensures metadata set parses with
// machine ID and options.
#[test]
fn parse_metadata_set() {
    let cmd = Cmd::try_parse_from([
        "machine",
        "metadata",
        "set",
        TEST_MACHINE_ID,
        "--name",
        "MyMachine",
    ])
    .expect("should parse metadata set");

    match cmd {
        Cmd::Metadata(MachineMetadataCommand::Set(args)) => {
            assert_eq!(args.name, Some("MyMachine".to_string()));
        }
        _ => panic!("expected Metadata Set variant"),
    }
}

// parse_positions ensures positions parses with no
// arguments.
#[test]
fn parse_positions() {
    let cmd = Cmd::try_parse_from(["machine", "positions"]).expect("should parse positions");

    match cmd {
        Cmd::Positions(args) => {
            assert!(args.machine.is_empty());
        }
        _ => panic!("expected Positions variant"),
    }
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// health_override_templates_value_enum ensures HealthOverrideTemplates
// parses from strings.
#[test]
fn health_override_templates_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        HealthOverrideTemplates::from_str("host-update", false),
        Ok(HealthOverrideTemplates::HostUpdate)
    ));
    assert!(matches!(
        HealthOverrideTemplates::from_str("internal-maintenance", false),
        Ok(HealthOverrideTemplates::InternalMaintenance)
    ));
    assert!(matches!(
        HealthOverrideTemplates::from_str("out-for-repair", false),
        Ok(HealthOverrideTemplates::OutForRepair)
    ));
    assert!(matches!(
        HealthOverrideTemplates::from_str("degraded", false),
        Ok(HealthOverrideTemplates::Degraded)
    ));
    assert!(matches!(
        HealthOverrideTemplates::from_str("validation", false),
        Ok(HealthOverrideTemplates::Validation)
    ));
    assert!(HealthOverrideTemplates::from_str("invalid", false).is_err());
}
