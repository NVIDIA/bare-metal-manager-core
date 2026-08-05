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
use carbide_test_support::scenarios;
use carbide_uuid::machine::MachineId;
use clap::{CommandFactory, Parser};

use self::health_report::args::{Args as HealthReportCommand, HealthReportTemplates};
use super::*;
use crate::test_support::{parse_leaf, raw_value};

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

// `show` parses with no arguments and with each of its flags, capturing the
// machine/all/dpus/hosts state in each case.
#[test]
fn parse_show_variants() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.machine.is_some(), args.all, args.dpus, args.hosts),
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "no arguments (all machines)" {
            &["machine", "show"][..] => Yields((false, false, false, false)),
        }

        "--dpus flag" {
            &["machine", "show", "--dpus"][..] => Yields((false, false, true, false)),
        }

        "--hosts flag" {
            &["machine", "show", "--hosts"][..] => Yields((false, false, false, true)),
        }
    );
}

// network status routes to the Status variant; network config parses with a
// machine ID and exposes it.
#[test]
fn parse_network_status() {
    parse_leaf::<Cmd>(&["machine", "network", "status"], &["network", "status"])
        .expect("should parse network status");
}

// parse_network_config ensures network config parses
// with machine ID.
#[test]
fn parse_network_config() {
    let matches = parse_leaf::<Cmd>(
        &[
            "machine",
            "network",
            "config",
            "--machine-id",
            TEST_MACHINE_ID,
        ],
        &["network", "config"],
    )
    .expect("should parse network config");

    assert_eq!(
        matches.get_one::<MachineId>("machine_id"),
        Some(&TEST_MACHINE_ID.parse::<MachineId>().unwrap())
    );
}

// health-report show parses, and the legacy health-override alias routes to the
// same Show variant; both expose the machine ID.
#[test]
fn parse_health_report_show_variants() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::HealthReport(HealthReportCommand::Show { machine_id }) => {
                        machine_id.to_string()
                    }
                    _ => panic!("expected HealthReport Show variant"),
                })
                .map_err(drop)
        };
        "health-report show" {
            &["machine", "health-report", "show", TEST_MACHINE_ID][..] => Yields(TEST_MACHINE_ID.to_string()),
        }

        "legacy health-override show alias" {
            &["machine", "health-override", "show", TEST_MACHINE_ID][..] => Yields(TEST_MACHINE_ID.to_string()),
        }
    );
}

// parse_health_override_add_with_template ensures the
// legacy health-override alias still parses with template.
#[test]
fn parse_health_override_add_with_template() {
    let matches = parse_leaf::<Cmd>(
        &[
            "machine",
            "health-override",
            "add",
            TEST_MACHINE_ID,
            "--template",
            "host-update",
        ],
        &["health-report", "add"],
    )
    .expect("should parse health-override add with template");

    assert!(matches!(
        matches.get_one::<HealthReportTemplates>("template"),
        Some(HealthReportTemplates::HostUpdate)
    ));
    assert!(raw_value(&matches, "health_report").is_none());
}

// parse_reboot ensures reboot parses with
// machine.
#[test]
fn parse_reboot() {
    let matches = parse_leaf::<Cmd>(
        &["machine", "reboot", "--machine", TEST_MACHINE_ID],
        &["reboot"],
    )
    .expect("should parse reboot");

    assert_eq!(
        raw_value(&matches, "machine").as_deref(),
        Some(TEST_MACHINE_ID)
    );
}

// parse_force_delete ensures force-delete parses with
// machine.
#[test]
fn parse_force_delete() {
    let matches = parse_leaf::<Cmd>(
        &["machine", "force-delete", "--machine", TEST_MACHINE_ID],
        &["force-delete"],
    )
    .expect("should parse force-delete");

    assert_eq!(
        raw_value(&matches, "machine").as_deref(),
        Some(TEST_MACHINE_ID)
    );
    assert!(!matches.get_flag("delete_interfaces"));
    assert!(!matches.get_flag("allow_delete_with_instance"));
    assert!(!matches.get_flag("allow_delete_with_orphaned_dpf_crds"));
}

// parse_auto_update_enable ensures auto-update parses
// with enable flag.
#[test]
fn parse_auto_update_enable() {
    let matches = parse_leaf::<Cmd>(
        &[
            "machine",
            "auto-update",
            "--machine",
            TEST_MACHINE_ID,
            "--enable",
        ],
        &["auto-update"],
    )
    .expect("should parse auto-update --enable");

    assert!(matches.get_flag("enable"));
    assert!(!matches.get_flag("disable"));
    assert!(!matches.get_flag("clear"));
}

// metadata show exposes the machine ID; metadata set exposes the parsed
// --name option.
#[test]
fn parse_metadata_show() {
    let matches = parse_leaf::<Cmd>(
        &["machine", "metadata", "show", TEST_MACHINE_ID],
        &["metadata", "show"],
    )
    .expect("should parse metadata show");

    assert_eq!(
        matches.get_one::<MachineId>("machine"),
        Some(&TEST_MACHINE_ID.parse::<MachineId>().unwrap())
    );
}

// parse_metadata_set ensures metadata set parses with
// machine ID and options.
#[test]
fn parse_metadata_set() {
    let matches = parse_leaf::<Cmd>(
        &[
            "machine",
            "metadata",
            "set",
            TEST_MACHINE_ID,
            "--name",
            "MyMachine",
        ],
        &["metadata", "set"],
    )
    .expect("should parse metadata set");

    assert_eq!(raw_value(&matches, "name").as_deref(), Some("MyMachine"));
}

// parse_positions ensures positions parses with no
// arguments.
#[test]
fn parse_positions() {
    let matches = parse_leaf::<Cmd>(&["machine", "positions"], &["positions"])
        .expect("should parse positions");

    assert!(matches.get_many::<MachineId>("machine").is_none());
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// Each HealthReportTemplates string round-trips to its variant, and an unknown
// string is rejected. The variant isn't PartialEq, so the closure projects the
// parsed variant through an EXHAUSTIVE `template_name` (no wildcard arm) and each
// row's expected is that same projection applied to the variant it names -- the
// variant, not a hand-copied string, is the source of truth. The exhaustive match
// also means a newly-added HealthReportTemplates variant fails to compile here
// rather than silently slipping past, so it has to be given a string and a row.
#[test]
fn health_override_templates_value_enum() {
    use HealthReportTemplates as T;
    use clap::ValueEnum;

    fn template_name(t: &HealthReportTemplates) -> &'static str {
        match t {
            T::HostUpdate => "host-update",
            T::InternalMaintenance => "internal-maintenance",
            T::OutForRepair => "out-for-repair",
            T::Degraded => "degraded",
            T::Validation => "validation",
            T::SuppressExternalAlerting => "suppress-external-alerting",
            T::MarkHealthy => "mark-healthy",
            T::StopRebootForAutomaticRecoveryFromStateMachine => {
                "stop-reboot-for-automatic-recovery-from-state-machine"
            }
            T::TenantReportedIssue => "tenant-reported-issue",
            T::RequestOnlineRepair => "request-online-repair",
            T::RequestRepair => "request-repair",
        }
    }

    scenarios!(
        run = |s| {
            HealthReportTemplates::from_str(s, false)
                .map(|t| template_name(&t))
                .map_err(drop)
        };
        "host-update" {
            "host-update" => Yields(template_name(&T::HostUpdate)),
        }

        "internal-maintenance" {
            "internal-maintenance" => Yields(template_name(&T::InternalMaintenance)),
        }

        "out-for-repair" {
            "out-for-repair" => Yields(template_name(&T::OutForRepair)),
        }

        "degraded" {
            "degraded" => Yields(template_name(&T::Degraded)),
        }

        "validation" {
            "validation" => Yields(template_name(&T::Validation)),
        }

        "suppress-external-alerting" {
            "suppress-external-alerting" => Yields(template_name(&T::SuppressExternalAlerting)),
        }

        "mark-healthy" {
            "mark-healthy" => Yields(template_name(&T::MarkHealthy)),
        }

        "stop-reboot-for-automatic-recovery-from-state-machine" {
            "stop-reboot-for-automatic-recovery-from-state-machine" =>
                Yields(template_name(&T::StopRebootForAutomaticRecoveryFromStateMachine)),
        }

        "tenant-reported-issue" {
            "tenant-reported-issue" => Yields(template_name(&T::TenantReportedIssue)),
        }

        "request-online-repair" {
            "request-online-repair" => Yields(template_name(&T::RequestOnlineRepair)),
        }

        "request-repair" {
            "request-repair" => Yields(template_name(&T::RequestRepair)),
        }

        "invalid string is rejected" {
            "invalid" => Fails,
        }
    );
}
