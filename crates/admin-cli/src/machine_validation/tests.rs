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

// parse_external_config_show ensures external-config
// show parses.
#[test]
fn parse_external_config_show() {
    let cmd = Cmd::try_parse_from(["machine-validation", "external-config", "show"])
        .expect("should parse external-config show");

    match cmd {
        Cmd::ExternalConfig(external_config::Args::Show(args)) => {
            assert!(args.name.is_empty());
        }
        _ => panic!("expected ExternalConfig Show variant"),
    }
}

// parse_external_config_add_update ensures
// external-config add-update parses.
#[test]
fn parse_external_config_add_update() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "external-config",
        "add-update",
        "--file-name",
        "config.yaml",
        "--name",
        "my-config",
        "--description",
        "Test config",
    ])
    .expect("should parse external-config add-update");

    match cmd {
        Cmd::ExternalConfig(external_config::Args::AddUpdate(args)) => {
            assert_eq!(args.file_name, "config.yaml");
            assert_eq!(args.name, "my-config");
        }
        _ => panic!("expected ExternalConfig AddUpdate variant"),
    }
}

// parse_on_demand_start ensures on-demand start parses
// with machine ID.
#[test]
fn parse_on_demand_start() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "on-demand",
        "start",
        "--machine",
        TEST_MACHINE_ID,
    ])
    .expect("should parse on-demand start");

    match cmd {
        Cmd::OnDemand(on_demand::Args::Start(args)) => {
            assert_eq!(args.machine.to_string(), TEST_MACHINE_ID);
            assert!(!args.run_unverfied_tests);
        }
        _ => panic!("expected OnDemand Start variant"),
    }
}

// parse_runs_show ensures runs show parses.
#[test]
fn parse_runs_show() {
    let cmd = Cmd::try_parse_from(["machine-validation", "runs", "show"])
        .expect("should parse runs show");

    match cmd {
        Cmd::Runs(runs::Args::Show(args)) => {
            assert!(args.machine.is_none());
            assert!(!args.history);
        }
        _ => panic!("expected Runs Show variant"),
    }
}

// parse_runs_show_with_machine ensures runs show
// parses with machine filter.
#[test]
fn parse_runs_show_with_machine() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "runs",
        "show",
        "--machine",
        TEST_MACHINE_ID,
    ])
    .expect("should parse runs show with machine");

    match cmd {
        Cmd::Runs(runs::Args::Show(args)) => {
            assert!(args.machine.is_some());
        }
        _ => panic!("expected Runs Show variant"),
    }
}

// parse_results_show_with_machine ensures results
// show parses with machine.
#[test]
fn parse_results_show_with_machine() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "results",
        "show",
        "--machine",
        TEST_MACHINE_ID,
    ])
    .expect("should parse results show with machine");

    match cmd {
        Cmd::Results(results::Args::Show(args)) => {
            assert!(args.machine.is_some());
        }
        _ => panic!("expected Results Show variant"),
    }
}

// parse_results_show_with_validation_id ensures
// results show parses with validation ID.
#[test]
fn parse_results_show_with_validation_id() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "results",
        "show",
        "--validation-id",
        "val-123",
    ])
    .expect("should parse results show with validation-id");

    match cmd {
        Cmd::Results(results::Args::Show(args)) => {
            assert_eq!(args.validation_id, Some("val-123".to_string()));
        }
        _ => panic!("expected Results Show variant"),
    }
}

// parse_tests_show ensures tests show parses.
#[test]
fn parse_tests_show() {
    let cmd = Cmd::try_parse_from(["machine-validation", "tests", "show"])
        .expect("should parse tests show");

    match cmd {
        Cmd::Tests(tests_cmd) => match tests_cmd {
            tests_cmd::Args::Show(args) => {
                assert!(args.test_id.is_none());
            }
            _ => panic!("expected Tests Show variant"),
        },
        _ => panic!("expected Tests variant"),
    }
}

// parse_tests_verify ensures tests verify parses with
// required args.
#[test]
fn parse_tests_verify() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "tests",
        "verify",
        "--test-id",
        "test-123",
        "--version",
        "v1",
    ])
    .expect("should parse tests verify");

    match cmd {
        Cmd::Tests(tests_cmd) => match tests_cmd {
            tests_cmd::Args::Verify(args) => {
                assert_eq!(args.test_id, "test-123");
                assert_eq!(args.version, "v1");
            }
            _ => panic!("expected Tests Verify variant"),
        },
        _ => panic!("expected Tests variant"),
    }
}

// parse_tests_add ensures tests add parses with
// required args.
#[test]
fn parse_tests_add() {
    let cmd = Cmd::try_parse_from([
        "machine-validation",
        "tests",
        "add",
        "--name",
        "my-test",
        "--command",
        "/bin/test",
        "--args",
        "--verbose",
    ])
    .expect("should parse tests add");

    match cmd {
        Cmd::Tests(tests_cmd) => match tests_cmd {
            tests_cmd::Args::Add(args) => {
                assert_eq!(args.name, "my-test");
                assert_eq!(args.command, "/bin/test");
                assert_eq!(args.args, "--verbose");
            }
            _ => panic!("expected Tests Add variant"),
        },
        _ => panic!("expected Tests variant"),
    }
}

// parse_results_show_missing_required_fails ensures
// results show fails without required args.
#[test]
fn parse_results_show_missing_required_fails() {
    let result = Cmd::try_parse_from(["machine-validation", "results", "show"]);
    assert!(
        result.is_err(),
        "should fail without machine/validation_id/test_name"
    );
}
