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
use carbide_uuid::machine_validation::MachineValidationId;
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

// external-config parses to the ExternalConfig variant: `show` defaults to an
// empty name filter, and `add-update` carries its file-name/name through.
#[test]
fn parse_external_config_routes_and_carries_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::ExternalConfig(external_config::Args::Show(args)) => {
                        // show has no file-name; surface its (empty) name filter
                        // as a joined string so both arms yield (String, String)
                        (String::new(), args.name.join(","))
                    }
                    Cmd::ExternalConfig(external_config::Args::AddUpdate(args)) => {
                        (args.file_name, args.name)
                    }
                    _ => panic!("expected ExternalConfig variant"),
                })
                .map_err(drop)
        };
        "show defaults to an empty name filter" {
            &["machine-validation", "external-config", "show"][..] => Yields((String::new(), String::new())),
        }

        "add-update carries file-name and name" {
            &[
                "machine-validation",
                "external-config",
                "add-update",
                "--file-name",
                "config.yaml",
                "--name",
                "my-config",
                "--description",
                "Test config",
            ][..] => Yields(("config.yaml".to_string(), "my-config".to_string())),
        }
    );
}

// on-demand start parses to the OnDemand::Start variant, carrying the machine ID
// and defaulting --run-unverified-tests to false.
#[test]
fn parse_on_demand_start_carries_machine() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::OnDemand(on_demand::Args::Start(args)) => {
                        (args.machine.to_string(), args.run_unverified_tests)
                    }
                    _ => panic!("expected OnDemand Start variant"),
                })
                .map_err(drop)
        };
        "start with a machine ID" {
            &[
                "machine-validation",
                "on-demand",
                "start",
                "--machine",
                TEST_MACHINE_ID,
            ][..] => Yields((TEST_MACHINE_ID.to_string(), false)),
        }
    );
}

// runs show parses to the Runs::Show variant: with no --machine the filter is
// unset (and --history defaults off), with --machine the filter is present.
#[test]
fn parse_runs_show_machine_filter() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Runs(runs::Args::Show(args)) => (args.machine.is_some(), args.history),
                    _ => panic!("expected Runs Show variant"),
                })
                .map_err(drop)
        };
        "no machine filter (and history defaults off)" {
            &["machine-validation", "runs", "show"][..] => Yields((false, false)),
        }

        "with a machine filter" {
            &[
                "machine-validation",
                "runs",
                "show",
                "--machine",
                TEST_MACHINE_ID,
            ][..] => Yields((true, false)),
        }
    );
}

// results show parses to the Results::Show variant: --machine sets the machine
// filter, --validation-id sets the validation-id filter.
#[test]
fn parse_results_show_filters() {
    let validation_id = MachineValidationId::new();
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Results(results::Args::Show(args)) => {
                        (args.machine.is_some(), args.validation_id)
                    }
                    _ => panic!("expected Results Show variant"),
                })
                .map_err(drop)
        };
        "with a machine filter" {
            &[
                "machine-validation",
                "results",
                "show",
                "--machine",
                TEST_MACHINE_ID,
            ][..] => Yields((true, None)),
        }

        "with a validation-id filter" {
            &[
                "machine-validation",
                "results",
                "show",
                "--validation-id",
                validation_id.to_string().as_str(),
            ][..] => Yields((false, Some(validation_id))),
        }
    );
}

// tests parses to the Tests variant: `show` leaves test-id unset, `verify`
// carries test-id/version, and `add` carries name/command/args.
#[test]
fn parse_tests_subcommands() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Tests(tests_cmd::Args::Show(args)) => {
                        // show: only test-id is meaningful; pad the tuple
                        (args.test_id.is_some(), String::new(), String::new())
                    }
                    Cmd::Tests(tests_cmd::Args::Verify(args)) => {
                        // verify: (present, test-id, version)
                        (true, args.test_id, args.version)
                    }
                    Cmd::Tests(tests_cmd::Args::Add(args)) => {
                        // add: name/command checked here, args asserted below
                        assert_eq!(args.args, "--verbose", "tests add --args");
                        (true, args.name, args.command)
                    }
                    _ => panic!("expected Tests variant"),
                })
                .map_err(drop)
        };
        "show leaves test-id unset" {
            &["machine-validation", "tests", "show"][..] => Yields((false, String::new(), String::new())),
        }

        "verify carries test-id and version" {
            &[
                "machine-validation",
                "tests",
                "verify",
                "--test-id",
                "test-123",
                "--version",
                "v1",
            ][..] => Yields((true, "test-123".to_string(), "v1".to_string())),
        }

        "add carries name, command, and args" {
            &[
                "machine-validation",
                "tests",
                "add",
                "--name",
                "my-test",
                "--command",
                "/bin/test",
                "--args",
                "--verbose",
            ][..] => Yields((true, "my-test".to_string(), "/bin/test".to_string())),
        }
    );
}

// img_name requires a pinned sha256 digest; the tag is optional.
const VALID_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64 hex chars

#[test]
fn parse_tests_add_img_name_validation() {
    let valid_img = format!("nvcr.io/foo/bar:v1.0@sha256:{VALID_DIGEST}");
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Tests(tests_cmd::Args::Add(args)) => args.img_name,
                    _ => panic!("expected Tests Add variant"),
                })
                .map_err(drop)
        };
        "add accepts a pinned digest" {
            &[
                "machine-validation", "tests", "add",
                "--name", "my-test",
                "--command", "/bin/test",
                "--args", "--verbose",
                "--img-name", valid_img.as_str(),
            ][..] => Yields(Some(valid_img.clone())),
        }
        "add accepts :latest tag when digest is present" {
            &[
                "machine-validation", "tests", "add",
                "--name", "my-test",
                "--command", "/bin/test",
                "--args", "--verbose",
                "--img-name", &format!("nvcr.io/foo/bar:latest@sha256:{VALID_DIGEST}"),
            ][..] => Yields(Some(format!("nvcr.io/foo/bar:latest@sha256:{VALID_DIGEST}"))),
        }
        "add rejects missing digest" {
            &[
                "machine-validation", "tests", "add",
                "--name", "my-test",
                "--command", "/bin/test",
                "--args", "--verbose",
                "--img-name", "nvcr.io/foo/bar:v1.0",
            ][..] => Fails,
        }
        "add rejects empty name before @" {
            &[
                "machine-validation", "tests", "add",
                "--name", "my-test",
                "--command", "/bin/test",
                "--args", "--verbose",
                "--img-name", &format!("@sha256:{VALID_DIGEST}"),
            ][..] => Fails,
        }
        "add without img_name is fine" {
            &[
                "machine-validation", "tests", "add",
                "--name", "my-test",
                "--command", "/bin/test",
                "--args", "--verbose",
            ][..] => Yields(None),
        }
    );
}

#[test]
fn parse_tests_update_img_name_validation() {
    let valid_img = format!("nvcr.io/foo/bar:v1.0@sha256:{VALID_DIGEST}");
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Tests(tests_cmd::Args::Update(args)) => args.img_name,
                    _ => panic!("expected Tests Update variant"),
                })
                .map_err(drop)
        };
        "update accepts a pinned digest" {
            &[
                "machine-validation", "tests", "update",
                "--test-id", "my-test",
                "--version", "v1",
                "--img-name", valid_img.as_str(),
            ][..] => Yields(Some(valid_img.clone())),
        }
        "update accepts :latest tag when digest is present" {
            &[
                "machine-validation", "tests", "update",
                "--test-id", "my-test",
                "--version", "v1",
                "--img-name", &format!("nvcr.io/foo/bar:latest@sha256:{VALID_DIGEST}"),
            ][..] => Yields(Some(format!("nvcr.io/foo/bar:latest@sha256:{VALID_DIGEST}"))),
        }
        "update rejects missing digest" {
            &[
                "machine-validation", "tests", "update",
                "--test-id", "my-test",
                "--version", "v1",
                "--img-name", "nvcr.io/foo/bar:v1.0",
            ][..] => Fails,
        }
        "update rejects empty name before @" {
            &[
                "machine-validation", "tests", "update",
                "--test-id", "my-test",
                "--version", "v1",
                "--img-name", &format!("@sha256:{VALID_DIGEST}"),
            ][..] => Fails,
        }
    );
}

// Malformed invocations are rejected at parse time -- results show with none of
// its required filters cannot parse.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "results show without machine/validation_id/test_name" {
            &["machine-validation", "results", "show"][..] => Fails,
        }
    );
}
