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
use carbide_test_support::{Case, check_cases};
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

// Each supported shell name parses to its matching `Shell` variant.
#[test]
fn shell_names_parse_to_their_variant() {
    fn shell(s: &Shell) -> &'static str {
        match s {
            Shell::Bash => "bash",
            Shell::Fish => "fish",
            Shell::Zsh => "zsh",
        }
    }

    check_cases(
        [
            Case {
                scenario: "bash subcommand",
                input: &["generate-shell-complete", "bash"][..],
                expect: Yields("bash"),
            },
            Case {
                scenario: "fish subcommand",
                input: &["generate-shell-complete", "fish"][..],
                expect: Yields("fish"),
            },
            Case {
                scenario: "zsh subcommand",
                input: &["generate-shell-complete", "zsh"][..],
                expect: Yields("zsh"),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| shell(&cmd.shell))
                .map_err(drop)
        },
    );
}

// A shell subcommand is required, and an unknown shell is rejected.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [
            Case {
                scenario: "missing shell subcommand",
                input: &["generate-shell-complete"][..],
                expect: Fails,
            },
            Case {
                scenario: "unknown shell",
                input: &["generate-shell-complete", "powershell"][..],
                expect: Fails,
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
