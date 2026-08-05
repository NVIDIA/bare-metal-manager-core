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
use crate::test_support::{parse_leaf, raw_value};

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

// config apply routes to Cmd::Config(Apply) for every accepted invocation:
// the long --mode/-m forms, the kebab-case mode values, and the visible `c`
// (config) and `a` (apply) aliases. Each row yields the parsed path; the mode's
// typed value-enum mapping is tested beside its private definition.
#[test]
fn config_apply_parses_path_and_mode() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["config", "apply"])
                .map(|matches| raw_value(&matches, "path").expect("path is required"))
                .map_err(drop)
        };
        "network-segment mode parses path and mode" {
            &[
                "devenv",
                "config",
                "apply",
                "/path/to/config.toml",
                "--mode",
                "network-segment",
            ][..] => Yields("/path/to/config.toml".to_string()),
        }

        "vpc-prefix mode parses" {
            &[
                "devenv",
                "config",
                "apply",
                "/path/to/config.toml",
                "--mode",
                "vpc-prefix",
            ][..] => Yields("/path/to/config.toml".to_string()),
        }

        "-m short flag parses" {
            &[
                "devenv",
                "config",
                "apply",
                "/path/to/config.toml",
                "-m",
                "network-segment",
            ][..] => Yields("/path/to/config.toml".to_string()),
        }

        "config alias 'c' routes to apply" {
            &[
                "devenv",
                "c",
                "apply",
                "/path/to/config.toml",
                "-m",
                "network-segment",
            ][..] => Yields("/path/to/config.toml".to_string()),
        }

        "apply alias 'a' routes to apply" {
            &[
                "devenv",
                "config",
                "a",
                "/path/to/config.toml",
                "-m",
                "network-segment",
            ][..] => Yields("/path/to/config.toml".to_string()),
        }
    );
}

// config apply requires both its positional path and its --mode flag; either
// one missing is rejected at parse time.
#[test]
fn config_apply_rejects_missing_required_args() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "missing path" {
            &["devenv", "config", "apply", "-m", "network-segment"][..] => Fails,
        }

        "missing --mode" {
            &["devenv", "config", "apply", "/path/to/config.toml"][..] => Fails,
        }
    );
}
