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

// parse_config_apply_network_segment ensures config
// apply parses with network-segment mode.
#[test]
fn parse_config_apply_network_segment() {
    let cmd = Cmd::try_parse_from([
        "devenv",
        "config",
        "apply",
        "/path/to/config.toml",
        "--mode",
        "network-segment",
    ])
    .expect("should parse config apply");

    match cmd {
        Cmd::Config(config::Cmd::Apply(args)) => {
            assert_eq!(args.path, "/path/to/config.toml");
            assert_eq!(args.mode, config::NetworkChoice::NetworkSegment);
        }
    }
}

// parse_config_apply_vpc_prefix ensures config apply
// parses with vpc-prefix mode.
#[test]
fn parse_config_apply_vpc_prefix() {
    let cmd = Cmd::try_parse_from([
        "devenv",
        "config",
        "apply",
        "/path/to/config.toml",
        "--mode",
        "vpc-prefix",
    ])
    .expect("should parse config apply with vpc-prefix");

    match cmd {
        Cmd::Config(config::Cmd::Apply(args)) => {
            assert_eq!(args.mode, config::NetworkChoice::VpcPrefix);
        }
    }
}

// parse_config_apply_short_mode ensures config apply
// parses with -m short flag.
#[test]
fn parse_config_apply_short_mode() {
    let cmd = Cmd::try_parse_from([
        "devenv",
        "config",
        "apply",
        "/path/to/config.toml",
        "-m",
        "network-segment",
    ])
    .expect("should parse with -m");

    match cmd {
        Cmd::Config(config::Cmd::Apply(args)) => {
            assert_eq!(args.mode, config::NetworkChoice::NetworkSegment);
        }
    }
}

// parse_config_alias ensures config has visible alias 'c'.
#[test]
fn parse_config_alias() {
    let cmd = Cmd::try_parse_from([
        "devenv",
        "c",
        "apply",
        "/path/to/config.toml",
        "-m",
        "network-segment",
    ])
    .expect("should parse via config alias");

    assert!(matches!(cmd, Cmd::Config(_)));
}

// parse_apply_alias ensures apply has visible alias 'a'.
#[test]
fn parse_apply_alias() {
    let cmd = Cmd::try_parse_from([
        "devenv",
        "config",
        "a",
        "/path/to/config.toml",
        "-m",
        "network-segment",
    ])
    .expect("should parse via apply alias");

    assert!(matches!(cmd, Cmd::Config(config::Cmd::Apply(_))));
}

// parse_missing_path_fails ensures config apply
// requires path.
#[test]
fn parse_missing_path_fails() {
    let result = Cmd::try_parse_from(["devenv", "config", "apply", "-m", "network-segment"]);
    assert!(result.is_err(), "should fail without path");
}

// parse_missing_mode_fails ensures config apply
// requires --mode.
#[test]
fn parse_missing_mode_fails() {
    let result = Cmd::try_parse_from(["devenv", "config", "apply", "/path/to/config.toml"]);
    assert!(result.is_err(), "should fail without --mode");
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// network_choice_value_enum ensures NetworkChoice parses
// from kebab-case strings.
#[test]
fn network_choice_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        config::NetworkChoice::from_str("network-segment", false),
        Ok(config::NetworkChoice::NetworkSegment)
    ));
    assert!(matches!(
        config::NetworkChoice::from_str("vpc-prefix", false),
        Ok(config::NetworkChoice::VpcPrefix)
    ));
    assert!(config::NetworkChoice::from_str("invalid", false).is_err());
}
