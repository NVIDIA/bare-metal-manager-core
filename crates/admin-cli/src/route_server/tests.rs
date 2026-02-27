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
// ValueEnum Parsing - Test clap ValueEnum translations (if applicable).

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

// parse_get_no_args ensures get parses with no arguments.
#[test]
fn parse_get_no_args() {
    let cmd = Cmd::try_parse_from(["route-server", "get"]).expect("should parse get");

    assert!(matches!(cmd, Cmd::Get(_)));
}

// parse_add_single_ip ensures add parses with a single
// IP address.
#[test]
fn parse_add_single_ip() {
    let cmd = Cmd::try_parse_from(["route-server", "add", "192.168.1.1"])
        .expect("should parse add with single IP");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.inner.ip.len(), 1);
            assert_eq!(args.inner.ip[0].to_string(), "192.168.1.1");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_multiple_ips ensures add parses with
// comma-separated IP addresses.
#[test]
fn parse_add_multiple_ips() {
    let cmd = Cmd::try_parse_from(["route-server", "add", "192.168.1.1,192.168.1.2,10.0.0.1"])
        .expect("should parse add with multiple IPs");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.inner.ip.len(), 3);
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_remove_with_ip ensures remove parses with
// IP address.
#[test]
fn parse_remove_with_ip() {
    let cmd = Cmd::try_parse_from(["route-server", "remove", "192.168.1.1"])
        .expect("should parse remove");

    assert!(matches!(cmd, Cmd::Remove(_)));
}

// parse_replace_with_ip ensures replace parses with
// IP address.
#[test]
fn parse_replace_with_ip() {
    let cmd = Cmd::try_parse_from(["route-server", "replace", "192.168.1.1"])
        .expect("should parse replace");

    assert!(matches!(cmd, Cmd::Replace(_)));
}

// parse_add_no_ips ensures add parses with no
// IP addresses (empty list).
#[test]
fn parse_add_no_ips() {
    let cmd = Cmd::try_parse_from(["route-server", "add"]).expect("should parse add with no IPs");

    match cmd {
        Cmd::Add(args) => {
            assert!(args.inner.ip.is_empty());
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_remove_no_ips ensures remove parses with no
// IP addresses (empty list).
#[test]
fn parse_remove_no_ips() {
    let cmd =
        Cmd::try_parse_from(["route-server", "remove"]).expect("should parse remove with no IPs");

    match cmd {
        Cmd::Remove(args) => {
            assert!(args.inner.ip.is_empty());
        }
        _ => panic!("expected Remove variant"),
    }
}

// parse_replace_no_ips ensures replace parses with no
// IP addresses (empty list).
#[test]
fn parse_replace_no_ips() {
    let cmd =
        Cmd::try_parse_from(["route-server", "replace"]).expect("should parse replace with no IPs");

    match cmd {
        Cmd::Replace(args) => {
            assert!(args.inner.ip.is_empty());
        }
        _ => panic!("expected Replace variant"),
    }
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// This section tests clap ValueEnum translations for the
// source_type argument.

// parse_add_with_source_type_admin_api ensures add parses
// with --source-type admin_api.
#[test]
fn parse_add_with_source_type_admin_api() {
    let cmd = Cmd::try_parse_from([
        "route-server",
        "add",
        "192.168.1.1",
        "--source-type",
        "admin_api",
    ])
    .expect("should parse add with source-type admin_api");

    match cmd {
        Cmd::Add(args) => {
            // AdminApi = 1 in the proto enum
            assert_eq!(args.inner.source_type as i32, 1);
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_with_source_type_config_file ensures add
// parses with --source-type config_file.
#[test]
fn parse_add_with_source_type_config_file() {
    let cmd = Cmd::try_parse_from([
        "route-server",
        "add",
        "192.168.1.1",
        "--source-type",
        "config_file",
    ])
    .expect("should parse add with source-type config_file");

    match cmd {
        Cmd::Add(args) => {
            // ConfigFile = 0 in the proto enum
            assert_eq!(args.inner.source_type as i32, 0);
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_invalid_source_type_fails ensures add fails
// with invalid source-type value.
#[test]
fn parse_add_invalid_source_type_fails() {
    let result = Cmd::try_parse_from([
        "route-server",
        "add",
        "192.168.1.1",
        "--source-type",
        "invalid",
    ]);
    assert!(result.is_err(), "should fail with invalid source-type");
}

// parse_add_invalid_ip_fails ensures add fails with
// invalid IP address format.
#[test]
fn parse_add_invalid_ip_fails() {
    let result = Cmd::try_parse_from(["route-server", "add", "not-an-ip"]);
    assert!(result.is_err(), "should fail with invalid IP");
}
