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
//
// Command Structure - Baseline debug_assert() of the entire command.
// Argument Parsing  - Ensure required/optional arg combinations parse correctly.

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

// parse_find_with_valid_ip ensures find parses a valid
// IPv4 address.
#[test]
fn parse_find_with_valid_ip() {
    let cmd = Cmd::try_parse_from(["ip", "find", "192.168.1.100"]).expect("should parse find");

    match cmd {
        Cmd::Find(args) => {
            assert_eq!(args.ip.to_string(), "192.168.1.100");
        }
    }
}

// parse_find_with_different_ips ensures find parses
// various valid IPs.
#[test]
fn parse_find_with_different_ips() {
    let cmd1 = Cmd::try_parse_from(["ip", "find", "10.0.0.1"]).expect("should parse 10.x IP");
    match cmd1 {
        Cmd::Find(args) => assert_eq!(args.ip.to_string(), "10.0.0.1"),
    }

    let cmd2 = Cmd::try_parse_from(["ip", "find", "172.16.0.1"]).expect("should parse 172.x IP");
    match cmd2 {
        Cmd::Find(args) => assert_eq!(args.ip.to_string(), "172.16.0.1"),
    }

    let cmd3 = Cmd::try_parse_from(["ip", "find", "0.0.0.0"]).expect("should parse 0.0.0.0");
    match cmd3 {
        Cmd::Find(args) => assert_eq!(args.ip.to_string(), "0.0.0.0"),
    }
}

// parse_find_invalid_ip_fails ensures find fails with
// invalid IP.
#[test]
fn parse_find_invalid_ip_fails() {
    let result = Cmd::try_parse_from(["ip", "find", "not-an-ip"]);
    assert!(result.is_err(), "should fail with invalid IP");
}

// parse_find_ipv6 ensures find parses a valid IPv6 address.
#[test]
fn parse_find_ipv6() {
    let cmd = Cmd::try_parse_from(["ip", "find", "::1"]).expect("should parse IPv6 address");
    match cmd {
        Cmd::Find(args) => assert_eq!(args.ip.to_string(), "::1"),
    }
}

// parse_find_missing_ip_fails ensures find requires
// ip argument.
#[test]
fn parse_find_missing_ip_fails() {
    let result = Cmd::try_parse_from(["ip", "find"]);
    assert!(result.is_err(), "should fail without IP argument");
}
