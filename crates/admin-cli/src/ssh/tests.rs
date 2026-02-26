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

// parse_get_rshim_status ensures get-rshim-status parses
// with credentials.
#[test]
fn parse_get_rshim_status() {
    let cmd = Cmd::try_parse_from([
        "ssh",
        "get-rshim-status",
        "192.168.1.100:443",
        "admin",
        "password123",
    ])
    .expect("should parse get-rshim-status");

    match cmd {
        Cmd::GetRshimStatus(args) => {
            assert_eq!(
                args.inner.credentials.bmc_ip_address.to_string(),
                "192.168.1.100:443"
            );
            assert_eq!(args.inner.credentials.bmc_username, "admin");
            assert_eq!(args.inner.credentials.bmc_password, "password123");
        }
        _ => panic!("expected GetRshimStatus variant"),
    }
}

// parse_disable_rshim ensures disable-rshim parses correctly.
#[test]
fn parse_disable_rshim() {
    let cmd = Cmd::try_parse_from([
        "ssh",
        "disable-rshim",
        "192.168.1.100:443",
        "admin",
        "password123",
    ])
    .expect("should parse disable-rshim");

    assert!(matches!(cmd, Cmd::DisableRshim(_)));
}

// parse_enable_rshim ensures enable-rshim parses correctly.
#[test]
fn parse_enable_rshim() {
    let cmd = Cmd::try_parse_from([
        "ssh",
        "enable-rshim",
        "192.168.1.100:443",
        "admin",
        "password123",
    ])
    .expect("should parse enable-rshim");

    assert!(matches!(cmd, Cmd::EnableRshim(_)));
}

// parse_copy_bfb ensures copy-bfb parses with bfb_path.
#[test]
fn parse_copy_bfb() {
    let cmd = Cmd::try_parse_from([
        "ssh",
        "copy-bfb",
        "192.168.1.100:443",
        "admin",
        "password123",
        "/path/to/image.bfb",
    ])
    .expect("should parse copy-bfb");

    match cmd {
        Cmd::CopyBfb(args) => {
            assert_eq!(args.bfb_path, "/path/to/image.bfb");
        }
        _ => panic!("expected CopyBfb variant"),
    }
}

// parse_show_obmc_log ensures show-obmc-log parses correctly.
#[test]
fn parse_show_obmc_log() {
    let cmd = Cmd::try_parse_from([
        "ssh",
        "show-obmc-log",
        "192.168.1.100:443",
        "admin",
        "password123",
    ])
    .expect("should parse show-obmc-log");

    assert!(matches!(cmd, Cmd::ShowObmcLog(_)));
}

// parse_missing_credentials_fails ensures subcommands
// require all credentials.
#[test]
fn parse_missing_credentials_fails() {
    let result = Cmd::try_parse_from(["ssh", "get-rshim-status", "192.168.1.100:443"]);
    assert!(result.is_err(), "should fail without username and password");
}
