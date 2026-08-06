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

use std::net::SocketAddr;

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

// parse_get_rshim_status ensures get-rshim-status parses
// with credentials and routes them onto the credential fields.
#[test]
fn parse_get_rshim_status() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["get-rshim-status"])
                .map(|matches| {
                    (
                        *matches
                            .get_one::<SocketAddr>("bmc_ip_address")
                            .expect("BMC IP address is required"),
                        raw_value(&matches, "bmc_username").expect("BMC username is required"),
                        raw_value(&matches, "bmc_password").expect("BMC password is required"),
                    )
                })
                .map_err(drop)
        };
        "get-rshim-status with credentials" {
            &[
                "ssh",
                "get-rshim-status",
                "192.168.1.100:443",
                "admin",
                "password123",
            ][..] => Yields((
                "192.168.1.100:443".parse::<SocketAddr>().unwrap(),
                "admin".to_string(),
                "password123".to_string(),
            )),
        }
    );
}

// parse_copy_bfb ensures copy-bfb parses with bfb_path.
#[test]
fn parse_copy_bfb() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["copy-bfb"])
                .map(|matches| raw_value(&matches, "bfb_path").expect("BFB path is required"))
                .map_err(drop)
        };
        "copy-bfb with bfb path" {
            &[
                "ssh",
                "copy-bfb",
                "192.168.1.100:443",
                "admin",
                "password123",
                "/path/to/image.bfb",
            ][..] => Yields("/path/to/image.bfb".to_string()),
        }
    );
}

// Credential-only subcommands route a valid argv onto their own Cmd variant.
#[test]
fn credential_subcommands_route_to_variant() {
    fn variant(cmd: &Cmd) -> &'static str {
        match cmd {
            Cmd::DisableRshim(_) => "disable-rshim",
            Cmd::EnableRshim(_) => "enable-rshim",
            Cmd::ShowObmcLog(_) => "show-obmc-log",
            _ => panic!("expected a credential-only subcommand variant"),
        }
    }

    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        };
        "disable-rshim routes to DisableRshim" {
            &[
                "ssh",
                "disable-rshim",
                "192.168.1.100:443",
                "admin",
                "password123",
            ][..] => Yields("disable-rshim"),
        }

        "enable-rshim routes to EnableRshim" {
            &[
                "ssh",
                "enable-rshim",
                "192.168.1.100:443",
                "admin",
                "password123",
            ][..] => Yields("enable-rshim"),
        }

        "show-obmc-log routes to ShowObmcLog" {
            &[
                "ssh",
                "show-obmc-log",
                "192.168.1.100:443",
                "admin",
                "password123",
            ][..] => Yields("show-obmc-log"),
        }
    );
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "get-rshim-status without username and password" {
            &["ssh", "get-rshim-status", "192.168.1.100:443"][..] => Fails,
        }
    );
}
