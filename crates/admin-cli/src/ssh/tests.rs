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
// with credentials and routes them onto the credential fields.
#[test]
fn parse_get_rshim_status() {
    check_cases(
        [Case {
            scenario: "get-rshim-status with credentials",
            input: &[
                "ssh",
                "get-rshim-status",
                "192.168.1.100:443",
                "admin",
                "password123",
            ][..],
            expect: Yields((
                "192.168.1.100:443".to_string(),
                "admin".to_string(),
                "password123".to_string(),
            )),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::GetRshimStatus(args) => (
                        args.inner.credentials.bmc_ip_address.to_string(),
                        args.inner.credentials.bmc_username,
                        args.inner.credentials.bmc_password,
                    ),
                    _ => panic!("expected GetRshimStatus variant"),
                })
                .map_err(drop)
        },
    );
}

// parse_copy_bfb ensures copy-bfb parses with bfb_path.
#[test]
fn parse_copy_bfb() {
    check_cases(
        [Case {
            scenario: "copy-bfb with bfb path",
            input: &[
                "ssh",
                "copy-bfb",
                "192.168.1.100:443",
                "admin",
                "password123",
                "/path/to/image.bfb",
            ][..],
            expect: Yields("/path/to/image.bfb".to_string()),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::CopyBfb(args) => args.bfb_path,
                    _ => panic!("expected CopyBfb variant"),
                })
                .map_err(drop)
        },
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

    check_cases(
        [
            Case {
                scenario: "disable-rshim routes to DisableRshim",
                input: &[
                    "ssh",
                    "disable-rshim",
                    "192.168.1.100:443",
                    "admin",
                    "password123",
                ][..],
                expect: Yields("disable-rshim"),
            },
            Case {
                scenario: "enable-rshim routes to EnableRshim",
                input: &[
                    "ssh",
                    "enable-rshim",
                    "192.168.1.100:443",
                    "admin",
                    "password123",
                ][..],
                expect: Yields("enable-rshim"),
            },
            Case {
                scenario: "show-obmc-log routes to ShowObmcLog",
                input: &[
                    "ssh",
                    "show-obmc-log",
                    "192.168.1.100:443",
                    "admin",
                    "password123",
                ][..],
                expect: Yields("show-obmc-log"),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| variant(&cmd))
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "get-rshim-status without username and password",
            input: &["ssh", "get-rshim-status", "192.168.1.100:443"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
