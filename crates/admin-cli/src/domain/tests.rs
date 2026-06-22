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

// show parses with or without the (deprecated) --all flag; bare `show` means
// all domains with no specific domain selected, and --all flips the flag. Each
// row yields the `(all, domain.is_some())` pair the originals asserted.
#[test]
fn parse_show_variants() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => (args.all, args.domain.is_some()),
                    other => unreachable!("show inputs only parse to Cmd::Show, got {other:?}"),
                })
                .map_err(drop)
        };
        "no arguments (all domains)" {
            &["domain", "show"][..] => Yields((false, false)),
        }

        "--all flag (deprecated)" {
            &["domain", "show", "--all"][..] => Yields((true, false)),
        }
    );
}

// create takes a single positional domain name and requires it.
#[test]
fn parse_create_variants() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => args.name,
                    other => unreachable!("create inputs only parse to Cmd::Create, got {other:?}"),
                })
                .map_err(drop)
        };
        "create takes a domain name" {
            &["domain", "create", "168.192.in-addr.arpa"][..]
                => Yields("168.192.in-addr.arpa".to_string()),
        }
        "create requires a name" {
            &["domain", "create"][..] => Fails,
        }
    );
}

// create-reverse takes a single positional CIDR; clap rejects a non-CIDR.
#[test]
fn parse_create_reverse_variants() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::CreateReverse(args) => args.cidr.to_string(),
                    other => unreachable!(
                        "create-reverse inputs only parse to Cmd::CreateReverse, got {other:?}"
                    ),
                })
                .map_err(drop)
        };
        "create-reverse takes a CIDR" {
            &["domain", "create-reverse", "192.168.0.0/16"][..]
                => Yields("192.168.0.0/16".to_string()),
        }
        "create-reverse rejects a non-CIDR" {
            &["domain", "create-reverse", "not-a-cidr"][..] => Fails,
        }
        "create-reverse requires a CIDR" {
            &["domain", "create-reverse"][..] => Fails,
        }
    );
}
