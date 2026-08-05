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
use carbide_uuid::rack::RackId;
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

// show parses with or without a rack identifier: bare `show` targets all
// racks (no rack), while a trailing identifier scopes it to that one rack.
#[test]
fn parse_show_routes_to_show_variant() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["show"])
                .map(|matches| {
                    matches
                        .get_one::<RackId>("rack")
                        .map(ToString::to_string)
                })
                .map_err(drop)
        };
        "no args targets all racks" {
            &["rack", "show"][..] => Yields(None),
        }

        "trailing identifier scopes to one rack" {
            &["rack", "show", "rack-123"][..] => Yields(Some("rack-123".to_string())),
        }
    );
}

// parse_list ensures list parses with no arguments.
#[test]
fn parse_list() {
    let cmd = Cmd::try_parse_from(["rack", "list"]).expect("should parse list");

    assert!(matches!(cmd, Cmd::List(_)));
}

// parse_delete ensures delete parses with identifier.
#[test]
fn parse_delete() {
    let matches = parse_leaf::<Cmd>(&["rack", "delete", "rack-123"], &["delete"])
        .expect("should parse delete");

    assert_eq!(
        raw_value(&matches, "identifier").as_deref(),
        Some("rack-123")
    );
}

// parse_state_history ensures state-history parses with rack ID.
#[test]
fn parse_state_history() {
    let matches = parse_leaf::<Cmd>(
        &["rack", "state-history", "ipp6-b03-gb-nvl-124-mini2"],
        &["state-history"],
    )
    .expect("should parse state-history");

    assert_eq!(
        matches
            .get_one::<RackId>("rack_id")
            .map(ToString::to_string)
            .as_deref(),
        Some("ipp6-b03-gb-nvl-124-mini2")
    );
}

// parse_profile_show ensures profile show parses with rack ID.
#[test]
fn parse_profile_show() {
    let matches = parse_leaf::<Cmd>(
        &["rack", "profile", "show", "rack-123"],
        &["profile", "show"],
    )
    .expect("should parse profile show");

    assert_eq!(
        matches
            .get_one::<RackId>("rack_id")
            .map(ToString::to_string)
            .as_deref(),
        Some("rack-123")
    );
}

#[test]
fn parse_profile_list() {
    let cmd = Cmd::try_parse_from(["rack", "profile", "list"]).expect("should parse profile list");

    assert!(matches!(cmd, Cmd::Profile(profile::Args::List(_))));
}

// Every malformed invocation is rejected at parse time -- a delete or a
// profile-show left without its required rack identifier.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "delete without an identifier" {
            &["rack", "delete"][..] => Fails,
        }

        "profile show without a rack_id" {
            &["rack", "profile", "show"][..] => Fails,
        }

        "state-history without a rack_id" {
            &["rack", "state-history"][..] => Fails,
        }
    );
}
