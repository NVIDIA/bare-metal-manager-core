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
// command, including things like basic structure parsing and any
// external input validators that are configured. Specific
// "categories" are:
//
// Command Structure - Baseline debug_assert() of the entire command.
// Argument Parsing  - Ensure required/optional arg combinations parse correctly.
// Routing Profile Parsing - Ensure profile strings are accepted unchanged.

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

// show parses with or without the optional positional tenant_org; the parsed
// value flows straight through, so each row yields the resulting Option.
#[test]
fn parse_show_tenant_org() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Show(args)) => Ok(args.tenant_org),
            Ok(_) => panic!("expected Show variant"),
            Err(_) => Err(()),
        };
        "no arguments" {
            &["tenant", "show"][..] => Yields(None),
        }

        "with tenant_org" {
            &["tenant", "show", "org-123"][..] => Yields(Some("org-123".to_string())),
        }
    );
}

// update parses with a required tenant_org plus optional -p/-v/-n flags; each
// row yields the full (tenant_org, routing_profile_type, version, name) tuple.
#[test]
fn parse_update_fields() {
    scenarios!(
        run = |argv| match Cmd::try_parse_from(argv.iter().copied()) {
            Ok(Cmd::Update(args)) => Ok((
                args.tenant_org,
                args.routing_profile_type,
                args.version,
                args.name,
            )),
            Ok(_) => panic!("expected Update variant"),
            Err(_) => Err(()),
        };
        "tenant_org only" {
            &["tenant", "update", "org-123"][..] => Yields(("org-123".to_string(), None, None, None)),
        }

        "with -p routing profile" {
            &["tenant", "update", "org-123", "-p", "profile-a"][..] => Yields((
                "org-123".to_string(),
                Some("profile-a".to_string()),
                None,
                None,
            )),
        }

        "with -v version" {
            &["tenant", "update", "org-123", "-v", "1.0"][..] => Yields(("org-123".to_string(), None, Some("1.0".to_string()), None)),
        }

        "with -n name" {
            &["tenant", "update", "org-123", "-n", "New Name"][..] => Yields((
                "org-123".to_string(),
                None,
                None,
                Some("New Name".to_string()),
            )),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, update with its
// required tenant_org positional omitted.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "update without tenant_org" {
            &["tenant", "update"][..] => Fails,
        }
    );
}
