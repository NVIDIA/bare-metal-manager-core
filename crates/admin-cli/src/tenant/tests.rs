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
use crate::tenant::common::TenantRoutingProfileType;

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

// parse_show_no_args ensures show parses with no arguments.
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["tenant", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.tenant_org.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_tenant_org ensures show parses with tenant_org.
#[test]
fn parse_show_with_tenant_org() {
    let cmd =
        Cmd::try_parse_from(["tenant", "show", "org-123"]).expect("should parse show with tenant");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.tenant_org, Some("org-123".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_update ensures update parses with tenant_org.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123"]).expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.tenant_org, "org-123");
            assert!(args.routing_profile_type.is_none());
            assert!(args.version.is_none());
            assert!(args.name.is_none());
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_update_with_routing_profile ensures update parses
// with -p routing profile.
#[test]
fn parse_update_with_routing_profile() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "internal"])
        .expect("should parse update with routing profile");

    match cmd {
        Cmd::Update(args) => {
            assert!(matches!(
                args.routing_profile_type,
                Some(TenantRoutingProfileType::Internal)
            ));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_update_with_version ensures update parses with -v version.
#[test]
fn parse_update_with_version() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-v", "1.0"])
        .expect("should parse update with version");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.version, Some("1.0".to_string()));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_update_with_name ensures update parses with -n name.
#[test]
fn parse_update_with_name() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-n", "New Name"])
        .expect("should parse update with name");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.name, Some("New Name".to_string()));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_update_missing_tenant_org_fails ensures update
// fails without tenant_org.
#[test]
fn parse_update_missing_tenant_org_fails() {
    let result = Cmd::try_parse_from(["tenant", "update"]);
    assert!(result.is_err(), "should fail without tenant_org");
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// parse_routing_profile_internal ensures internal routing
// profile parses.
#[test]
fn parse_routing_profile_internal() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "internal"])
        .expect("should parse");

    match cmd {
        Cmd::Update(args) => {
            assert!(matches!(
                args.routing_profile_type,
                Some(TenantRoutingProfileType::Internal)
            ));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_routing_profile_privileged_internal ensures
// privileged-internal routing profile parses.
#[test]
fn parse_routing_profile_privileged_internal() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "privileged-internal"])
        .expect("should parse");

    match cmd {
        Cmd::Update(args) => {
            assert!(matches!(
                args.routing_profile_type,
                Some(TenantRoutingProfileType::PrivilegedInternal)
            ));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_routing_profile_external ensures external routing
// profile parses.
#[test]
fn parse_routing_profile_external() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "external"])
        .expect("should parse");

    match cmd {
        Cmd::Update(args) => {
            assert!(matches!(
                args.routing_profile_type,
                Some(TenantRoutingProfileType::External)
            ));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_routing_profile_maintenance ensures maintenance
// routing profile parses.
#[test]
fn parse_routing_profile_maintenance() {
    let cmd = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "maintenance"])
        .expect("should parse");

    match cmd {
        Cmd::Update(args) => {
            assert!(matches!(
                args.routing_profile_type,
                Some(TenantRoutingProfileType::Maintenance)
            ));
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_routing_profile_invalid_fails ensures invalid
// routing profile fails.
#[test]
fn parse_routing_profile_invalid_fails() {
    let result = Cmd::try_parse_from(["tenant", "update", "org-123", "-p", "invalid"]);
    assert!(result.is_err(), "should fail with invalid routing profile");
}
