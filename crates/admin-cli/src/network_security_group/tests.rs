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

// create routes to the Create variant and threads through the tenant org id
// plus its optional id/name/stateful-egress flags: bare invocation leaves the
// options unset, the fully-flagged invocation carries them through.
#[test]
fn parse_create_routes_to_create_variant() {
    check_cases(
        [
            Case {
                scenario: "create with only the required tenant org id",
                input: &[
                    "network-security-group",
                    "create",
                    "--tenant-organization-id",
                    "tenant-123",
                ][..],
                expect: Yields(("tenant-123".to_string(), None, None, false)),
            },
            Case {
                scenario: "create with all options",
                input: &[
                    "network-security-group",
                    "create",
                    "--tenant-organization-id",
                    "tenant-123",
                    "--id",
                    "nsg-123",
                    "--name",
                    "my-nsg",
                    "--description",
                    "Test NSG",
                    "--stateful-egress",
                ][..],
                expect: Yields((
                    "tenant-123".to_string(),
                    Some("nsg-123".to_string()),
                    Some("my-nsg".to_string()),
                    true,
                )),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Create(args) => (
                        args.tenant_organization_id,
                        args.id,
                        args.name,
                        args.stateful_egress,
                    ),
                    _ => panic!("expected Create variant"),
                })
                .map_err(drop)
        },
    );
}

// show routes to the Show variant with an optional positional id: bare leaves
// it unset, a supplied id is captured.
#[test]
fn parse_show_routes_to_show_variant() {
    check_cases(
        [
            Case {
                scenario: "show with no args (all groups)",
                input: &["network-security-group", "show"][..],
                expect: Yields(None),
            },
            Case {
                scenario: "show with a group id",
                input: &["network-security-group", "show", "nsg-123"][..],
                expect: Yields(Some("nsg-123".to_string())),
            },
        ],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => args.id,
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        },
    );
}

// delete routes to the Delete variant, threading through the required id and
// tenant org id.
#[test]
fn parse_delete_routes_to_delete_variant() {
    check_cases(
        [Case {
            scenario: "delete with required id and tenant org id",
            input: &[
                "network-security-group",
                "delete",
                "--id",
                "nsg-123",
                "--tenant-organization-id",
                "tenant-123",
            ][..],
            expect: Yields(("nsg-123".to_string(), "tenant-123".to_string())),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => (args.id, args.tenant_organization_id),
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        },
    );
}

// update routes to the Update variant, threading through the required id and
// tenant org id.
#[test]
fn parse_update_routes_to_update_variant() {
    check_cases(
        [Case {
            scenario: "update with required id and tenant org id",
            input: &[
                "network-security-group",
                "update",
                "--id",
                "nsg-123",
                "--tenant-organization-id",
                "tenant-123",
            ][..],
            expect: Yields(("nsg-123".to_string(), "tenant-123".to_string())),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Update(args) => (args.id, args.tenant_organization_id),
                    _ => panic!("expected Update variant"),
                })
                .map_err(drop)
        },
    );
}

// show-attachments routes to the ShowAttachments variant, threading through the
// required id; --include-indirect defaults off.
#[test]
fn parse_show_attachments_routes_to_show_attachments_variant() {
    check_cases(
        [Case {
            scenario: "show-attachments with required id",
            input: &[
                "network-security-group",
                "show-attachments",
                "--id",
                "nsg-123",
            ][..],
            expect: Yields(("nsg-123".to_string(), false)),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::ShowAttachments(args) => (args.id, args.include_indirect),
                    _ => panic!("expected ShowAttachments variant"),
                })
                .map_err(drop)
        },
    );
}

// attach routes to the Attach variant, threading through the required NSG id;
// the optional vpc/instance targets default unset.
#[test]
fn parse_attach_routes_to_attach_variant() {
    check_cases(
        [Case {
            scenario: "attach with NSG id",
            input: &["network-security-group", "attach", "--id", "nsg-123"][..],
            expect: Yields(("nsg-123".to_string(), None, None)),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Attach(args) => (args.id, args.vpc_id, args.instance_id),
                    _ => panic!("expected Attach variant"),
                })
                .map_err(drop)
        },
    );
}

// detach routes to the Detach variant with no required args; the optional
// vpc/instance targets default unset.
#[test]
fn parse_detach_routes_to_detach_variant() {
    check_cases(
        [Case {
            scenario: "detach with no required args",
            input: &["network-security-group", "detach"][..],
            expect: Yields((None, None)),
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Detach(args) => (args.vpc_id, args.instance_id),
                    _ => panic!("expected Detach variant"),
                })
                .map_err(drop)
        },
    );
}

// Every malformed invocation is rejected at parse time -- here, create without
// its required --tenant-organization-id.
#[test]
fn invalid_invocations_are_rejected() {
    check_cases(
        [Case {
            scenario: "create without --tenant-organization-id",
            input: &["network-security-group", "create"][..],
            expect: Fails,
        }],
        |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        },
    );
}
