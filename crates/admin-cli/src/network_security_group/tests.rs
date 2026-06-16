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

// create routes to the Create variant and threads through the tenant org id
// plus its optional id/name/stateful-egress flags: bare invocation leaves the
// options unset, the fully-flagged invocation carries them through.
#[test]
fn parse_create_routes_to_create_variant() {
    scenarios!(
        run = |argv| {
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
        };
        "create with only the required tenant org id" {
            &[
                "network-security-group",
                "create",
                "--tenant-organization-id",
                "tenant-123",
            ][..] => Yields(("tenant-123".to_string(), None, None, false)),
        }

        "create with all options" {
            &[
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
            ][..] => Yields((
                "tenant-123".to_string(),
                Some("nsg-123".to_string()),
                Some("my-nsg".to_string()),
                true,
            )),
        }
    );
}

// show routes to the Show variant with an optional positional id: bare leaves
// it unset, a supplied id is captured.
#[test]
fn parse_show_routes_to_show_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Show(args) => args.id,
                    _ => panic!("expected Show variant"),
                })
                .map_err(drop)
        };
        "show with no args (all groups)" {
            &["network-security-group", "show"][..] => Yields(None),
        }

        "show with a group id" {
            &["network-security-group", "show", "nsg-123"][..] => Yields(Some("nsg-123".to_string())),
        }
    );
}

// delete routes to the Delete variant, threading through the required id and
// tenant org id.
#[test]
fn parse_delete_routes_to_delete_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Delete(args) => (args.id, args.tenant_organization_id),
                    _ => panic!("expected Delete variant"),
                })
                .map_err(drop)
        };
        "delete with required id and tenant org id" {
            &[
                "network-security-group",
                "delete",
                "--id",
                "nsg-123",
                "--tenant-organization-id",
                "tenant-123",
            ][..] => Yields(("nsg-123".to_string(), "tenant-123".to_string())),
        }
    );
}

// update routes to the Update variant, threading through the required id and
// tenant org id.
#[test]
fn parse_update_routes_to_update_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Update(args) => (args.id, args.tenant_organization_id),
                    _ => panic!("expected Update variant"),
                })
                .map_err(drop)
        };
        "update with required id and tenant org id" {
            &[
                "network-security-group",
                "update",
                "--id",
                "nsg-123",
                "--tenant-organization-id",
                "tenant-123",
            ][..] => Yields(("nsg-123".to_string(), "tenant-123".to_string())),
        }
    );
}

// show-attachments routes to the ShowAttachments variant, threading through the
// required id; --include-indirect defaults off.
#[test]
fn parse_show_attachments_routes_to_show_attachments_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::ShowAttachments(args) => (args.id, args.include_indirect),
                    _ => panic!("expected ShowAttachments variant"),
                })
                .map_err(drop)
        };
        "show-attachments with required id" {
            &[
                "network-security-group",
                "show-attachments",
                "--id",
                "nsg-123",
            ][..] => Yields(("nsg-123".to_string(), false)),
        }
    );
}

// attach routes to the Attach variant, threading through the required NSG id;
// the optional vpc/instance targets default unset.
#[test]
fn parse_attach_routes_to_attach_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Attach(args) => (args.id, args.vpc_id, args.instance_id),
                    _ => panic!("expected Attach variant"),
                })
                .map_err(drop)
        };
        "attach with NSG id" {
            &["network-security-group", "attach", "--id", "nsg-123"][..] => Yields(("nsg-123".to_string(), None, None)),
        }
    );
}

// detach routes to the Detach variant with no required args; the optional
// vpc/instance targets default unset.
#[test]
fn parse_detach_routes_to_detach_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Detach(args) => (args.vpc_id, args.instance_id),
                    _ => panic!("expected Detach variant"),
                })
                .map_err(drop)
        };
        "detach with no required args" {
            &["network-security-group", "detach"][..] => Yields((None, None)),
        }
    );
}

// Every malformed invocation is rejected at parse time -- here, create without
// its required --tenant-organization-id.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create without --tenant-organization-id" {
            &["network-security-group", "create"][..] => Fails,
        }
    );
}
