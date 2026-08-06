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
use carbide_uuid::instance::InstanceId;
use carbide_uuid::vpc::VpcId;
use clap::CommandFactory;

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

// create routes to the Create variant and threads through the tenant org id
// plus its optional id/name/stateful-egress flags: bare invocation leaves the
// options unset, the fully-flagged invocation carries them through.
#[test]
fn parse_create_routes_to_create_variant() {
    scenarios!(
        run = |argv| {
            let matches = parse_leaf::<Cmd>(argv, &["create"]).map_err(drop)?;
            Ok::<_, ()>((
                raw_value(&matches, "tenant_organization_id")
                    .expect("tenant organization ID is required"),
                raw_value(&matches, "id"),
                raw_value(&matches, "name"),
                matches.get_flag("stateful_egress"),
            ))
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
            let matches = parse_leaf::<Cmd>(argv, &["show"]).map_err(drop)?;
            Ok::<_, ()>(raw_value(&matches, "id"))
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
            let matches = parse_leaf::<Cmd>(argv, &["delete"]).map_err(drop)?;
            Ok::<_, ()>((
                raw_value(&matches, "id").expect("network security group ID is required"),
                raw_value(&matches, "tenant_organization_id")
                    .expect("tenant organization ID is required"),
            ))
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
            let matches = parse_leaf::<Cmd>(argv, &["update"]).map_err(drop)?;
            Ok::<_, ()>((
                raw_value(&matches, "id").expect("network security group ID is required"),
                raw_value(&matches, "tenant_organization_id")
                    .expect("tenant organization ID is required"),
            ))
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
            let matches = parse_leaf::<Cmd>(argv, &["show-attachments"]).map_err(drop)?;
            Ok::<_, ()>((
                raw_value(&matches, "id").expect("network security group ID is required"),
                matches.get_flag("include_indirect"),
            ))
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
            let matches = parse_leaf::<Cmd>(argv, &["attach"]).map_err(drop)?;
            Ok::<_, ()>((
                raw_value(&matches, "id").expect("network security group ID is required"),
                matches.get_one::<VpcId>("vpc_id").copied(),
                matches.get_one::<InstanceId>("instance_id").copied(),
            ))
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
            let matches = parse_leaf::<Cmd>(argv, &["detach"]).map_err(drop)?;
            Ok::<_, ()>((
                matches.get_one::<VpcId>("vpc_id").copied(),
                matches.get_one::<InstanceId>("instance_id").copied(),
            ))
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
            Cmd::command()
                .try_get_matches_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create without --tenant-organization-id" {
            &["network-security-group", "create"][..] => Fails,
        }
    );
}
