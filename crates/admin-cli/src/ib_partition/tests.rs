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
use carbide_uuid::infiniband::IBPartitionId;
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

// show parses its (all-optional) filters: bare `show` lists everything, while
// --tenant-org-id and --name each route to the Show variant carrying that filter.
// Each row yields (id.is_none(), tenant_org_id, name) -- exactly the fields the
// originals asserted on.
#[test]
fn parse_show_routes_to_show_variant() {
    scenarios!(
        run = |argv| {
            parse_leaf::<Cmd>(argv, &["show"])
                .map(|matches| {
                    (
                        matches.get_one::<IBPartitionId>("id").is_none(),
                        raw_value(&matches, "tenant_org_id"),
                        raw_value(&matches, "name"),
                    )
                })
                .map_err(drop)
        };
        "no args lists all partitions" {
            &["ib-partition", "show"][..] => Yields((true, None, None)),
        }

        "--tenant-org-id filters by tenant" {
            &["ib-partition", "show", "--tenant-org-id", "tenant-123"][..] => Yields((true, Some("tenant-123".to_string()), None)),
        }

        "--name filters by partition name" {
            &["ib-partition", "show", "--name", "my-partition"][..] => Yields((true, None, Some("my-partition".to_string()))),
        }
    );
}
