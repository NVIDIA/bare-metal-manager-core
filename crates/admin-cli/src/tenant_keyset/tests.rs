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

// show parses every combination of its optional positional keyset id and
// optional --tenant-org-id: neither (all keysets), id only, org only, and both.
// Each row yields the parsed (id, tenant_org_id) pair.
#[test]
fn parse_show_arg_combinations() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| {
                    let Cmd::Show(args) = cmd;
                    (args.id, args.tenant_org_id)
                })
                .map_err(drop)
        };
        "no arguments (all keysets)" {
            &["tenant-keyset", "show"][..] => Yields((String::new(), None)),
        }

        "with keyset id" {
            &["tenant-keyset", "show", "org-123/keyset-456"][..] => Yields(("org-123/keyset-456".to_string(), None)),
        }

        "with --tenant-org-id" {
            &["tenant-keyset", "show", "--tenant-org-id", "org-123"][..] => Yields((String::new(), Some("org-123".to_string()))),
        }

        "with both id and --tenant-org-id" {
            &[
                "tenant-keyset",
                "show",
                "org-123/keyset-456",
                "--tenant-org-id",
                "org-123",
            ][..] => Yields((
                "org-123/keyset-456".to_string(),
                Some("org-123".to_string()),
            )),
        }
    );
}
