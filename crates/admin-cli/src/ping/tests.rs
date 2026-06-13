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

use super::args::*;

// verify_cmd_structure runs the underlying clap debug_assert()
#[test]
fn verify_cmd_structure() {
    Opts::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// ping parses the --interval value, defaulting to 1.0 when omitted and
// honoring both the long --interval flag and its -i short form. These decimals
// are exactly representable in f32, so equality is exact.
#[test]
fn parse_interval() {
    scenarios!(
        run = |argv| {
            Opts::try_parse_from(argv.iter().copied())
                .map(|opts| opts.interval)
                .map_err(drop)
        };
        "default interval" {
            &["ping"][..] => Yields(1.0f32),
        }

        "custom --interval" {
            &["ping", "--interval", "2.5"][..] => Yields(2.5f32),
        }

        "short -i flag" {
            &["ping", "-i", "0.5"][..] => Yields(0.5f32),
        }
    );
}
