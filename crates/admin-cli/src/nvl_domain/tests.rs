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

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use clap::{CommandFactory, Parser};

use super::health_report::args::Args as HealthReportCommand;
use super::*;

const TEST_DOMAIN_ID: &str = "00000000-0000-0000-0000-000000000001";

#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

// Every health-report invocation routes to Cmd::HealthReport: `show` yields the
// domain id with no report source, `remove` yields the domain id plus the report
// source it targets. Each row pulls out (domain_id, report_source) as the fields
// the originals asserted.
#[test]
fn parse_health_report_subcommands() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| {
                    let Cmd::HealthReport(command) = cmd;
                    match command {
                        HealthReportCommand::Show { domain_id } => (domain_id.to_string(), None),
                        HealthReportCommand::Remove {
                            domain_id,
                            report_source,
                        } => (domain_id.to_string(), Some(report_source)),
                        other => panic!("unexpected HealthReport variant: {other:?}"),
                    }
                })
                .map_err(drop)
        };
        "show routes to HealthReport Show with the domain id" {
            &["nvl-domain", "health-report", "show", TEST_DOMAIN_ID][..] => Yields((TEST_DOMAIN_ID.to_string(), None)),
        }

        "remove routes to HealthReport Remove with domain id and source" {
            &[
                "nvl-domain",
                "health-report",
                "remove",
                TEST_DOMAIN_ID,
                "haas-log-analyzer",
            ][..] => Yields((
                TEST_DOMAIN_ID.to_string(),
                Some("haas-log-analyzer".to_string()),
            )),
        }
    );
}
