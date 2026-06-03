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

use clap::{CommandFactory, Parser};

use super::health_report::args::Args as HealthReportCommand;
use super::*;

const TEST_DOMAIN_ID: &str = "00000000-0000-0000-0000-000000000001";

fn parse_cmd(args: impl IntoIterator<Item = &'static str>) -> Cmd {
    match Cmd::try_parse_from(args) {
        Ok(cmd) => cmd,
        Err(err) => panic!("failed to parse command: {err}"),
    }
}

#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

#[test]
fn parse_health_report_show() {
    let cmd = parse_cmd(["nvl-domain", "health-report", "show", TEST_DOMAIN_ID]);

    let Cmd::HealthReport(command) = cmd;
    if let HealthReportCommand::Show { domain_id } = command {
        assert_eq!(domain_id.to_string(), TEST_DOMAIN_ID);
    } else {
        panic!("expected HealthReport Show variant");
    }
}

#[test]
fn parse_health_report_remove() {
    let cmd = parse_cmd([
        "nvl-domain",
        "health-report",
        "remove",
        TEST_DOMAIN_ID,
        "haas-log-analyzer",
    ]);

    let Cmd::HealthReport(command) = cmd;
    if let HealthReportCommand::Remove {
        domain_id,
        report_source,
    } = command
    {
        assert_eq!(domain_id.to_string(), TEST_DOMAIN_ID);
        assert_eq!(report_source, "haas-log-analyzer");
    } else {
        panic!("expected HealthReport Remove variant");
    }
}
