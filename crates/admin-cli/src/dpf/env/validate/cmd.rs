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

use ::rpc::forge::{DpfValidationCheck, DpfValidationStatus};
use prettytable::row;
use serde_json::json;

use crate::dpf::env::validate::args::Args;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

pub async fn validate(args: &Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let checks = api_client.validate_dpf().await?;

    if args.json {
        print_json(&checks);
    } else {
        print_table(&checks, args.verbose);
    }
    // Validation is informational only — exit code is always 0 so SRE can
    // capture and act on the report regardless of severity.
    Ok(())
}

fn status_label(status: i32) -> &'static str {
    match DpfValidationStatus::try_from(status).unwrap_or(DpfValidationStatus::Unspecified) {
        DpfValidationStatus::Pass => "PASS",
        DpfValidationStatus::Warn => "WARN",
        DpfValidationStatus::Fail => "FAIL",
        DpfValidationStatus::Skip => "SKIP",
        DpfValidationStatus::Unspecified => "?",
    }
}

fn print_table(checks: &[DpfValidationCheck], verbose: bool) {
    let mut table = prettytable::Table::new();
    if verbose {
        table.set_titles(row!["Status", "Check", "Description", "Message", "Details"]);
    } else {
        table.set_titles(row!["Status", "Check", "Message"]);
    }

    let mut pass = 0;
    let mut warn = 0;
    let mut fail = 0;
    let mut skip = 0;

    for c in checks {
        match DpfValidationStatus::try_from(c.status).unwrap_or(DpfValidationStatus::Unspecified) {
            DpfValidationStatus::Pass => pass += 1,
            DpfValidationStatus::Warn => warn += 1,
            DpfValidationStatus::Fail => fail += 1,
            DpfValidationStatus::Skip => skip += 1,
            DpfValidationStatus::Unspecified => {}
        }

        let label = status_label(c.status);
        if verbose {
            table.add_row(row![label, c.name, c.description, c.message, c.details]);
        } else {
            table.add_row(row![label, c.name, c.message]);
        }
    }

    table.printstd();
    println!(
        "\nSummary: {} checks  |  {} pass  |  {} warn  |  {} fail  |  {} skip",
        checks.len(),
        pass,
        warn,
        fail,
        skip,
    );
    if fail > 0 {
        println!(
            "Note: {fail} check(s) FAILED. Review the rows above; this command intentionally exits 0 so user can capture full output."
        );
    }
}

fn print_json(checks: &[DpfValidationCheck]) {
    let payload: Vec<_> = checks
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "description": c.description,
                "status": status_label(c.status),
                "message": c.message,
                "details": c.details,
            })
        })
        .collect();
    let out = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "[]".to_string());
    println!("{out}");
}
