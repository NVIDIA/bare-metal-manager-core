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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc};
use prettytable::{Table, row};

use crate::machine::health_report::cmd::get_empty_template;
use crate::machine::{HealthReportTemplates, get_health_report};

/// Display a list of health report entries.
pub fn display_health_reports(
    entries: Vec<forgerpc::HealthReportEntry>,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    let mut rows = vec![];
    for entry in entries {
        let report = entry.report.ok_or(CarbideCliError::GenericError(
            "missing response".to_string(),
        ))?;
        let mode = match forgerpc::HealthReportApplyMode::try_from(entry.mode)
            .map_err(|_| CarbideCliError::GenericError("invalide response".to_string()))?
        {
            forgerpc::HealthReportApplyMode::Merge => "Merge",
            forgerpc::HealthReportApplyMode::Replace => "Replace",
        };
        rows.push((report, mode));
    }
    match output_format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(
                &rows
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "report": r.0,
                            "mode": r.1,
                        })
                    })
                    .collect::<Vec<_>>(),
            )?
        ),
        _ => {
            let mut table = Table::new();
            table.set_titles(row!["Report", "Mode"]);
            for row in rows {
                table.add_row(row![serde_json::to_string(&row.0)?, row.1]);
            }
            table.printstd();
        }
    }
    Ok(())
}

/// Resolve a health report from either a template or raw JSON.
pub fn resolve_health_report(
    template: Option<HealthReportTemplates>,
    health_report_json: Option<String>,
    message: Option<String>,
) -> CarbideCliResult<health_report::HealthReport> {
    if let Some(template) = template {
        Ok(get_health_report(template, message))
    } else if let Some(json) = health_report_json {
        serde_json::from_str::<health_report::HealthReport>(&json)
            .map_err(CarbideCliError::JsonError)
    } else {
        Err(CarbideCliError::GenericError(
            "Either health_report or template name must be provided.".to_string(),
        ))
    }
}

/// Print the empty health report template.
pub fn print_empty_template() {
    println!(
        "{}",
        serde_json::to_string_pretty(&get_empty_template()).unwrap()
    );
}
