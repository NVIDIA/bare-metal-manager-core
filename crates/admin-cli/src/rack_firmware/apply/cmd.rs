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

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use prettytable::{Cell, Row, Table};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn apply(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    println!(
        "Applying firmware ID '{}' ({}) to rack '{}'...",
        opts.firmware_id, opts.firmware_type, opts.rack_id
    );

    let request = rpc::forge::RackFirmwareApplyRequest {
        rack_id: Some(opts.rack_id),
        firmware_id: opts.firmware_id,
        firmware_type: opts.firmware_type,
    };

    let response = api_client
        .0
        .apply_rack_firmware(request)
        .await
        .map_err(CarbideCliError::from)?;

    if format == OutputFormat::Json {
        let result = serde_json::json!({
            "total_updates": response.total_updates,
            "successful_updates": response.successful_updates,
            "failed_updates": response.failed_updates,
            "device_results": response.device_results.iter().map(|r| serde_json::json!({
                "device_id": r.device_id,
                "device_type": r.device_type,
                "success": r.success,
                "message": r.message,
                "job_id": r.job_id,
                "node_jobs": r.node_jobs.iter().map(|j| serde_json::json!({
                    "node_id": j.node_id,
                    "job_id": j.job_id,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Device Type"),
            Cell::new("Status"),
            Cell::new("Job ID"),
        ]));

        for device_result in &response.device_results {
            let status_text = if device_result.success {
                "INITIATED"
            } else {
                "FAILED"
            };

            let job_id_display = if device_result.job_id.is_empty() {
                "-".to_string()
            } else {
                device_result.job_id.clone()
            };

            table.add_row(Row::new(vec![
                Cell::new(&device_result.device_type),
                Cell::new(status_text),
                Cell::new(&job_id_display),
            ]));
        }

        println!("\n{}", "=".repeat(80));
        println!("Firmware Update Summary");
        println!("{}", "=".repeat(80));
        table.printstd();
        println!("\nTotal updates: {}", response.total_updates);
        println!("Successfully initiated: {}", response.successful_updates);
        println!("Failed to initiate: {}", response.failed_updates);

        let has_node_jobs = response
            .device_results
            .iter()
            .any(|r| !r.node_jobs.is_empty());
        if has_node_jobs {
            println!("\n{}", "-".repeat(80));
            println!("Per-Node Job IDs (use with GetFirmwareJobStatus to track progress)");
            println!("{}", "-".repeat(80));

            let mut node_table = Table::new();
            node_table.set_titles(Row::new(vec![
                Cell::new("Device Type"),
                Cell::new("Node ID"),
                Cell::new("Job ID"),
            ]));

            for device_result in &response.device_results {
                for node_job in &device_result.node_jobs {
                    node_table.add_row(Row::new(vec![
                        Cell::new(&device_result.device_type),
                        Cell::new(&node_job.node_id),
                        Cell::new(&node_job.job_id),
                    ]));
                }
            }

            node_table.printstd();
        }
    }

    if response.failed_updates > 0 {
        return Err(CarbideCliError::GenericError(format!(
            "{} firmware updates failed",
            response.failed_updates
        )));
    }

    Ok(())
}
