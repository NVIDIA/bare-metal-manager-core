/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Debug Bundle Module
//!
//! This module contains all functionality related to creating debug bundles
//! for troubleshooting managed hosts and Carbide API issues.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use chrono::{DateTime, Local, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use zip::CompressionMethod;
use zip::write::{FileOptions, ZipWriter};

use crate::cfg::cli_options::DebugBundle;

const MAX_BATCH_SIZE: u32 = 5000;
const CARBIDE_API_CONTAINER_NAME: &str = "carbide-api";
const K8S_CONTAINER_NAME_LABEL: &str = "k8s_container_name";

// 🔗 Grafana link generation
#[derive(Serialize)]
struct GrafanaConfig {
    datasource: String,
    queries: Vec<GrafanaQuery>,
    range: GrafanaTimeRange,
}

#[derive(Serialize)]
struct GrafanaQuery {
    expr: String,
    #[serde(rename = "refId")]
    ref_id: String,
}

#[derive(Serialize)]
struct GrafanaTimeRange {
    from: String,
    to: String,
}

// 🎯 LogType enum for log categorization
#[derive(Debug, Clone, Copy)]
enum LogType {
    CarbideApi,
    HostSpecific,
}

impl LogType {
    fn batch_label(&self, batch_number: usize) -> String {
        match self {
            LogType::CarbideApi => format!("Carbide-API Batch {batch_number}"),
            LogType::HostSpecific => format!("Host Batch {batch_number}"),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogType::CarbideApi => "carbide-api",
            LogType::HostSpecific => "host-specific",
        }
    }
}

// 🎯 TimeRange struct to group related time parameters
#[derive(Debug, Clone)]
struct TimeRange {
    start_date: String,
    start_time: String,
    end_date: String,
    end_time: String,
}

impl TimeRange {
    fn new(start_date: &str, start_time: &str, end_date: &str, end_time: &str) -> Self {
        Self {
            start_date: start_date.to_string(),
            start_time: start_time.to_string(),
            end_date: end_date.to_string(),
            end_time: end_time.to_string(),
        }
    }

    fn to_grafana_format(&self) -> CarbideCliResult<(String, String)> {
        convert_time_to_grafana_format(
            &self.start_date,
            &self.start_time,
            &self.end_date,
            &self.end_time,
        )
    }

    fn with_new_end_time(&self, new_end_time: &str) -> Self {
        Self {
            start_date: self.start_date.clone(),
            start_time: self.start_time.clone(),
            end_date: self.end_date.clone(),
            end_time: new_end_time.to_string(),
        }
    }
}

// 🎯 LogBatch struct for batch management
#[derive(Debug)]
struct LogBatch {
    batch_number: usize,
    log_type: LogType,
    time_range: TimeRange,
    grafana_link: Option<String>,
}

impl LogBatch {
    fn new(batch_number: usize, log_type: LogType, time_range: TimeRange) -> Self {
        Self {
            batch_number,
            log_type,
            time_range,
            grafana_link: None,
        }
    }

    fn set_grafana_link(&mut self, site: &str, loki_uid: &str, expr: &str) -> CarbideCliResult<()> {
        let (start_ms, end_ms) = self.time_range.to_grafana_format()?;
        let link = generate_grafana_link(site, loki_uid, expr, &start_ms, &end_ms)?;
        self.grafana_link = Some(link);
        Ok(())
    }

    fn label(&self) -> String {
        self.log_type.batch_label(self.batch_number)
    }

    fn needs_pagination(&self, batch_count: usize, batch_size: u32) -> bool {
        batch_count >= batch_size as usize
    }

    fn next_time_range(
        &self,
        response_body: &str,
        batch_size: u32,
    ) -> CarbideCliResult<Option<TimeRange>> {
        if let Some(next_end_time) = handle_pagination(response_body, batch_size as usize)? {
            Ok(Some(self.time_range.with_new_end_time(&next_end_time)))
        } else {
            Ok(None)
        }
    }
}

// 🎯 LogCollector struct to encapsulate state and behavior
#[derive(Debug)]
struct LogCollector {
    site: String,
    loki_uid: String,
    unique_log_ids: HashSet<String>,
    all_entries: Vec<LogEntry>,
    batch_size: u32,
    batch_links: Vec<(String, String, usize, String)>, // (batch_label, grafana_link, log_count, time_range_display)
    grafana_client: GrafanaClient,                     // ✅ Reuse client across batches
}

impl LogCollector {
    fn new(site: String, loki_uid: String, batch_size: u32) -> CarbideCliResult<Self> {
        // Validate and cap batch size
        let capped_batch_size = batch_size.min(MAX_BATCH_SIZE);
        if batch_size > MAX_BATCH_SIZE {
            println!(
                "⚠️  Batch size {batch_size} exceeds maximum {MAX_BATCH_SIZE}, using {capped_batch_size}"
            );
        }

        // ✅ Create GrafanaClient once and reuse
        let grafana_client = GrafanaClient::new(site.clone())?;

        Ok(Self {
            site,
            loki_uid,
            unique_log_ids: HashSet::new(),
            all_entries: Vec::new(),
            batch_size: capped_batch_size,
            batch_links: Vec::new(),
            grafana_client,
        })
    }

    async fn collect_logs(
        mut self,
        expr: &str,
        log_type: LogType,
        time_range: TimeRange,
    ) -> CarbideCliResult<(Vec<LogEntry>, Vec<(String, String, usize, String)>)> {
        let mut current_time_range = time_range;
        let mut batch_number = 1;

        loop {
            let mut batch = LogBatch::new(batch_number, log_type, current_time_range.clone());
            let (start_ms, end_ms) = batch.time_range.to_grafana_format()?;
            let end_display = format_end_display(&batch.time_range.end_time, &end_ms);

            println!(
                "📊 {}: Fetching logs from {} ({}) to {}",
                batch.label(),
                batch.time_range.start_time,
                start_ms,
                end_display
            );

            let batch_result = self.process_batch(expr, &start_ms, &end_ms).await?;

            // Generate Grafana link for this batch
            batch.set_grafana_link(&self.site, &self.loki_uid, expr)?;

            // Store batch info with link and time range
            let batch_label = batch.label();
            let grafana_link = batch.grafana_link.clone().unwrap_or_default();
            let log_count = batch_result.entries.len();
            let time_range_display = format!(
                "{} ({}) to {}",
                batch.time_range.start_time, start_ms, end_display
            );
            self.batch_links
                .push((batch_label, grafana_link, log_count, time_range_display));

            // Update collections for next batch
            self.unique_log_ids.extend(
                batch_result
                    .entries
                    .iter()
                    .map(|entry| entry.unique_id.clone()),
            );
            self.all_entries.extend(batch_result.entries);

            if !batch.needs_pagination(batch_result.original_batch_count, self.batch_size) {
                break;
            }

            if let Some(next_time_range) =
                batch.next_time_range(&batch_result.response_body, self.batch_size)?
            {
                current_time_range = next_time_range;
                batch_number += 1;
            } else {
                break;
            }
        }

        // Destructure to get both fields without cloning
        let LogCollector {
            all_entries: logs,
            unique_log_ids,
            batch_links,
            ..
        } = self;

        // Validate before returning
        let log_type_upper = log_type.as_str().to_uppercase();
        println!("📝 TOTAL {} LOGS COLLECTED: {}", log_type_upper, logs.len());

        let logs_count = logs.len();
        let unique_ids_count = unique_log_ids.len();

        if logs_count != unique_ids_count {
            println!(
                "❌ Validation FAILED for {}: {} logs but {} unique IDs (some logs missing unique IDs)",
                log_type.as_str(),
                logs_count,
                unique_ids_count
            );
            return Err(CarbideCliError::GenericError(format!(
                "Log validation failed for {}: {logs_count} logs but {unique_ids_count} unique IDs",
                log_type.as_str()
            )));
        }

        println!(
            "✅ Validation PASSED for {}: {} logs = {} unique IDs",
            log_type.as_str(),
            logs_count,
            unique_ids_count
        );

        Ok((logs, batch_links))
    }

    async fn process_batch(
        &self,
        expr: &str,
        start_ms: &str,
        end_ms: &str,
    ) -> CarbideCliResult<BatchResult> {
        let query_request =
            build_grafana_query_request(expr, start_ms, end_ms, &self.loki_uid, self.batch_size);

        // 2. Execute HTTP request using reusable function and stored client
        let response_body = execute_grafana_query(&query_request, &self.grafana_client).await?;

        // 3. Parse response using reusable function
        let batch_entries = parse_logs_from_response(&response_body)?;

        let original_batch_count = batch_entries.len();
        let new_entries = remove_duplicates_from_end(batch_entries, &self.unique_log_ids);

        Ok(BatchResult {
            entries: new_entries,
            response_body,
            original_batch_count,
        })
    }
}

// 🎯 GrafanaClient struct for API interactions
#[derive(Debug)]
struct GrafanaClient {
    client: reqwest::Client,
    site: String,
    base_url: String,
    auth_token: String,
}

impl GrafanaClient {
    fn new(site: String) -> CarbideCliResult<Self> {
        let auth_token = std::env::var("GRAFANA_AUTH_TOKEN").map_err(|_| {
            CarbideCliError::GenericError(
                "GRAFANA_AUTH_TOKEN environment variable not set".to_string(),
            )
        })?;

        // Build HTTP client with optional proxy support from environment variables
        let mut client_builder = reqwest::Client::builder();

        // Check for proxy configuration in environment variables
        // Standard proxy env vars: HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy
        if let Ok(proxy_url) = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("HTTP_PROXY"))
            .or_else(|_| std::env::var("http_proxy"))
        {
            println!("🔗 Using proxy: {}", proxy_url);
            let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| {
                CarbideCliError::GenericError(format!("Failed to configure proxy: {}", e))
            })?;
            client_builder = client_builder.proxy(proxy);
        } else {
            println!("📡 No proxy configured - connecting directly");
        }

        let client = client_builder.build().map_err(|e| {
            CarbideCliError::GenericError(format!("Failed to build HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            base_url: format!("https://grafana-{site}.frg.nvidia.com"),
            auth_token,
            site,
        })
    }

    async fn get_loki_datasource_uid(&self) -> CarbideCliResult<String> {
        println!("🔍 Fetching Loki datasource UID for site: {}", self.site);

        let datasources_url = format!("{}/api/datasources/", self.base_url);

        let response = self
            .client
            .get(&datasources_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("📡 Datasources API Response Status: {status}");

                if status.is_success() {
                    let datasources: Vec<GrafanaDatasource> = match resp.json().await {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(CarbideCliError::GenericError(format!(
                                "Failed to parse datasources JSON: {e}"
                            )));
                        }
                    };

                    for ds in datasources {
                        if ds.datasource_type == "loki" {
                            println!("✅ Found Loki datasource: {} (UID: {})", ds.name, ds.uid);
                            return Ok(ds.uid);
                        }
                    }

                    Err(CarbideCliError::GenericError(
                        "Loki datasource not found in the response".to_string(),
                    ))
                } else {
                    let body = resp.text().await.unwrap_or_default();
                    Err(CarbideCliError::GenericError(format!(
                        "HTTP Error {status}: {body}"
                    )))
                }
            }
            Err(e) => Err(CarbideCliError::GenericError(format!(
                "Failed to fetch datasources: {e}"
            ))),
        }
    }
}

// 🎯 LogEntry struct for log entries
#[derive(Debug, Clone)]
struct LogEntry {
    message: String,
    timestamp_ms: i64,
    unique_id: String,
    nanosecond_timestamp: u64,
}

impl LogEntry {
    fn format_header(&self) -> String {
        format_timestamp_header(self.timestamp_ms)
    }

    fn is_duplicate(&self, existing_ids: &std::collections::HashSet<String>) -> bool {
        existing_ids.contains(&self.unique_id)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrafanaResponse {
    pub results: GrafanaResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrafanaResults {
    #[serde(rename = "A")]
    pub a: GrafanaFrameResult,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrafanaFrameResult {
    pub status: u16,
    pub frames: Vec<GrafanaFrame>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrafanaFrame {
    pub data: GrafanaFrameData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrafanaFrameData {
    pub values: Vec<Vec<GrafanaValue>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum GrafanaValue {
    Int(i64),       // For timestamps (values[1])
    String(String), // For log messages (values[2]) and nanosecond timestamps (values[3])
    Object(serde_json::Value),
}

// 🎯 Strongly typed structs for Grafana query requests
#[derive(Serialize)]
struct GrafanaQueryRequest {
    queries: Vec<LokiQuery>,
    from: String,
    to: String,
    limit: u32,
}

#[derive(Serialize)]
struct LokiQuery {
    #[serde(rename = "refId")]
    ref_id: String,
    datasource: LokiDatasource,
    #[serde(rename = "queryType")]
    query_type: String,
    expr: String,
    #[serde(rename = "maxLines")]
    max_lines: u32,
}

#[derive(Serialize)]
struct LokiDatasource {
    #[serde(rename = "type")]
    datasource_type: String,
    uid: String,
}

// 🎯 Grafana Datasource API Response Structs
#[derive(Deserialize, Debug)]
struct GrafanaDatasource {
    pub uid: String,
    pub name: String,
    #[serde(rename = "type")]
    pub datasource_type: String,
}

/// Creates a debug bundle for a specific host machine.
///
/// This function collects host-specific logs, carbide-api logs, and other diagnostic
/// information for the specified machine within the given time range. The collected
/// data is packaged into a ZIP file for debugging purposes.
///
/// # Arguments
///
/// * `debug_bundle` - Configuration containing the host ID, time range, output path,
///   site name, and batch size for log collection
///
/// # Returns
///
/// Returns `Ok(())` on successful bundle creation, or a `CarbideCliError` if any step fails.
pub async fn handle_debug_bundle(debug_bundle: DebugBundle) -> CarbideCliResult<()> {
    println!(
        "🔍 Creating debug bundle for host: {}",
        debug_bundle.host_id
    );

    // 🎯 Use new GrafanaClient struct
    let grafana_client = GrafanaClient::new(debug_bundle.site.clone())?;

    println!("\n🔧 Step 0: Fetching Loki datasource UID...");
    let loki_uid = grafana_client.get_loki_datasource_uid().await?;

    // 🎯 Parse flexible date/time inputs
    let (start_date, start_time) = parse_datetime_input(&debug_bundle.start_time)?;
    let (end_date, end_time) = parse_datetime_input(&debug_bundle.end_time)?;

    // 🎯 Create TimeRange struct with parsed values
    let time_range = TimeRange::new(&start_date, &start_time, &end_date, &end_time);

    println!("\n📋 Step 1: Downloading host-specific logs...");
    let (host_logs, host_batch_links) = get_host_logs(
        &debug_bundle.host_id,
        time_range.clone(),
        &debug_bundle.site,
        &loki_uid,
        debug_bundle.batch_size,
    )
    .await?;

    println!("\n📋 Step 2: Downloading carbide-api logs...");
    let (carbide_api_logs, carbide_batch_links) = get_carbide_api_logs(
        time_range.clone(),
        &debug_bundle.site,
        &loki_uid,
        debug_bundle.batch_size,
    )
    .await?;

    println!("\n📊 Log Collection Summary:");
    println!("   Host Logs: {} logs collected", host_logs.len());
    println!(
        "   Carbide-API Logs: {} logs collected",
        carbide_api_logs.len()
    );
    println!(
        "   Total: {} logs",
        host_logs.len() + carbide_api_logs.len()
    );

    // Create ZIP file with both log types
    println!("\n📦 Step 3: Creating ZIP file...");
    create_debug_bundle_zip(
        &debug_bundle,
        &host_logs,
        &carbide_api_logs,
        &host_batch_links,
        &carbide_batch_links,
    )?;

    println!("\n✅ Debug bundle creation completed!");

    Ok(())
}

async fn get_host_logs(
    host_id: &str,
    time_range: TimeRange,
    site: &str,
    loki_uid: &str,
    batch_size: u32,
) -> CarbideCliResult<(Vec<LogEntry>, Vec<(String, String, usize, String)>)> {
    let expr = format!("{{host_machine_id=\"{host_id}\"}} |= ``");
    let log_type = LogType::HostSpecific;

    // ✅ NEW() NOW RETURNS RESULT
    let collector = LogCollector::new(site.to_string(), loki_uid.to_string(), batch_size)?;
    let (logs, batch_links) = collector.collect_logs(&expr, log_type, time_range).await?;
    Ok((logs, batch_links))
}

async fn get_carbide_api_logs(
    time_range: TimeRange,
    site: &str,
    loki_uid: &str,
    batch_size: u32,
) -> CarbideCliResult<(Vec<LogEntry>, Vec<(String, String, usize, String)>)> {
    let expr = format!("{{{K8S_CONTAINER_NAME_LABEL}=\"{CARBIDE_API_CONTAINER_NAME}\"}} |= ``");
    let log_type = LogType::CarbideApi;

    // ✅ NEW() NOW RETURNS RESULT
    let collector = LogCollector::new(site.to_string(), loki_uid.to_string(), batch_size)?;
    let (logs, batch_links) = collector.collect_logs(&expr, log_type, time_range).await?;
    Ok((logs, batch_links))
}

// Step 1: Reusable request builder
fn build_grafana_query_request(
    expr: &str,
    start_ms: &str,
    end_ms: &str,
    loki_uid: &str,
    batch_size: u32,
) -> GrafanaQueryRequest {
    GrafanaQueryRequest {
        queries: vec![LokiQuery {
            ref_id: "A".to_string(),
            datasource: LokiDatasource {
                datasource_type: "loki".to_string(),
                uid: loki_uid.to_string(),
            },
            query_type: "range".to_string(),
            expr: expr.to_string(),
            max_lines: batch_size,
        }],
        from: start_ms.to_string(),
        to: end_ms.to_string(),
        limit: batch_size,
    }
}

// Step 2: Reusable HTTP executor
async fn execute_grafana_query(
    query_request: &GrafanaQueryRequest,
    grafana_client: &GrafanaClient,
) -> CarbideCliResult<String> {
    let response = grafana_client
        .client
        .post(format!("{}/api/ds/query", grafana_client.base_url))
        .header("X-Scope-OrgID", "forge")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header(
            "Authorization",
            format!("Bearer {}", grafana_client.auth_token),
        )
        .json(query_request)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("📡 Response Status: {status}");

            if status.is_success() {
                let body = resp.text().await.map_err(|e| {
                    CarbideCliError::GenericError(format!("Failed to read response body: {e}"))
                })?;
                Ok(body)
            } else {
                let body = resp.text().await.unwrap_or_default();
                Err(CarbideCliError::GenericError(format!(
                    "HTTP Error {status}: {body}"
                )))
            }
        }
        Err(e) => Err(CarbideCliError::GenericError(format!(
            "Connection failed: {e}"
        ))),
    }
}

// Step 3: Reusable response parser
fn parse_logs_from_response(response_json: &str) -> CarbideCliResult<Vec<LogEntry>> {
    let (log_entries, _) = parse_grafana_logs(response_json)?;
    Ok(log_entries)
}

// Structure to hold batch processing results
struct BatchResult {
    entries: Vec<LogEntry>,
    response_body: String,
    original_batch_count: usize, // Count before deduplication
}

// Helper function to handle pagination logic
fn handle_pagination(response_body: &str, batch_size: usize) -> CarbideCliResult<Option<String>> {
    // Parse response to check if we need pagination
    let response: GrafanaResponse = serde_json::from_str(response_body).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to parse pagination response: {e}"))
    })?;

    let frame_data = &response.results.a.frames[0].data;
    let actual_batch_count = if frame_data.values.len() > 2 {
        frame_data.values[2].len()
    } else {
        0
    };

    if actual_batch_count < batch_size {
        return Ok(None);
    }

    let (_, oldest_timestamp) = parse_grafana_logs(response_body)?;
    if let Some(oldest_ts) = oldest_timestamp {
        let next_end_ms = oldest_ts + 1;
        Ok(Some(format!("{next_end_ms}ms")))
    } else {
        Ok(None)
    }
}

// Parse Grafana JSON response using strongly typed structs
fn parse_grafana_logs(json_response: &str) -> CarbideCliResult<(Vec<LogEntry>, Option<i64>)> {
    let response: GrafanaResponse = serde_json::from_str(json_response)
        .map_err(|e| CarbideCliError::GenericError(format!("Failed to parse JSON: {e}")))?;

    let frame_data = &response.results.a.frames[0].data;

    // Extract nanosecond timestamps from values[3] for sorting
    let timestamps: Vec<u64> = frame_data.values[3]
        .iter()
        .filter_map(|val| match val {
            GrafanaValue::String(s) => s.parse::<u64>().ok(),
            _ => None,
        })
        .collect();

    // Extract log messages from values[2]
    let logs: Vec<String> = frame_data.values[2]
        .iter()
        .filter_map(|val| match val {
            GrafanaValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    // Extract unique IDs from values[4] for deduplication
    let unique_ids: Vec<String> = frame_data.values[4]
        .iter()
        .filter_map(|val| match val {
            GrafanaValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    // Extract millisecond timestamps from values[1] for headers
    let ms_timestamps: Vec<i64> = frame_data.values[1]
        .iter()
        .filter_map(|val| match val {
            GrafanaValue::Int(n) => Some(*n),
            _ => None,
        })
        .collect();

    // Create LogEntry structs using direct indexing
    let mut log_entries: Vec<LogEntry> = (0..logs.len())
        .filter_map(|i| {
            let ns_timestamp = timestamps.get(i)?;
            let log = logs.get(i)?;
            let id = unique_ids.get(i)?;
            let ms_timestamp = ms_timestamps.get(i)?;
            Some(LogEntry {
                message: log.clone(),
                timestamp_ms: *ms_timestamp,
                unique_id: id.clone(),
                nanosecond_timestamp: *ns_timestamp,
            })
        })
        .collect();

    // Sort by nanosecond timestamp for perfect chronological order
    log_entries.sort_by_key(|entry| entry.nanosecond_timestamp);

    // Extract oldest timestamp from values[1] for pagination
    let oldest_timestamp = if frame_data.values.len() > 1 {
        frame_data.values[1]
            .iter()
            .filter_map(|val| match val {
                GrafanaValue::Int(ts) => Some(*ts),
                _ => None,
            })
            .min()
    } else {
        None
    };

    Ok((log_entries, oldest_timestamp))
}

// Helper function to remove duplicates from the end of batch (optimized for timestamp-sorted logs)
fn remove_duplicates_from_end(
    mut entries: Vec<LogEntry>,
    existing_unique_ids: &std::collections::HashSet<String>,
) -> Vec<LogEntry> {
    while let Some(last_entry) = entries.last() {
        if last_entry.is_duplicate(existing_unique_ids) {
            entries.pop();
        } else {
            break;
        }
    }

    entries
}

//  function to format timestamp as "2025-08-28 06:06:55.281" for ZIP file headers
fn format_timestamp_header(timestamp_ms: i64) -> String {
    if let Some(datetime) = DateTime::from_timestamp_millis(timestamp_ms) {
        let local_time: DateTime<Local> = datetime.with_timezone(&Local);
        local_time.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    } else {
        "Unknown Time".to_string()
    }
}

//  function to convert millisecond timestamp back to HH:MM:SS format
fn format_timestamp_for_display(timestamp_ms: i64) -> String {
    if let Some(datetime) = DateTime::from_timestamp_millis(timestamp_ms) {
        let local_time: DateTime<Local> = datetime.with_timezone(&Local);
        local_time.format("%H:%M:%S").to_string()
    } else {
        "INVALID".to_string()
    }
}

// function to format end display timestamp
fn format_end_display(current_end_time: &str, end_ms: &str) -> String {
    if current_end_time.ends_with("ms") {
        let end_timestamp_str = current_end_time.strip_suffix("ms").unwrap();
        if let Ok(end_ts) = end_timestamp_str.parse::<i64>() {
            format!("{} ({})", format_timestamp_for_display(end_ts), end_ts)
        } else {
            current_end_time.to_string()
        }
    } else {
        format!("{current_end_time} ({end_ms})")
    }
}

fn convert_time_to_grafana_format(
    start_date: &str,
    start_time: &str,
    end_date: &str,
    end_time: &str,
) -> CarbideCliResult<(String, String)> {
    let parse_datetime = |date: &str, time: &str| -> CarbideCliResult<i64> {
        let date_naive = NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|e| {
            CarbideCliError::GenericError(format!(
                "Invalid date format '{date}'. Expected YYYY-MM-DD: {e}"
            ))
        })?;

        let time_naive = NaiveTime::parse_from_str(time, "%H:%M:%S").map_err(|e| {
            CarbideCliError::GenericError(format!(
                "Invalid time format '{time}'. Expected HH:MM:SS: {e}"
            ))
        })?;

        let datetime = date_naive.and_time(time_naive);
        let utc: DateTime<Utc> = datetime
            .and_local_timezone(Local)
            .single()
            .ok_or_else(|| {
                CarbideCliError::GenericError(format!("Ambiguous local time: {}", datetime))
            })?
            .with_timezone(&Utc);
        Ok(utc.timestamp_millis())
    };

    let start_ms = parse_datetime(start_date, start_time)?;

    let end_ms = if end_time.ends_with("ms") {
        let end_timestamp_str = end_time.strip_suffix("ms").unwrap();
        return Ok((start_ms.to_string(), end_timestamp_str.to_string()));
    } else {
        parse_datetime(end_date, end_time)?
    };

    Ok((start_ms.to_string(), end_ms.to_string()))
}

// 🎯 datetime parsing function
fn parse_datetime_input(input: &str) -> CarbideCliResult<(String, String)> {
    let dash_count = input.chars().filter(|&c| c == '-').count();
    let colon_count = input.chars().filter(|&c| c == ':').count();

    if dash_count == 2 && colon_count == 2 {
        // Format: "2025-09-02 06:00:00" (full datetime)
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.len() == 2 {
            Ok((parts[0].to_string(), parts[1].to_string()))
        } else {
            Err(CarbideCliError::GenericError(
                "Invalid datetime format. Use 'YYYY-MM-DD HH:MM:SS'".to_string(),
            ))
        }
    } else if dash_count == 0 && colon_count == 2 {
        // Format: "06:00:00" (time only - use today's date)
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        Ok((today, input.to_string()))
    } else {
        Err(CarbideCliError::GenericError(
            "Invalid format. Use 'YYYY-MM-DD HH:MM:SS' or 'HH:MM:SS'".to_string(),
        ))
    }
}

fn generate_grafana_link(
    site: &str,
    loki_uid: &str,
    expr: &str,
    start_ms: &str,
    end_ms: &str,
) -> CarbideCliResult<String> {
    let config = GrafanaConfig {
        datasource: loki_uid.to_string(),
        queries: vec![GrafanaQuery {
            expr: expr.to_string(),
            ref_id: "A".to_string(),
        }],
        range: GrafanaTimeRange {
            from: start_ms.to_string(),
            to: end_ms.to_string(),
        },
    };

    let json_str = serde_json::to_string(&config).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to serialize Grafana config: {e}"))
    })?;

    let encoded = urlencoding::encode(&json_str);
    let grafana_url = format!("https://grafana-{site}.frg.nvidia.com/explore?left={encoded}");

    Ok(grafana_url)
}

// 🎯 NEW ZIP CREATOR STRUCT
struct ZipBundleCreator<'a> {
    config: &'a DebugBundle,
    timestamp: String,
}

impl<'a> ZipBundleCreator<'a> {
    fn new(config: &'a DebugBundle) -> Self {
        Self {
            timestamp: chrono::Local::now().format("%Y%m%d%H%M%S").to_string(),
            config,
        }
    }

    fn create_bundle(
        &self,
        host_logs: &[LogEntry],
        carbide_logs: &[LogEntry],
        host_batch_links: &[(String, String, usize, String)],
        carbide_batch_links: &[(String, String, usize, String)],
    ) -> CarbideCliResult<String> {
        let filename = format!("{}_{}.zip", self.timestamp, self.config.host_id);
        let filepath = format!("{}/{}", self.config.output_path, filename);
        let mut zip = ZipWriter::new(File::create(&filepath).map_err(|e| {
            CarbideCliError::GenericError(format!("Failed to create ZIP file: {e}"))
        })?);
        let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

        // Add all files using helper method
        self.add_file(
            &mut zip,
            &format!("host_logs_{}.txt", self.config.host_id),
            host_logs,
            options,
        )?;
        self.add_file(&mut zip, "carbide_api_logs.txt", carbide_logs, options)?;
        self.add_metadata(
            &mut zip,
            host_logs.len(),
            carbide_logs.len(),
            host_batch_links,
            carbide_batch_links,
            options,
        )?;

        zip.finish()
            .map_err(|e| CarbideCliError::GenericError(format!("Failed to finish ZIP: {e}")))?;

        println!("✅ ZIP created: {filepath}");
        println!(
            "📊 Files: host_logs_{}.txt ({} logs), carbide_api_logs.txt ({} logs), metadata.txt",
            self.config.host_id,
            host_logs.len(),
            carbide_logs.len()
        );

        Ok(filepath)
    }

    fn add_file(
        &self,
        zip: &mut ZipWriter<File>,
        filename: &str,
        logs: &[LogEntry],
        options: FileOptions,
    ) -> CarbideCliResult<()> {
        zip.start_file(filename, options).map_err(|e| {
            CarbideCliError::GenericError(format!("Failed to create file {filename}: {e}"))
        })?;
        for entry in logs {
            writeln!(zip, "{} {}", entry.format_header(), entry.message)?;
        }
        Ok(())
    }

    fn add_metadata(
        &self,
        zip: &mut ZipWriter<File>,
        host_count: usize,
        carbide_count: usize,
        host_batch_links: &[(String, String, usize, String)],
        carbide_batch_links: &[(String, String, usize, String)],
        options: FileOptions,
    ) -> CarbideCliResult<()> {
        zip.start_file("metadata.txt", options).map_err(|e| {
            CarbideCliError::GenericError(format!("Failed to create metadata file: {e}"))
        })?;
        writeln!(zip, "Debug Bundle: {}", self.config.host_id)?;
        writeln!(
            zip,
            "Time Range: {} to {}",
            self.config.start_time, self.config.end_time
        )?;
        writeln!(zip, "Site: {}", self.config.site)?;
        writeln!(zip, "Host Logs: {host_count}")?;
        writeln!(zip, "Carbide-API Logs: {carbide_count}")?;
        writeln!(zip, "Total: {}", host_count + carbide_count)?;
        writeln!(zip)?;

        // Add Grafana links for host-specific logs
        if !host_batch_links.is_empty() {
            writeln!(zip, "Host-Specific Batches:")?;
            for (batch_label, grafana_link, log_count, time_range_display) in host_batch_links {
                writeln!(zip, "  {batch_label} ({log_count} logs):")?;
                writeln!(zip, "    Time Range: {time_range_display}")?;
                writeln!(zip, "    {grafana_link}")?;
                writeln!(zip)?;
            }
        }

        // Add Grafana links for carbide-api logs
        if !carbide_batch_links.is_empty() {
            writeln!(zip, "Carbide-API Batches:")?;
            for (batch_label, grafana_link, log_count, time_range_display) in carbide_batch_links {
                writeln!(zip, "  {batch_label} ({log_count} logs):")?;
                writeln!(zip, "    Time Range: {time_range_display}")?;
                writeln!(zip, "    {grafana_link}")?;
                writeln!(zip)?;
            }
        }

        Ok(())
    }
}

fn create_debug_bundle_zip(
    debug_bundle: &DebugBundle,
    host_logs: &[LogEntry],
    carbide_api_logs: &[LogEntry],
    host_batch_links: &[(String, String, usize, String)],
    carbide_batch_links: &[(String, String, usize, String)],
) -> CarbideCliResult<()> {
    ZipBundleCreator::new(debug_bundle).create_bundle(
        host_logs,
        carbide_api_logs,
        host_batch_links,
        carbide_batch_links,
    )?;
    Ok(())
}
