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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nv_redfish::ServiceRoot;
use nv_redfish::log_service::LogService;
use nv_redfish_core::{Bmc, FilterQuery, ODataId};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::api_client::{BmcEndpoint, EndpointMetadata};
use crate::collector::PeriodicCollector;
use crate::{HealthError, collector};

/// Configuration for logs collector
pub struct LogsCollectorConfig {
    pub state_file_path: PathBuf,
    pub service_refresh_interval: Duration,
    pub log_writer: Arc<Mutex<LogFileWriter>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistentState {
    last_seen_ids: HashMap<ODataId, i32>,
}

struct LogsCollectorState<B: Bmc> {
    discovered_services: Vec<LogService<B>>,
    last_service_refresh: Instant,
    last_seen_ids: HashMap<ODataId, i32>,
}

#[derive(Debug, Serialize)]
struct OtelLogRecord {
    #[serde(rename = "timeUnixNano")]
    time_unix_nano: String,
    #[serde(rename = "observedTimeUnixNano")]
    observed_time_unix_nano: String,
    #[serde(rename = "severityNumber")]
    severity_number: u8,
    #[serde(rename = "severityText")]
    severity_text: String,
    body: String,
    #[serde(flatten)]
    attributes: HashMap<String, JsonValue>,
}

pub async fn create_log_file_writer(
    output_dir: PathBuf,
    machine_id: String,
    max_file_size: u64,
    max_backups: usize,
) -> Result<LogFileWriter, HealthError> {
    LogFileWriter::new(output_dir, machine_id, max_file_size, max_backups).await
}

pub struct LogFileWriter {
    output_dir: PathBuf,
    machine_id: String,
    max_file_size: u64,
    max_backups: usize,
    current_file: Option<tokio::io::BufWriter<tokio::fs::File>>,
    current_size: u64,
}

impl LogFileWriter {
    async fn new(
        output_dir: PathBuf,
        machine_id: String,
        max_file_size: u64,
        max_backups: usize,
    ) -> Result<Self, HealthError> {
        tokio::fs::create_dir_all(&output_dir).await.map_err(|e| {
            HealthError::GenericError(format!("Failed to create log directory: {e}"))
        })?;

        let mut writer = Self {
            output_dir,
            machine_id,
            max_file_size,
            max_backups,
            current_file: None,
            current_size: 0,
        };

        writer.open_current_file().await?;

        Ok(writer)
    }

    fn current_log_path(&self) -> PathBuf {
        self.output_dir
            .join(format!("{}_logs.jsonl", self.machine_id))
    }

    fn rotated_log_path(&self, index: usize) -> PathBuf {
        self.output_dir
            .join(format!("{}_logs.{index}.jsonl", self.machine_id))
    }

    async fn open_current_file(&mut self) -> Result<(), HealthError> {
        let path = self.current_log_path();

        self.current_size = tokio::fs::metadata(&path)
            .await
            .ok()
            .map(|m| m.len())
            .unwrap_or(0);

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| HealthError::LoggerError(format!("Failed to open log file: {e}")))?;

        self.current_file = Some(tokio::io::BufWriter::new(file));
        Ok(())
    }

    async fn rotate_if_needed(&mut self) -> Result<(), HealthError> {
        if self.current_size < self.max_file_size {
            return Ok(());
        }

        tracing::info!(
            machine_id = %self.machine_id,
            size = self.current_size,
            "Rotating log file"
        );

        if let Some(mut file) = self.current_file.take()
            && let Err(e) = file.flush().await
        {
            tracing::error!(error = ?e, "Failed to flush log file before rotation");
        }

        for i in (1..self.max_backups).rev() {
            let from_path = self.rotated_log_path(i);
            let to_path = self.rotated_log_path(i + 1);

            if tokio::fs::metadata(&from_path).await.is_ok()
                && let Err(e) = tokio::fs::rename(&from_path, &to_path).await
            {
                tracing::warn!(
                    error = ?e,
                    from = ?from_path,
                    to = ?to_path,
                    "Failed to rotate backup log file"
                );
            }
        }

        let current_path = self.current_log_path();
        let backup_path = self.rotated_log_path(1);

        if let Err(e) = tokio::fs::rename(&current_path, &backup_path).await {
            tracing::error!(
                error = ?e,
                "Failed to rotate current log file, will continue with new file"
            );
        }

        if self.max_backups > 0 {
            let oldest_path = self.rotated_log_path(self.max_backups + 1);
            if tokio::fs::metadata(&oldest_path).await.is_ok() {
                let _ = tokio::fs::remove_file(&oldest_path).await;
            }
        }

        self.current_size = 0;
        self.open_current_file().await?;

        Ok(())
    }

    async fn write_logs(&mut self, records: &[OtelLogRecord]) -> Result<(), HealthError> {
        let mut json = String::new();
        for record in records {
            json.push_str(&serde_json::to_string(record).map_err(|e| {
                HealthError::LoggerError(format!("Failed to serialize log record: {e}"))
            })?);
            json.push('\n');
        }

        let bytes = json.as_bytes();
        let write_size = bytes.len() as u64;

        self.rotate_if_needed().await?;

        if let Some(ref mut file) = self.current_file {
            file.write_all(bytes).await.map_err(|e| {
                HealthError::LoggerError(format!("Failed to write log record: {e}"))
            })?;

            file.flush()
                .await
                .map_err(|e| HealthError::LoggerError(format!("Failed to flush log file: {e}")))?;

            self.current_size += write_size;
        }

        Ok(())
    }
}

/// Logs collector for a single BMC endpoint
pub struct LogsCollector<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    bmc: Arc<B>,
    state_file_path: PathBuf,
    state: Option<LogsCollectorState<B>>,
    service_refresh_interval: Duration,
    log_writer: Arc<Mutex<LogFileWriter>>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for LogsCollector<B> {
    type Config = LogsCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        Ok(Self {
            bmc,
            endpoint,
            state_file_path: config.state_file_path,
            state: None,
            service_refresh_interval: config.service_refresh_interval,
            log_writer: config.log_writer,
        })
    }

    async fn run_iteration(&mut self) -> Result<collector::IterationResult, HealthError> {
        self.run_collection_iteration().await
    }

    fn collector_type(&self) -> &'static str {
        "logs_collector"
    }
}

impl<B: Bmc + 'static> LogsCollector<B> {
    fn redfish_severity_to_otel(severity: &str) -> (u8, String) {
        match severity.to_lowercase().as_str() {
            "critical" => (21, "FATAL".to_string()),
            "warning" => (13, "WARN".to_string()),
            "ok" => (9, "INFO".to_string()),
            _ => (1, "TRACE".to_string()),
        }
    }

    fn system_time_to_unix_nano(time: SystemTime) -> String {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string()
    }

    async fn load_persistent_state(&self) -> PersistentState {
        match tokio::fs::read_to_string(&self.state_file_path).await {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => PersistentState::default(),
        }
    }

    async fn save_persistent_state(&self) -> Result<(), HealthError> {
        if let Some(state) = &self.state {
            let state = PersistentState {
                last_seen_ids: state.last_seen_ids.clone(),
            };
            let json = serde_json::to_string_pretty(&state).map_err(|e| {
                HealthError::GenericError(format!("Failed to serialize state: {}", e))
            })?;

            tokio::fs::write(&self.state_file_path, json)
                .await
                .map_err(|e| HealthError::GenericError(format!("Failed to write state: {}", e)))?;
        }

        Ok(())
    }

    async fn discover_log_services(&self) -> Result<Vec<LogService<B>>, HealthError> {
        let service_root = ServiceRoot::new(self.bmc.clone()).await?;
        let mut services = Vec::new();
        let mut seen_ids = HashSet::new();

        if let Ok(manager_collection) = service_root.managers().await {
            for manager in manager_collection.members().await.unwrap_or_default() {
                if let Ok(log_services) = manager.log_services().await {
                    for service in log_services {
                        let service_id = service.odata_id().to_string();
                        if seen_ids.insert(service_id) {
                            services.push(service);
                        }
                    }
                }
            }
        }

        if let Ok(chassis_collection) = service_root.chassis().await {
            for chassis in chassis_collection.members().await.unwrap_or_default() {
                if let Ok(log_services) = chassis.log_services().await {
                    for service in log_services {
                        let service_id = service.odata_id().to_string();
                        if seen_ids.insert(service_id) {
                            services.push(service);
                        }
                    }
                }
            }
        }

        if let Ok(system_collection) = service_root.systems().await {
            for system in system_collection.members().await.unwrap_or_default() {
                if let Ok(log_services) = system.log_services().await {
                    for service in log_services {
                        let service_id = service.odata_id().to_string();
                        if seen_ids.insert(service_id) {
                            services.push(service);
                        }
                    }
                }
            }
        }

        tracing::info!(
            total_services = services.len(),
            "Discovered distinct log services"
        );

        Ok(services)
    }

    async fn run_collection_iteration(
        &mut self,
    ) -> Result<collector::IterationResult, HealthError> {
        let needs_refresh = self
            .state
            .as_ref()
            .map(|s| s.last_service_refresh.elapsed() > self.service_refresh_interval)
            .unwrap_or(true);

        let mut refresh_triggered = false;

        if needs_refresh {
            tracing::info!("Refreshing log services for BMC");
            match self.discover_log_services().await {
                Ok(services) => {
                    tracing::info!(
                        "Service discovery complete. Found {} log services",
                        services.len()
                    );

                    let persistent_state = self.load_persistent_state().await;

                    self.state = Some(LogsCollectorState {
                        discovered_services: services,
                        last_service_refresh: Instant::now(),
                        last_seen_ids: persistent_state.last_seen_ids,
                    });
                    refresh_triggered = true;
                }
                Err(e) => {
                    tracing::error!(error=?e, "Failed to discover log services");
                    if self.state.is_none() {
                        return Err(e);
                    }
                }
            }
        }

        let log_count = self.collect_logs_from_services().await?;
        self.save_persistent_state().await?;

        Ok(collector::IterationResult {
            refresh_triggered,
            entity_count: Some(log_count),
        })
    }

    async fn collect_logs_from_services(&mut self) -> Result<usize, HealthError> {
        let Some(EndpointMetadata::Machine(machine)) = &self.endpoint.metadata else {
            return Ok(0);
        };

        let Some(state) = self.state.as_mut() else {
            return Ok(0);
        };

        let mut total_log_count = 0;

        for service in &state.discovered_services {
            let last_seen_id = state.last_seen_ids.get(service.odata_id()).copied();

            let entries = match last_seen_id {
                Some(last_id) => {
                    let entries = match service
                        .filter_entries(FilterQuery::gt(&"Id", last_id))
                        .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!(
                                service_id = %service.odata_id(),
                                error = ?e,
                                "Failed to fetch filtered log entries, fetching all"
                            );
                            // Fallback - if filter is not supported properly
                            match service.entries().await {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::warn!(
                                        service_id = %service.odata_id(),
                                        error = ?e,
                                        "Failed to fetch log entries"
                                    );
                                    continue;
                                }
                            }
                        }
                    };

                    // We apply manual filter in either case, if BMC is returns all entries even with filter applied
                    entries
                        .into_iter()
                        .filter(|entry| {
                            entry
                                .base
                                .id
                                .parse::<i32>()
                                .ok()
                                .map(|id| id > last_id)
                                .unwrap_or(false)
                        })
                        .collect()
                }
                None => match service.entries().await {
                    Ok(e) => {
                        tracing::info!(
                            service_id = %service.odata_id(),
                            endpont=?self.endpoint.addr,
                            "Last seen id is empty, fetching all entries");
                        e
                    }
                    Err(e) => {
                        tracing::warn!(
                            service_id = %service.odata_id(),
                            error = ?e,
                            "Failed to fetch log entries"
                        );
                        continue;
                    }
                },
            };

            if entries.is_empty() {
                continue;
            }

            let mut max_id = last_seen_id.unwrap_or(0);
            let mut records = Vec::with_capacity(entries.len());

            for entry in &entries {
                let entry_timestamp = entry
                    .created
                    .as_ref()
                    .map(|dt| SystemTime::from(*dt))
                    .unwrap_or_else(SystemTime::now);

                let observed_timestamp = SystemTime::now();

                let (severity_number, severity_text) =
                    if let Some(Some(severity)) = entry.severity.as_ref() {
                        Self::redfish_severity_to_otel(&format!("{:?}", severity))
                    } else {
                        (9, "INFO".to_string())
                    };

                let body = if let Some(Some(msg)) = entry.message.as_ref() {
                    msg.clone()
                } else {
                    String::new()
                };

                let mut attributes = HashMap::new();
                attributes.insert(
                    "machineid".to_string(),
                    JsonValue::String(machine.machine_id.to_string()),
                );
                attributes.insert("type".to_string(), JsonValue::String("bmc_log".to_string()));
                attributes.insert(
                    "entry_id".to_string(),
                    JsonValue::String(entry.base.id.clone()),
                );
                attributes.insert(
                    "bmc_entry_type".to_string(),
                    JsonValue::String(format!("{:?}", entry.entry_type)),
                );

                if let Some(Some(severity)) = entry.severity.as_ref() {
                    attributes.insert(
                        "severity".to_string(),
                        JsonValue::String(format!("{:?}", severity)),
                    );
                }

                if let Some(args) = &entry.message_args {
                    let array_values: Vec<JsonValue> = args
                        .iter()
                        .map(|arg| JsonValue::String(arg.clone()))
                        .collect();
                    attributes.insert("message_args".to_string(), JsonValue::Array(array_values));
                }

                let otel_record = OtelLogRecord {
                    time_unix_nano: Self::system_time_to_unix_nano(entry_timestamp),
                    observed_time_unix_nano: Self::system_time_to_unix_nano(observed_timestamp),
                    severity_number,
                    severity_text,
                    body,
                    attributes,
                };

                records.push(otel_record);

                if let Ok(entry_id) = entry.base.id.parse::<i32>() {
                    max_id = max_id.max(entry_id);
                }
            }

            if let Err(e) = self.log_writer.lock().await.write_logs(&records).await {
                tracing::error!(
                    error = ?e,
                    "Failed to write log entries to file"
                );
            } else {
                if max_id > last_seen_id.unwrap_or(0) {
                    state
                        .last_seen_ids
                        .insert(service.odata_id().clone(), max_id);
                }
                total_log_count += entries.len();
            }
        }

        Ok(total_log_count)
    }
}
