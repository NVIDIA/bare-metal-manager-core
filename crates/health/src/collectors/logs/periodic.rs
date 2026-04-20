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

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nv_redfish::core::{Bmc, FilterQuery, ODataId};
use nv_redfish::log_service::LogService;
use nv_redfish::{Resource, ServiceRoot};
use serde::{Deserialize, Serialize};

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::sink::{CollectorEvent, DataSink, EventContext, LogRecord};

/// Configuration for logs collector
pub struct LogsCollectorConfig {
    pub state_file_path: PathBuf,
    pub service_refresh_interval: Duration,
    pub data_sink: Option<Arc<dyn DataSink>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistentState {
    last_seen_ids: HashMap<ODataId, i32>,
}

#[derive(Serialize)]
struct PersistentStateRef<'a> {
    last_seen_ids: &'a HashMap<ODataId, i32>,
}

struct LogsCollectorState<B: Bmc> {
    discovered_services: Vec<LogService<B>>,
    last_service_refresh: Instant,
    last_seen_ids: HashMap<ODataId, i32>,
}

/// Logs collector for a single BMC endpoint
pub struct LogsCollector<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    bmc: Arc<B>,
    event_context: EventContext,
    state_file_path: PathBuf,
    state: Option<LogsCollectorState<B>>,
    service_refresh_interval: Duration,
    data_sink: Option<Arc<dyn DataSink>>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for LogsCollector<B> {
    type Config = LogsCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "logs_collector");
        Ok(Self {
            bmc,
            endpoint,
            event_context,
            state_file_path: config.state_file_path,
            state: None,
            service_refresh_interval: config.service_refresh_interval,
            data_sink: config.data_sink,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
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

    async fn load_persistent_state(&self) -> PersistentState {
        match tokio::fs::read_to_string(&self.state_file_path).await {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => PersistentState::default(),
        }
    }

    async fn save_persistent_state(&self) -> Result<(), HealthError> {
        if let Some(state) = &self.state {
            let json = serde_json::to_string_pretty(&PersistentStateRef {
                last_seen_ids: &state.last_seen_ids,
            })
            .map_err(|e| HealthError::GenericError(format!("Failed to serialize state: {}", e)))?;

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

        if let Ok(Some(manager_collection)) = service_root.managers().await {
            for manager in manager_collection.members().await.iter().flatten() {
                if let Ok(Some(log_services)) = manager.log_services().await {
                    for service in log_services {
                        let service_id = service.odata_id().to_string();
                        if seen_ids.insert(service_id) {
                            services.push(service);
                        }
                    }
                }
            }
        }

        if let Ok(Some(chassis_collection)) = service_root.chassis().await {
            for chassis in chassis_collection.members().await.iter().flatten() {
                if let Ok(Some(log_services)) = chassis.log_services().await {
                    for service in log_services {
                        let service_id = service.odata_id().to_string();
                        if seen_ids.insert(service_id) {
                            services.push(service);
                        }
                    }
                }
            }
        }

        if let Ok(Some(system_collection)) = service_root.systems().await {
            for system in system_collection.members().await.iter().flatten() {
                if let Ok(Some(log_services)) = system.log_services().await {
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

    async fn run_collection_iteration(&mut self) -> Result<IterationResult, HealthError> {
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

        let (log_count, fetch_failures) = self.collect_logs_from_services().await?;
        self.save_persistent_state().await?;

        Ok(IterationResult {
            refresh_triggered,
            entity_count: Some(log_count),
            fetch_failures,
        })
    }

    async fn collect_logs_from_services(&mut self) -> Result<(usize, usize), HealthError> {
        let Some(EndpointMetadata::Machine(machine)) = &self.endpoint.metadata else {
            return Ok((0, 0));
        };
        let machine_id = machine.machine_id.to_string();

        let Some(state) = self.state.as_mut() else {
            return Ok((0, 0));
        };

        let mut total_log_count = 0;
        let mut fetch_failures = 0;

        for service in &state.discovered_services {
            let service_id = service.odata_id().to_string();
            let last_seen_id = state.last_seen_ids.get(service.odata_id()).copied();

            let entries = match last_seen_id {
                Some(last_id) => {
                    let entries = match service
                        .filter_entries(FilterQuery::gt(&"Id", last_id))
                        .await
                    {
                        Ok(Some(e)) => e,
                        Ok(None) => continue,
                        Err(error) => {
                            tracing::debug!(
                                %service_id,
                                ?error,
                                "Failed to fetch filtered log entries, fetching all"
                            );
                            // Fallback - if filter is not supported properly
                            match service.entries().await {
                                Ok(Some(e)) => e,
                                Ok(None) => continue,
                                Err(error) => {
                                    fetch_failures += 1;
                                    tracing::warn!(
                                        %service_id,
                                        ?error,
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
                    Ok(Some(v)) => {
                        tracing::info!(
                            %service_id,
                            endpoint=?self.endpoint.addr,
                            "Last seen id is empty, fetching all entries");
                        v
                    }
                    Ok(None) => {
                        continue;
                    }
                    Err(error) => {
                        fetch_failures += 1;
                        tracing::warn!(
                            %service_id,
                            ?error,
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

            for entry in &entries {
                let severity_text = if let Some(Some(severity)) = entry.severity.as_ref() {
                    Self::redfish_severity_to_otel(&format!("{:?}", severity)).1
                } else {
                    "INFO".to_string()
                };

                let body = if let Some(Some(msg)) = entry.message.as_ref() {
                    msg.clone()
                } else {
                    String::new()
                };

                let log_event = CollectorEvent::Log(
                    LogRecord {
                        body,
                        severity: severity_text,
                        attributes: vec![
                            (Cow::Borrowed("machine_id"), machine_id.clone()),
                            (Cow::Borrowed("entry_id"), entry.base.id.clone()),
                            (Cow::Borrowed("service_id"), service_id.clone()),
                        ],
                    }
                    .into(),
                );
                if let Some(data_sink) = &self.data_sink {
                    data_sink.handle_event(&self.event_context, &log_event);
                }

                if let Ok(entry_id) = entry.base.id.parse::<i32>() {
                    max_id = max_id.max(entry_id);
                }
            }

            if max_id > last_seen_id.unwrap_or(0) {
                state
                    .last_seen_ids
                    .insert(service.odata_id().clone(), max_id);
            }
            total_log_count += entries.len();
        }

        Ok((total_log_count, fetch_failures))
    }
}
