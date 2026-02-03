/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nv_redfish_bmc_http::HttpBmc;
use nv_redfish_bmc_http::reqwest::{
    BmcError, Client as ReqwestClient, ClientParams as ReqwestClientParams,
};
use prometheus::{Histogram, HistogramOpts};

use crate::HealthError;
use crate::api_client::{EndpointSource, HealthReportSink};
use crate::collector::Collector;
use crate::config::{
    Config, Configurable, FirmwareCollectorConfig as FirmwareCollectorOptions,
    HealthCollectorConfig as HealthCollectorOptions, LogsCollectorConfig as LogsCollectorOptions,
};
use crate::firmware_collector::{FirmwareCollector, FirmwareCollectorConfig};
use crate::limiter::RateLimiter;
use crate::logs_collector::{self, LogsCollector, LogsCollectorConfig};
use crate::metrics::MetricsManager;
use crate::monitor::{HealthMonitor, HealthMonitorConfig};
use crate::sharding::ShardManager;

pub(crate) type BmcClient = HttpBmc<ReqwestClient>;

#[derive(Debug, Clone)]
pub struct DiscoveryIterationStats {
    pub discovered_endpoints: usize,
    pub sharded_endpoints: usize,
    pub active_monitors: usize,
}

pub struct DiscoveryLoopContext {
    pub(crate) endpoint_monitors: HashMap<String, Collector>,
    pub(crate) logs_collectors: HashMap<String, Collector>,
    pub(crate) firmware_collectors: HashMap<String, Collector>,
    pub(crate) discovery_iteration_histogram: Histogram,
    pub(crate) discovery_endpoint_fetch_histogram: Histogram,
    pub(crate) client: ReqwestClient,
    pub(crate) limiter: Arc<dyn RateLimiter>,
    pub(crate) metrics_manager: Arc<MetricsManager>,
    pub(crate) config: Arc<Config>,
    pub(crate) health_config: Configurable<HealthCollectorOptions>,
    pub(crate) logs_config: Configurable<LogsCollectorOptions>,
    pub(crate) firmware_config: Configurable<FirmwareCollectorOptions>,
}

impl DiscoveryLoopContext {
    pub fn new(
        limiter: Arc<dyn RateLimiter>,
        metrics_manager: Arc<MetricsManager>,
        config: Arc<Config>,
    ) -> Result<Self, HealthError> {
        let registry = metrics_manager.global_registry();

        let metrics_prefix = &config.metrics.prefix;

        let discovery_iteration_histogram = Histogram::with_opts(HistogramOpts::new(
            format!("{metrics_prefix}_discovery_iteration_seconds"),
            "Duration of full discovery loop iteration",
        ))?;
        registry.register(Box::new(discovery_iteration_histogram.clone()))?;

        let discovery_endpoint_fetch_histogram = Histogram::with_opts(HistogramOpts::new(
            format!("{metrics_prefix}_discovery_endpoint_fetch_seconds"),
            "Duration of API call to fetch BMC endpoints",
        ))?;
        registry.register(Box::new(discovery_endpoint_fetch_histogram.clone()))?;

        let client =
            ReqwestClient::with_params(ReqwestClientParams::new().accept_invalid_certs(true))
                .map_err(BmcError::ReqwestError)?;

        let health_config = config.collectors.health.clone();
        let logs_config = config.collectors.logs.clone();
        let firmware_config = config.collectors.firmware.clone();

        Ok(Self {
            endpoint_monitors: HashMap::new(),
            logs_collectors: HashMap::new(),
            firmware_collectors: HashMap::new(),
            discovery_iteration_histogram,
            discovery_endpoint_fetch_histogram,
            client,
            limiter,
            metrics_manager,
            config,
            health_config,
            logs_config,
            firmware_config,
        })
    }
}

pub async fn run_discovery_iteration(
    endpoint_source: Arc<dyn EndpointSource>,
    shard_manager: &ShardManager,
    ctx: &mut DiscoveryLoopContext,
    report_sink: Option<Arc<dyn HealthReportSink>>,
    metrics_prefix: &String,
) -> Result<DiscoveryIterationStats, HealthError> {
    let iteration_start = Instant::now();

    let fetch_start = Instant::now();
    let endpoints = match endpoint_source.fetch_bmc_hosts().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=?e, "Could not fetch endpoints");
            return Err(e);
        }
    };
    let fetch_duration = fetch_start.elapsed();

    ctx.discovery_endpoint_fetch_histogram
        .observe(fetch_duration.as_secs_f64());

    let sharded_endpoints: Vec<_> = endpoints
        .iter()
        .filter(|ep| shard_manager.should_monitor(&ep.addr))
        .collect();

    if sharded_endpoints.is_empty() {
        tracing::warn!("No endpoints assigned to this shard");
    } else {
        tracing::info!(
            endpoint_count = sharded_endpoints.len(),
            "Discovered and sharded BMC endpoints"
        );
    }

    for endpoint in &sharded_endpoints {
        let key = endpoint.addr.hash_key().to_string();
        if !ctx.endpoint_monitors.contains_key(&key) {
            let endpoint_arc = Arc::new((*endpoint).clone());
            let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
                format!("health_monitor_collector_{}", endpoint.addr.hash_key()),
                metrics_prefix,
            )?);

            if let Configurable::Enabled(health_cfg) = &ctx.health_config {
                match Collector::start::<HealthMonitor<BmcClient>>(
                    endpoint_arc.clone(),
                    ctx.limiter.clone(),
                    health_cfg.sensor_fetch_interval,
                    HealthMonitorConfig {
                        report_sink: report_sink.clone(),
                        state_refresh_interval: health_cfg.state_refresh_interval,
                        sensor_fetch_concurrency: health_cfg.sensor_fetch_concurrency,
                        collector_registry: collector_registry.clone(),
                    },
                    collector_registry,
                    ctx.client.clone(),
                    &ctx.config,
                ) {
                    Ok(monitor) => {
                        ctx.endpoint_monitors.insert(key.to_string(), monitor);
                        tracing::info!(
                            endpoint_key = %key,
                            total_monitors = ctx.endpoint_monitors.len(),
                            "Started health monitoring for BMC endpoint"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error=?e,
                            "Could not start health monitor for: {:?}",
                            endpoint.addr
                        );
                        continue;
                    }
                }
            }

            if let Configurable::Enabled(logs_cfg) = &ctx.logs_config
                && let Some(machne) = &endpoint.machine
            {
                let state_file_path = PathBuf::from(
                    logs_cfg
                        .logs_state_file
                        .replace("{machine_id}", &machne.machine_id.to_string()),
                );
                let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
                    format!("log_collector_{}", endpoint.addr.hash_key()),
                    metrics_prefix,
                )?);

                let log_writer = match logs_collector::create_log_file_writer(
                    PathBuf::from(&logs_cfg.logs_output_dir),
                    machne.machine_id.to_string(),
                    logs_cfg.logs_max_file_size,
                    logs_cfg.logs_max_backups,
                )
                .await
                {
                    Ok(writer) => Arc::new(tokio::sync::Mutex::new(writer)),
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            machine_id = %machne.machine_id,
                            "Failed to create log file writer, skipping logs collector"
                        );
                        continue;
                    }
                };

                match Collector::start::<LogsCollector<BmcClient>>(
                    endpoint_arc.clone(),
                    ctx.limiter.clone(),
                    logs_cfg.logs_collection_interval,
                    LogsCollectorConfig {
                        state_file_path,
                        service_refresh_interval: ctx
                            .health_config
                            .as_option()
                            .map(|h| h.state_refresh_interval)
                            .unwrap_or(Duration::from_secs(1800)),
                        log_writer,
                    },
                    collector_registry,
                    ctx.client.clone(),
                    &ctx.config,
                ) {
                    Ok(collector) => {
                        ctx.logs_collectors.insert(key.to_string(), collector);
                        tracing::info!(
                            endpoint_key = %key,
                            total_collectors = ctx.logs_collectors.len(),
                            "Started logs collection for BMC endpoint"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error=?e,
                            "Could not start logs collector for: {:?}",
                            endpoint.addr
                        )
                    }
                }
            }

            if let Configurable::Enabled(firmware_cfg) = &ctx.firmware_config {
                let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
                    format!("firmware_collector_{}", endpoint.addr.hash_key()),
                    metrics_prefix,
                )?);
                match Collector::start::<FirmwareCollector<BmcClient>>(
                    endpoint_arc,
                    ctx.limiter.clone(),
                    firmware_cfg.firmware_refresh_interval,
                    FirmwareCollectorConfig {
                        collector_registry: collector_registry.clone(),
                    },
                    collector_registry,
                    ctx.client.clone(),
                    &ctx.config,
                ) {
                    Ok(collector) => {
                        ctx.firmware_collectors.insert(key.to_string(), collector);
                        tracing::info!(
                            endpoint_key = %key,
                            total_firmware_collectors = ctx.firmware_collectors.len(),
                            "Started firmware collection for BMC endpoint"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error=?e,
                            "Could not start firmware collector for: {:?}",
                            endpoint.addr
                        )
                    }
                }
            }
        }
    }

    // Stop monitors for endpoints no longer in the shard
    let active_endpoints: HashSet<_> = sharded_endpoints
        .iter()
        .map(|e| e.addr.hash_key())
        .collect();

    let removed_keys: Vec<_> = ctx
        .endpoint_monitors
        .keys()
        .filter(|key| !active_endpoints.contains(key.as_str()))
        .cloned()
        .collect();

    for key in &removed_keys {
        // Stop health monitor
        if let Some(monitor) = ctx.endpoint_monitors.remove(key) {
            tracing::info!(
                endpoint_key = %key,
                remaining_monitors = ctx.endpoint_monitors.len(),
                "Stopping health monitor for removed BMC endpoint"
            );
            // Spawn graceful shutdown in background to avoid blocking the discovery loop
            tokio::spawn(async move {
                monitor.stop().await;
            });
        }

        // Stop logs collector
        if let Some(collector) = ctx.logs_collectors.remove(key) {
            tracing::info!(
                endpoint_key = %key,
                remaining_collectors = ctx.logs_collectors.len(),
                "Stopping logs collector for removed BMC endpoint"
            );
            // Spawn graceful shutdown in background to avoid blocking the discovery loop
            tokio::spawn(async move {
                collector.stop().await;
            });
        }

        // Stop firmware collector
        if let Some(collector) = ctx.firmware_collectors.remove(key) {
            tracing::info!(
                endpoint_key = %key,
                remaining_firmware_collectors = ctx.firmware_collectors.len(),
                "Stopping firmware collector for removed BMC endpoint"
            );
            // Spawn graceful shutdown in background to avoid blocking the discovery loop
            tokio::spawn(async move {
                collector.stop().await;
            });
        }
    }

    if !removed_keys.is_empty() {
        tracing::info!(
            removed_count = removed_keys.len(),
            remaining_monitors = ctx.endpoint_monitors.len(),
            remaining_collectors = ctx.logs_collectors.len(),
            remaining_firmware_collectors = ctx.firmware_collectors.len(),
            "Cleaned up removed endpoints"
        );
    }

    let iteration_duration = iteration_start.elapsed();
    ctx.discovery_iteration_histogram
        .observe(iteration_duration.as_secs_f64());

    Ok(DiscoveryIterationStats {
        discovered_endpoints: endpoints.len(),
        sharded_endpoints: sharded_endpoints.len(),
        active_monitors: ctx.endpoint_monitors.len(),
    })
}
