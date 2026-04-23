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

use std::sync::Arc;
use std::time::Duration;

use nv_redfish::bmc_http::reqwest::BmcError;
use prometheus::{Gauge, GaugeVec, Opts};

pub mod api_client;
pub mod collectors;
pub mod config;
pub mod discovery;
pub mod endpoint;
pub mod limiter;
pub mod metrics;
pub mod otlp;
pub mod processor;
pub mod sharding;
pub mod sink;

pub use config::Config;
pub use discovery::{DiscoveryIterationStats, DiscoveryLoopContext};

use crate::api_client::ApiClientWrapper;
use crate::config::Configurable;
use crate::endpoint::{CompositeEndpointSource, EndpointSource, StaticEndpointSource};
use crate::limiter::{BucketLimiter, NoopLimiter, RateLimiter};
use crate::metrics::{MetricsManager, run_metrics_server};
use crate::processor::{
    EventProcessingPipeline, EventProcessor, HealthReportProcessor, LeakEventProcessor,
    RackLeakProcessor,
};
use crate::sharding::ShardManager;
use crate::sink::event_mapper::{OpenBmcEventMapper, RedfishEventMapper};
use crate::sink::{
    CompositeDataSink, DataSink, HealthOverrideSink, LogFileSink, OtlpSink, PrometheusSink,
    RackHealthOverrideSink, TracingSink,
};

#[derive(thiserror::Error, Debug)]
pub enum HealthError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(String),

    #[error("The API call to the Carbide API server returned {0}")]
    ApiInvocationError(tonic::Status),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Logger Error: {0}")]
    LoggerError(String),

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Tokio Task Join Error {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("Prometheus Error {0}")]
    PrometheusError(#[from] prometheus::Error),

    #[error("BMC Error: {0}")]
    BmcError(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("HTTP(S) error: {0}")]
    HttpError(String),

    #[error("Redfish SSE not available: {0}")]
    SseNotAvailable(String),
}

impl From<String> for HealthError {
    fn from(err: String) -> Self {
        HealthError::GenericError(err)
    }
}

impl From<BmcError> for HealthError {
    fn from(err: BmcError) -> Self {
        HealthError::BmcError(Box::new(err))
    }
}

impl<B: nv_redfish::core::Bmc + 'static> From<nv_redfish::Error<B>> for HealthError {
    fn from(err: nv_redfish::Error<B>) -> Self {
        HealthError::BmcError(Box::new(err))
    }
}

struct EndpointWiring {
    source: Arc<dyn EndpointSource>,
}

fn build_endpoint_wiring(config: &Config) -> Result<EndpointWiring, HealthError> {
    let mut sources: Vec<Arc<dyn EndpointSource>> = Vec::new();

    if !config.endpoint_sources.static_bmc_endpoints.is_empty() {
        let static_source = StaticEndpointSource::from_config(
            config.endpoint_sources.static_bmc_endpoints.as_slice(),
        );
        sources.push(Arc::new(static_source));
    }

    if let Configurable::Enabled(ref source_cfg) = config.endpoint_sources.carbide_api {
        let api_client = Arc::new(ApiClientWrapper::new(
            source_cfg.root_ca.clone(),
            source_cfg.client_cert.clone(),
            source_cfg.client_key.clone(),
            &source_cfg.api_url,
        ));
        sources.push(api_client as Arc<dyn EndpointSource>);
    }

    let composite_source = CompositeEndpointSource::new(sources);

    if composite_source.is_empty() {
        return Err(HealthError::GenericError(
            "no endpoint sources configured".to_string(),
        ));
    }

    Ok(EndpointWiring {
        source: Arc::new(composite_source),
    })
}

fn build_data_sink(
    config: &Config,
    metrics_manager: Arc<MetricsManager>,
) -> Result<Option<Arc<dyn DataSink>>, HealthError> {
    let mut sinks: Vec<Arc<dyn DataSink>> = Vec::new();
    let mut processors: Vec<Arc<dyn EventProcessor>> = Vec::new();

    if let Configurable::Enabled(_) = &config.sinks.tracing {
        sinks.push(Arc::new(TracingSink));
    }

    if let Configurable::Enabled(_) = &config.sinks.prometheus {
        sinks.push(Arc::new(PrometheusSink::new(
            metrics_manager.clone(),
            &config.metrics.prefix,
        )?));
    }

    if config.sinks.tracing.is_enabled()
        || config.sinks.health_override.is_enabled()
        || config.processors.leak_detection.is_enabled()
    {
        processors.push(Arc::new(HealthReportProcessor::new()));
    }

    if let Configurable::Enabled(ref leak_detection_cfg) = config.processors.leak_detection {
        processors.push(Arc::new(LeakEventProcessor::new(
            leak_detection_cfg.minimum_alerts_per_report,
        )));
    }

    if let Configurable::Enabled(ref rack_leak_cfg) = config.processors.rack_leak {
        processors.push(Arc::new(RackLeakProcessor::new(
            rack_leak_cfg.leaking_tray_threshold,
        )));
    }

    if let Configurable::Enabled(ref sink_cfg) = config.sinks.log_file {
        sinks.push(Arc::new(
            LogFileSink::new(sink_cfg).map_err(HealthError::GenericError)?,
        ));
    }

    if let Configurable::Enabled(ref sink_cfg) = config.sinks.health_override {
        sinks.push(Arc::new(HealthOverrideSink::new(sink_cfg)?));
    }

    if let Configurable::Enabled(ref sink_cfg) = config.sinks.rack_health_override {
        sinks.push(Arc::new(RackHealthOverrideSink::new(sink_cfg)?));
    }

    if let Configurable::Enabled(ref otlp_cfg) = config.sinks.otlp {
        let mapper: Arc<dyn RedfishEventMapper> = Arc::new(OpenBmcEventMapper);
        sinks.push(Arc::new(OtlpSink::new(
            otlp_cfg,
            mapper,
            &metrics_manager,
            &config.metrics.prefix,
        )?));
    }

    if sinks.is_empty() {
        return Ok(None);
    }

    let composite_sink: Arc<dyn DataSink> =
        Arc::new(CompositeDataSink::new(sinks, metrics_manager.clone()));

    if processors.is_empty() {
        return Ok(Some(composite_sink));
    }

    Ok(Some(Arc::new(EventProcessingPipeline::new(
        processors,
        composite_sink,
        metrics_manager,
    ))))
}

pub async fn run_service(config: Config) -> Result<(), HealthError> {
    let metrics_endpoint = config.metrics_addr()?;
    let metrics_manager = Arc::new(MetricsManager::new(&config.metrics.prefix)?);

    let join_listener = tokio::spawn(run_metrics_server(
        metrics_endpoint,
        metrics_manager.clone(),
    ));

    let registry = metrics_manager.global_registry();
    let active_endpoints_gauge = Gauge::new(
        format!(
            "{metrics_prefix}_active_endpoints",
            metrics_prefix = &config.metrics.prefix
        ),
        "Current number of active endpoints",
    )?;
    registry.register(Box::new(active_endpoints_gauge.clone()))?;

    let discovery_endpoints_gauge = GaugeVec::new(
        Opts::new(
            format!(
                "{metrics_prefix}_discovery_endpoints",
                metrics_prefix = &config.metrics.prefix
            ),
            "Number of endpoints at each discovery stage",
        ),
        &["status"],
    )?;
    registry.register(Box::new(discovery_endpoints_gauge.clone()))?;

    let EndpointWiring {
        source: endpoint_source,
    } = build_endpoint_wiring(&config)?;

    let data_sink = build_data_sink(&config, metrics_manager.clone())?;

    let config_arc = Arc::new(config);

    let join_discovery: tokio::task::JoinHandle<Result<(), HealthError>> = tokio::spawn({
        let config = config_arc.clone();
        let shard_manager = ShardManager {
            shard: config.shard,
            shards_count: config.shards_count,
        };
        let limiter: Arc<dyn RateLimiter> =
            if let Configurable::Enabled(rate_limit) = &config.rate_limit {
                Arc::new(BucketLimiter::new(
                    rate_limit.bucket_burst,
                    rate_limit.bucket_replenish,
                    rate_limit.max_jitter,
                ))
            } else {
                Arc::new(NoopLimiter)
            };
        let metrics_manager = metrics_manager.clone();
        let active_endpoints_gauge = active_endpoints_gauge.clone();
        let discovery_endpoints_gauge = discovery_endpoints_gauge.clone();
        let endpoint_source = endpoint_source.clone();
        let data_sink = data_sink.clone();

        let mut ctx = DiscoveryLoopContext::new(limiter, metrics_manager, config.clone())?;

        async move {
            loop {
                let stats = discovery::run_discovery_iteration(
                    endpoint_source.clone(),
                    &shard_manager,
                    &mut ctx,
                    data_sink.clone(),
                    &config.metrics.prefix,
                )
                .await?;

                discovery_endpoints_gauge
                    .get_metric_with_label_values(&["discovered"])?
                    .set(stats.discovered_endpoints as f64);
                discovery_endpoints_gauge
                    .get_metric_with_label_values(&["sharded"])?
                    .set(stats.sharded_endpoints as f64);
                active_endpoints_gauge.set(stats.active_monitors as f64);

                tokio::time::sleep(
                    config
                        .collectors
                        .sensors
                        .as_option()
                        .map(|s| s.rediscover_interval)
                        .unwrap_or(Duration::from_secs(300)),
                )
                .await;
            }
        }
    });

    tokio::select! {
        res = join_listener => {
            match res {
                Ok(Ok(_)) => {
                    tracing::info!("Metrics listener shutdown");
                }
                 Ok(Err(e)) => {
                    tracing::error!(error=?e, "Metrics listener failed");
                }
                Err(e) => {
                    tracing::error!(error=?e, "Metrics listener join error");
                }
            }
        }
        res = join_discovery => {
            match res {
                Ok(Ok(_)) => {
                    tracing::error!("Discovery loop shutdown");
                }
                Ok(Err(e)) => {
                    tracing::error!(error=?e, "Discovery loop ended unexpectedly");
                }
                Err(e) => {
                    tracing::error!(error=?e, "Discovery loop join error");
                }
            }
        }
    };

    Ok(())
}
