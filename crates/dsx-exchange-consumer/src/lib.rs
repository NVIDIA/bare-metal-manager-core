/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! DSX Exchange Consumer microservice for BMS leak detection events.
//!
//! This service consumes leak detection events from the Cronus MQTT event bus
//! and updates rack-level health overrides in the Carbide API.

use std::sync::Arc;

pub mod api_client;
pub mod config;
pub mod health_updater;
pub mod messages;
pub mod metrics;
pub mod mqtt_consumer;

pub use config::Config;
pub use metrics::ConsumerMetrics;

use crate::api_client::{ApiClientWrapper, ConsoleRackHealthSink};
use crate::health_updater::HealthUpdater;

#[derive(thiserror::Error, Debug)]
pub enum DsxConsumerError {
    #[error("API call failed: {0}")]
    Api(#[from] tonic::Status),

    #[error("Configuration invalid: {0}")]
    Config(String),

    #[error("MQTT operation failed: {0}")]
    Mqtt(String),

    #[error("Metrics setup failed: {0}")]
    Metrics(String),
}

pub async fn run_service(config: Config) -> Result<(), DsxConsumerError> {
    let metrics_endpoint = config.metrics_addr().map_err(DsxConsumerError::Config)?;

    // Set up OpenTelemetry + Prometheus metrics
    let metrics_setup =
        metrics_endpoint::new_metrics_setup("carbide-dsx-exchange-consumer", "carbide", false)
            .map_err(|e| DsxConsumerError::Metrics(e.to_string()))?;

    let registry = metrics_setup.registry;
    let meter = metrics_setup.meter;

    // Spawn metrics server
    let metrics_config = metrics_endpoint::MetricsEndpointConfig {
        address: metrics_endpoint,
        registry,
        health_controller: Some(metrics_setup.health_controller),
    };
    let join_listener =
        tokio::spawn(async move { metrics_endpoint::run_metrics_endpoint(&metrics_config).await });

    // Create consumer metrics
    let consumer_metrics = ConsumerMetrics::new(&meter);

    // Connect to MQTT and get message receiver
    let rx = mqtt_consumer::connect(&config.mqtt, consumer_metrics.clone()).await?;

    // Set up API client and create health updater
    let join_updater = if let Some(api_config) = config.carbide_api {
        let api_client = Arc::new(ApiClientWrapper::new(
            api_config.root_ca,
            api_config.client_cert,
            api_config.client_key,
            &api_config.api_url,
        ));
        let health_updater = HealthUpdater::new(
            config.mqtt.topic_prefix,
            config.cache,
            api_client,
            consumer_metrics,
            meter,
        );
        tokio::spawn(async move { health_updater.run(rx).await })
    } else {
        tracing::warn!("Carbide API disabled, using console sink");
        let api_client = Arc::new(ConsoleRackHealthSink);
        let health_updater = HealthUpdater::new(
            config.mqtt.topic_prefix,
            config.cache,
            api_client,
            consumer_metrics,
            meter,
        );
        tokio::spawn(async move { health_updater.run(rx).await })
    };

    tokio::select! {
        res = join_listener => {
            match res {
                Ok(Ok(_)) => tracing::info!("Metrics listener shutdown"),
                Ok(Err(e)) => tracing::error!(error=?e, "Metrics listener failed"),
                Err(e) => tracing::error!(error=?e, "Metrics listener join error"),
            }
        }
        res = join_updater => {
            match res {
                Ok(_) => tracing::info!("Health updater shutdown"),
                Err(e) => tracing::error!(error=?e, "Health updater join error"),
            }
        }
    };

    Ok(())
}
