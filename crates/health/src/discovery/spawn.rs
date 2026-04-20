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

use std::path::PathBuf;
use std::sync::Arc;

use super::context::{BmcClient, CollectorKind, DiscoveryLoopContext};
use crate::HealthError;
use crate::collectors::{
    BackoffConfig, Collector, CollectorStartContext, FirmwareCollector, FirmwareCollectorConfig,
    LogsCollector, LogsCollectorConfig, NmxtCollector, NmxtCollectorConfig, NvueRestCollector,
    NvueRestCollectorConfig, SensorCollector, SensorCollectorConfig, SseLogCollector,
    SseLogCollectorConfig, StreamingCollectorStartContext,
};
use crate::config::{Configurable, LogCollectionMode};
use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::sink::DataSink;

fn logs_state_file_path(template: &str, endpoint_id: &str) -> PathBuf {
    PathBuf::from(template.replace("{machine_id}", endpoint_id))
}

pub(super) async fn spawn_collectors_for_endpoint(
    ctx: &mut DiscoveryLoopContext,
    endpoint: &Arc<BmcEndpoint>,
    data_sink: Option<Arc<dyn DataSink>>,
    metrics_prefix: &str,
) -> Result<(), HealthError> {
    let key = endpoint.hash_key();
    let endpoint_arc = endpoint.clone();
    if let Configurable::Enabled(sensor_cfg) = &ctx.sensors_config
        && !ctx.collectors.contains(CollectorKind::Sensor, &key)
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("sensor_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<SensorCollector<BmcClient>>(
            endpoint_arc.clone(),
            SensorCollectorConfig {
                data_sink: data_sink.clone(),
                state_refresh_interval: sensor_cfg.state_refresh_interval,
                sensor_fetch_concurrency: sensor_cfg.sensor_fetch_concurrency,
                include_sensor_thresholds: sensor_cfg.include_sensor_thresholds,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: sensor_cfg.sensor_fetch_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
                client: ctx.client.clone(),
                health_options: ctx.config.clone(),
            },
        ) {
            Ok(monitor) => {
                ctx.collectors
                    .insert(CollectorKind::Sensor, key.clone(), monitor);
                tracing::info!(
                    endpoint_key = %key,
                    total_collectors = ctx.collectors.len(CollectorKind::Sensor),
                    "Started sensor collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start sensor collector for: {:?}",
                    endpoint.addr
                );
            }
        }
    }

    if let Configurable::Enabled(logs_cfg) = &ctx.logs_config
        && !ctx.collectors.contains(CollectorKind::Logs, &key)
    {
        let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
            format!("log_collector_{}", endpoint.hash_key()),
            metrics_prefix,
        )?);

        let result = match logs_cfg.mode {
            LogCollectionMode::Sse => {
                if let Some(data_sink) = data_sink.clone() {
                    Some(Collector::start_streaming::<SseLogCollector<BmcClient>>(
                        endpoint_arc.clone(),
                        SseLogCollectorConfig,
                        data_sink,
                        StreamingCollectorStartContext {
                            backoff_config: BackoffConfig::default(),
                            collector_registry,
                            client: ctx.client.clone(),
                            health_options: ctx.config.clone(),
                        },
                    ))
                } else {
                    tracing::warn!("SSE log collector requires a data sink, skipping");
                    None
                }
            }
            LogCollectionMode::Periodic => {
                if let Some(pcfg) = &logs_cfg.periodic {
                    let endpoint_id = endpoint.log_identity().into_owned();
                    let state_file_path = logs_state_file_path(&pcfg.logs_state_file, &endpoint_id);

                    Some(Collector::start::<LogsCollector<BmcClient>>(
                        endpoint_arc.clone(),
                        LogsCollectorConfig {
                            state_file_path,
                            service_refresh_interval: pcfg.state_refresh_interval,
                            data_sink: data_sink.clone(),
                        },
                        CollectorStartContext {
                            limiter: ctx.limiter.clone(),
                            iteration_interval: pcfg.logs_collection_interval,
                            collector_registry,
                            metrics_manager: ctx.metrics_manager.clone(),
                            client: ctx.client.clone(),
                            health_options: ctx.config.clone(),
                        },
                    ))
                } else {
                    tracing::error!(
                        endpoint = ?endpoint.addr,
                        "periodic log config missing but mode is periodic, skipping"
                    );
                    None
                }
            }
        };

        match result {
            Some(Ok(collector)) => {
                ctx.collectors
                    .insert(CollectorKind::Logs, key.clone(), collector);
                tracing::info!(
                    endpoint_key = %key,
                    mode = ?logs_cfg.mode,
                    total_collectors = ctx.collectors.len(CollectorKind::Logs),
                    "Started logs collection for BMC endpoint"
                );
            }
            Some(Err(error)) => {
                tracing::error!(
                    ?error,
                    mode = ?logs_cfg.mode,
                    "Could not start logs collector for: {:?}",
                    endpoint.addr
                );
            }
            None => {}
        }
    }

    if let Configurable::Enabled(firmware_cfg) = &ctx.firmware_config
        && !ctx.collectors.contains(CollectorKind::Firmware, &key)
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("firmware_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<FirmwareCollector<BmcClient>>(
            endpoint_arc.clone(),
            FirmwareCollectorConfig {
                data_sink: data_sink.clone(),
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: firmware_cfg.firmware_refresh_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
                client: ctx.client.clone(),
                health_options: ctx.config.clone(),
            },
        ) {
            Ok(collector) => {
                ctx.collectors
                    .insert(CollectorKind::Firmware, key.clone(), collector);
                tracing::info!(
                    endpoint_key = %key,
                    total_firmware_collectors = ctx.collectors.len(CollectorKind::Firmware),
                    "Started firmware collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start firmware collector for: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    if let Configurable::Enabled(nmxt_cfg) = &ctx.nmxt_config
        && !ctx.collectors.contains(CollectorKind::Nmxt, &key)
        && matches!(endpoint.metadata, Some(EndpointMetadata::Switch(_)))
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("nmxt_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<NmxtCollector>(
            endpoint_arc.clone(),
            NmxtCollectorConfig {
                nmxt_config: nmxt_cfg.clone(),
                data_sink: data_sink.clone(),
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: nmxt_cfg.scrape_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
                client: ctx.client.clone(),
                health_options: ctx.config.clone(),
            },
        ) {
            Ok(handle) => {
                ctx.collectors
                    .insert(CollectorKind::Nmxt, key.clone(), handle);
                tracing::info!(
                    endpoint_key = %key,
                    total_nmxt_collectors = ctx.collectors.len(CollectorKind::Nmxt),
                    "Started NMX-T collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start NMX-T collector for: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    if let Configurable::Enabled(nvue_cfg) = &ctx.nvue_config
        && let Configurable::Enabled(rest_cfg) = &nvue_cfg.rest
        && !ctx.collectors.contains(CollectorKind::NvueRest, &key)
        && matches!(endpoint.metadata, Some(EndpointMetadata::Switch(_)))
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("nvue_rest_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<NvueRestCollector>(
            endpoint_arc,
            NvueRestCollectorConfig {
                rest_config: rest_cfg.clone(),
                data_sink: data_sink.clone(),
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: rest_cfg.poll_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
                client: ctx.client.clone(),
                health_options: ctx.config.clone(),
            },
        ) {
            Ok(handle) => {
                ctx.collectors
                    .insert(CollectorKind::NvueRest, key.clone(), handle);
                tracing::info!(
                    endpoint_key = %key,
                    total_nvue_rest_collectors = ctx.collectors.len(CollectorKind::NvueRest),
                    "Started NVUE REST collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start NVUE REST collector for: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use mac_address::MacAddress;

    use super::*;
    use crate::config::{Config, Configurable};
    use crate::endpoint::{BmcAddr, BmcCredentials, EndpointMetadata, SwitchData};
    use crate::limiter::{NoopLimiter, RateLimiter};
    use crate::metrics::MetricsManager;

    #[test]
    fn test_logs_state_file_path_replaces_endpoint_id() {
        let path = logs_state_file_path("/tmp/logs_{machine_id}.json", "endpoint-42");
        assert_eq!(path, PathBuf::from("/tmp/logs_endpoint-42.json"));
    }

    #[test]
    fn test_endpoint_log_identity_falls_back_to_mac_without_metadata() {
        let endpoint = BmcEndpoint::with_fixed_credentials(
            BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            None,
            None,
        );

        assert_eq!(endpoint.log_identity().as_ref(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_endpoint_log_identity_uses_switch_serial_when_available() {
        let endpoint = BmcEndpoint::with_fixed_credentials(
            BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: Some(443),
                mac: MacAddress::from_str("11:22:33:44:55:66").unwrap(),
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            Some(EndpointMetadata::Switch(SwitchData {
                serial: "switch-serial-1".to_string(),
            })),
            None,
        );

        assert_eq!(endpoint.log_identity().as_ref(), "switch-serial-1");
    }

    #[tokio::test]
    async fn test_spawn_is_idempotent_when_collectors_are_disabled() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;

        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopLimiter);
        let metrics_manager =
            Arc::new(MetricsManager::new("test").expect("metrics manager should initialize"));
        let mut ctx = DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(config))
            .expect("context should initialize");

        let endpoint = Arc::new(BmcEndpoint::with_fixed_credentials(
            BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            None,
            None,
        ));

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .await
            .expect("first spawn should succeed");
        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .await
            .expect("second spawn should also succeed without duplicate registry errors");

        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Firmware), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 0);
    }
}
