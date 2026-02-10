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
    Collector, FirmwareCollector, FirmwareCollectorConfig, LogsCollector, LogsCollectorConfig,
    NmxtCollector, NmxtCollectorConfig, SensorCollector, SensorCollectorConfig,
    create_log_file_writer,
};
use crate::config::Configurable;
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
    let key = endpoint.addr.hash_key();
    let endpoint_arc = endpoint.clone();
    if let Configurable::Enabled(sensor_cfg) = &ctx.sensors_config
        && !ctx.collectors.contains(CollectorKind::Sensor, &key)
    {
        let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
            format!("sensor_collector_{}", endpoint.addr.hash_key()),
            metrics_prefix,
        )?);
        match Collector::start::<SensorCollector<BmcClient>>(
            endpoint_arc.clone(),
            ctx.limiter.clone(),
            sensor_cfg.sensor_fetch_interval,
            SensorCollectorConfig {
                data_sink: data_sink.clone(),
                state_refresh_interval: sensor_cfg.state_refresh_interval,
                sensor_fetch_concurrency: sensor_cfg.sensor_fetch_concurrency,
                include_sensor_thresholds: sensor_cfg.include_sensor_thresholds,
            },
            collector_registry,
            ctx.client.clone(),
            &ctx.config,
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
        let endpoint_id = endpoint.log_identity().into_owned();
        let state_file_path = logs_state_file_path(&logs_cfg.logs_state_file, &endpoint_id);

        let log_writer = match create_log_file_writer(
            PathBuf::from(&logs_cfg.logs_output_dir),
            endpoint_id.clone(),
            logs_cfg.logs_max_file_size,
            logs_cfg.logs_max_backups,
        )
        .await
        {
            Ok(writer) => Some(Arc::new(tokio::sync::Mutex::new(writer))),
            Err(error) => {
                tracing::error!(
                    ?error,
                    endpoint_id = %endpoint_id,
                    "Failed to create log file writer, skipping logs collector"
                );
                None
            }
        };

        if let Some(log_writer) = log_writer {
            let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
                format!("log_collector_{}", endpoint.addr.hash_key()),
                metrics_prefix,
            )?);

            match Collector::start::<LogsCollector<BmcClient>>(
                endpoint_arc.clone(),
                ctx.limiter.clone(),
                logs_cfg.logs_collection_interval,
                LogsCollectorConfig {
                    state_file_path,
                    service_refresh_interval: logs_cfg.state_refresh_interval,
                    log_writer,
                    data_sink: data_sink.clone(),
                },
                collector_registry,
                ctx.client.clone(),
                &ctx.config,
            ) {
                Ok(collector) => {
                    ctx.collectors
                        .insert(CollectorKind::Logs, key.clone(), collector);
                    tracing::info!(
                        endpoint_key = %key,
                        total_collectors = ctx.collectors.len(CollectorKind::Logs),
                        "Started logs collection for BMC endpoint"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "Could not start logs collector for: {:?}",
                        endpoint.addr
                    )
                }
            }
        }
    }

    if let Configurable::Enabled(firmware_cfg) = &ctx.firmware_config
        && !ctx.collectors.contains(CollectorKind::Firmware, &key)
    {
        let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
            format!("firmware_collector_{}", endpoint.addr.hash_key()),
            metrics_prefix,
        )?);
        match Collector::start::<FirmwareCollector<BmcClient>>(
            endpoint_arc.clone(),
            ctx.limiter.clone(),
            firmware_cfg.firmware_refresh_interval,
            FirmwareCollectorConfig {
                data_sink: data_sink.clone(),
            },
            collector_registry,
            ctx.client.clone(),
            &ctx.config,
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
        let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
            format!("nmxt_collector_{}", endpoint.addr.hash_key()),
            metrics_prefix,
        )?);
        match Collector::start::<NmxtCollector>(
            endpoint_arc,
            ctx.limiter.clone(),
            nmxt_cfg.scrape_interval,
            NmxtCollectorConfig {
                nmxt_config: nmxt_cfg.clone(),
                collector_registry: collector_registry.clone(),
                data_sink: data_sink.clone(),
            },
            collector_registry,
            ctx.client.clone(),
            &ctx.config,
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
                    endpoint_key = %key,
                    "Could not start NMX-T collector for switch"
                );
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
        let endpoint = BmcEndpoint {
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            credentials: BmcCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            metadata: None,
        };

        assert_eq!(endpoint.log_identity().as_ref(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_endpoint_log_identity_uses_switch_serial_when_available() {
        let endpoint = BmcEndpoint {
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: Some(443),
                mac: MacAddress::from_str("11:22:33:44:55:66").unwrap(),
            },
            credentials: BmcCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            metadata: Some(EndpointMetadata::Switch(SwitchData {
                serial: "switch-serial-1".to_string(),
            })),
        };

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
        let metrics_manager = Arc::new(MetricsManager::new());
        let mut ctx = DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(config))
            .expect("context should initialize");

        let endpoint = Arc::new(BmcEndpoint {
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            credentials: BmcCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            metadata: None,
        });

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
    }
}
