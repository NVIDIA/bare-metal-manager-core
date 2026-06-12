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
use std::time::Instant;

use super::context::{CollectorKind, DiscoveryLoopContext};
use crate::HealthError;
use crate::bmc::BmcClient;
use crate::collectors::{
    AutoFailureBudget, BackoffConfig, BudgetDecision, Collector, CollectorStartContext,
    EntityDiscoveryCollector, EntityDiscoveryCollectorConfig, FailureKind, FirmwareCollector,
    FirmwareCollectorConfig, LeakDetectorCollector, LeakDetectorCollectorConfig, LogsCollector,
    LogsCollectorConfig, MetricsCollector, MetricsCollectorConfig, NmxtCollector,
    NmxtCollectorConfig, NvueRestCollector, NvueRestCollectorConfig, SensorCollector,
    SensorCollectorConfig, SseLogCollector, SseLogCollectorConfig, StreamingCollectorStartContext,
    spawn_gnmi_collector,
};
use crate::config::{Configurable, LogCollectionMode, PeriodicLogConfig};
use crate::endpoint::{BmcEndpoint, EndpointMetadata, SwitchEndpointRole};
use crate::sink::DataSink;

fn logs_state_file_path(template: &str, endpoint_id: &str) -> PathBuf {
    PathBuf::from(template.replace("{machine_id}", endpoint_id))
}

pub(super) fn spawn_collectors_for_endpoint(
    ctx: &mut DiscoveryLoopContext,
    endpoint: &Arc<BmcEndpoint>,
    data_sink: Option<Arc<dyn DataSink>>,
    metrics_prefix: &str,
) -> Result<(), HealthError> {
    let endpoint_role = endpoint.switch_data().map(|switch| switch.endpoint_role);

    if matches!(endpoint_role, Some(SwitchEndpointRole::Host)) {
        spawn_switch_host_collectors(ctx, endpoint, data_sink, metrics_prefix)
    } else {
        spawn_generic_redfish_collectors(ctx, endpoint, data_sink, metrics_prefix)
    }
}

fn spawn_generic_redfish_collectors(
    ctx: &mut DiscoveryLoopContext,
    endpoint: &Arc<BmcEndpoint>,
    data_sink: Option<Arc<dyn DataSink>>,
    metrics_prefix: &str,
) -> Result<(), HealthError> {
    let key = endpoint.key();
    let endpoint_arc = endpoint.clone();
    let bmc = endpoint.bmc().clone();

    let sensors_enabled = matches!(ctx.sensors_config, Configurable::Enabled(_));
    let metrics_enabled = matches!(ctx.metrics_config, Configurable::Enabled(_));

    if (sensors_enabled || metrics_enabled)
        && !ctx.collectors.contains(CollectorKind::Discovery, &key)
    {
        let shared = ctx.collectors.inventory_for(&key);
        let collector_registry = Arc::new(ctx.metrics_manager.create_collector_registry(
            format!("entity_discovery_collector_{key}"),
            metrics_prefix,
        )?);
        match Collector::start::<EntityDiscoveryCollector<BmcClient>>(
            endpoint_arc.clone(),
            bmc.clone(),
            EntityDiscoveryCollectorConfig {
                shared,
                discovery_concurrency: ctx.discovery_config.discovery_concurrency,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: ctx.discovery_config.refresh_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(monitor) => {
                ctx.collectors
                    .insert(CollectorKind::Discovery, key.clone().into(), monitor);
                tracing::info!(
                    endpoint_key = %key,
                    total_collectors = ctx.collectors.len(CollectorKind::Discovery),
                    "Started entity discovery for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start entity discovery collector for: {:?}",
                    endpoint.addr
                );
            }
        }
    }

    if let Configurable::Enabled(sensor_cfg) = &ctx.sensors_config
        && !ctx.collectors.contains(CollectorKind::Sensor, &key)
    {
        let shared = ctx.collectors.inventory_for(&key);
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("sensor_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<SensorCollector<BmcClient>>(
            endpoint_arc.clone(),
            bmc.clone(),
            SensorCollectorConfig {
                data_sink: data_sink.clone(),
                shared,
                sensor_fetch_concurrency: sensor_cfg.sensor_fetch_concurrency,
                include_sensor_thresholds: sensor_cfg.include_sensor_thresholds,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: sensor_cfg.sensor_fetch_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(monitor) => {
                ctx.collectors
                    .insert(CollectorKind::Sensor, key.clone().into(), monitor);
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

    if let Configurable::Enabled(metrics_cfg) = &ctx.metrics_config
        && !ctx.collectors.contains(CollectorKind::Metrics, &key)
    {
        let shared = ctx.collectors.inventory_for(&key);
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("metrics_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<MetricsCollector<BmcClient>>(
            endpoint_arc.clone(),
            bmc.clone(),
            MetricsCollectorConfig {
                data_sink: data_sink.clone(),
                shared,
                fetch_concurrency: metrics_cfg.fetch_concurrency,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: metrics_cfg.fetch_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(monitor) => {
                ctx.collectors
                    .insert(CollectorKind::Metrics, key.clone().into(), monitor);
                tracing::info!(
                    endpoint_key = %key,
                    total_collectors = ctx.collectors.len(CollectorKind::Metrics),
                    "Started entity metrics collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start entity metrics collector for: {:?}",
                    endpoint.addr
                );
            }
        }
    }

    if let Configurable::Enabled(logs_cfg) = &ctx.logs_config
        && !ctx.collectors.contains(CollectorKind::Logs, &key)
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("log_collector_{key}"), metrics_prefix)?,
        );

        let sse_backoff_config = || {
            let sse_cfg = logs_cfg.sse_or_default();
            BackoffConfig {
                initial: sse_cfg.initial_backoff,
                max: sse_cfg.max_backoff,
            }
        };

        let spawn_periodic_logs = |pcfg: PeriodicLogConfig,
                                   data_sink: Option<Arc<dyn DataSink>>,
                                   collector_registry: Arc<_>|
         -> Option<Result<Collector, HealthError>> {
            let endpoint_id = endpoint.log_identity().into_owned();
            let state_file_path = logs_state_file_path(&pcfg.logs_state_file, &endpoint_id);

            Some(Collector::start::<LogsCollector<BmcClient>>(
                endpoint_arc.clone(),
                bmc.clone(),
                LogsCollectorConfig {
                    state_file_path,
                    service_refresh_interval: pcfg.state_refresh_interval,
                    data_sink,
                },
                CollectorStartContext {
                    limiter: ctx.limiter.clone(),
                    iteration_interval: pcfg.logs_collection_interval,
                    collector_registry,
                    metrics_manager: ctx.metrics_manager.clone(),
                },
            ))
        };

        let result = match logs_cfg.mode {
            LogCollectionMode::Sse => {
                if let Some(data_sink) = data_sink.clone() {
                    Some(Collector::start_streaming::<SseLogCollector<BmcClient>, _>(
                        endpoint_arc.clone(),
                        bmc.clone(),
                        SseLogCollectorConfig,
                        data_sink,
                        StreamingCollectorStartContext {
                            backoff_config: sse_backoff_config(),
                            collector_registry,
                        },
                        |_| true,
                    ))
                } else {
                    tracing::warn!("SSE log collector requires a data sink, skipping");
                    None
                }
            }
            LogCollectionMode::Periodic => spawn_periodic_logs(
                logs_cfg.periodic_or_default(),
                data_sink.clone(),
                collector_registry,
            ),
            LogCollectionMode::Auto => {
                if ctx.log_downgrade_registry.is_downgraded(&key) {
                    spawn_periodic_logs(
                        logs_cfg.auto_periodic_or_default(),
                        data_sink.clone(),
                        collector_registry,
                    )
                } else if let Some(data_sink) = data_sink.clone() {
                    let auto_cfg = logs_cfg.auto.clone().unwrap_or_default();
                    let registry = ctx.log_downgrade_registry.clone();
                    let endpoint_key: std::borrow::Cow<'static, str> = key.clone().into();
                    let mut budget = AutoFailureBudget::new(auto_cfg, Instant::now());

                    Some(Collector::start_streaming::<SseLogCollector<BmcClient>, _>(
                        endpoint_arc.clone(),
                        bmc.clone(),
                        SseLogCollectorConfig,
                        data_sink,
                        StreamingCollectorStartContext {
                            backoff_config: sse_backoff_config(),
                            collector_registry,
                        },
                        move |result| match result {
                            Ok(()) => {
                                budget.reset_transient(Instant::now());
                                true
                            }
                            Err(e) => {
                                match budget.record(FailureKind::classify(e), Instant::now()) {
                                    BudgetDecision::Continue => true,
                                    BudgetDecision::Downgrade(reason) => {
                                        registry.mark_downgraded(endpoint_key.clone(), reason);
                                        false
                                    }
                                }
                            }
                        },
                    ))
                } else {
                    tracing::warn!("auto-mode SSE log collector requires a data sink, skipping");
                    None
                }
            }
        };

        match result {
            Some(Ok(collector)) => {
                ctx.collectors
                    .insert(CollectorKind::Logs, key.clone().into(), collector);
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
            bmc.clone(),
            FirmwareCollectorConfig {
                data_sink: data_sink.clone(),
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: firmware_cfg.firmware_refresh_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(collector) => {
                ctx.collectors
                    .insert(CollectorKind::Firmware, key.clone().into(), collector);
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

    if let Configurable::Enabled(leak_detector_cfg) = &ctx.leak_detector_config
        && !ctx.collectors.contains(CollectorKind::LeakDetector, &key)
    {
        let collector_registry =
            Arc::new(ctx.metrics_manager.create_collector_registry(
                format!("leak_detector_collector_{key}"),
                metrics_prefix,
            )?);
        match Collector::start::<LeakDetectorCollector<BmcClient>>(
            endpoint_arc,
            bmc,
            LeakDetectorCollectorConfig {
                data_sink: data_sink.clone(),
                state_refresh_interval: leak_detector_cfg.state_refresh_interval,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: leak_detector_cfg.poll_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(collector) => {
                ctx.collectors
                    .insert(CollectorKind::LeakDetector, key.clone().into(), collector);
                tracing::info!(
                    endpoint_key = %key,
                    total_leak_detector_collectors =
                        ctx.collectors.len(CollectorKind::LeakDetector),
                    "Started leak detector collection for BMC endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start leak detector collector for: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    Ok(())
}

fn spawn_switch_host_collectors(
    ctx: &mut DiscoveryLoopContext,
    endpoint: &Arc<BmcEndpoint>,
    data_sink: Option<Arc<dyn DataSink>>,
    metrics_prefix: &str,
) -> Result<(), HealthError> {
    let key = endpoint.key();
    let endpoint_arc = endpoint.clone();
    let bmc = endpoint.bmc().clone();

    if endpoint
        .switch_data()
        .is_some_and(|switch| switch.nmxt_enabled)
        && let Configurable::Enabled(nmxt_cfg) = &ctx.nmxt_config
        && !ctx.collectors.contains(CollectorKind::Nmxt, &key)
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("nmxt_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<NmxtCollector>(
            endpoint_arc.clone(),
            bmc.clone(),
            NmxtCollectorConfig {
                nmxt_config: nmxt_cfg.clone(),
                data_sink: data_sink.clone(),
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: nmxt_cfg.scrape_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(handle) => {
                ctx.collectors
                    .insert(CollectorKind::Nmxt, key.clone().into(), handle);
                tracing::info!(
                    endpoint_key = %key,
                    total_nmxt_collectors = ctx.collectors.len(CollectorKind::Nmxt),
                    "Started NMX-T collection for switch host endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start NMX-T collector for switch host: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    if let Configurable::Enabled(nvue_cfg) = &ctx.nvue_config
        && let Configurable::Enabled(rest_cfg) = &nvue_cfg.rest
        && !ctx.collectors.contains(CollectorKind::NvueRest, &key)
    {
        let credential_provider = bmc.credential_provider();
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("nvue_rest_collector_{key}"), metrics_prefix)?,
        );
        match Collector::start::<NvueRestCollector>(
            endpoint_arc,
            bmc.clone(),
            NvueRestCollectorConfig {
                rest_config: rest_cfg.clone(),
                data_sink: data_sink.clone(),
                credential_provider,
            },
            CollectorStartContext {
                limiter: ctx.limiter.clone(),
                iteration_interval: rest_cfg.poll_interval,
                collector_registry,
                metrics_manager: ctx.metrics_manager.clone(),
            },
        ) {
            Ok(handle) => {
                ctx.collectors
                    .insert(CollectorKind::NvueRest, key.clone().into(), handle);
                tracing::info!(
                    endpoint_key = %key,
                    total_nvue_rest_collectors = ctx.collectors.len(CollectorKind::NvueRest),
                    "Started NVUE REST collection for switch host endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Could not start NVUE REST collector for switch host: {:?}",
                    endpoint.addr
                )
            }
        }
    }

    if let Configurable::Enabled(nvue_cfg) = &ctx.nvue_config
        && let Configurable::Enabled(gnmi_cfg) = &nvue_cfg.gnmi
        && !ctx.collectors.contains(CollectorKind::NvueGnmi, &key)
        && matches!(endpoint.metadata, Some(EndpointMetadata::Switch(_)))
    {
        let collector_registry = Arc::new(
            ctx.metrics_manager
                .create_collector_registry(format!("nvue_gnmi_collector_{key}"), metrics_prefix)?,
        );
        let credential_provider = bmc.credential_provider();
        match spawn_gnmi_collector(
            endpoint,
            gnmi_cfg,
            credential_provider,
            collector_registry,
            data_sink.clone(),
        ) {
            Ok(handle) => {
                ctx.collectors
                    .insert(CollectorKind::NvueGnmi, key.clone().into(), handle);
                tracing::info!(
                    endpoint_key = %key,
                    total_nvue_gnmi_collectors = ctx.collectors.len(CollectorKind::NvueGnmi),
                    "Started NVUE gNMI streaming collection for switch endpoint"
                );
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    endpoint_key = %key,
                    "Could not start NVUE gNMI collector for switch"
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
    use crate::collectors::DowngradeReason;
    use crate::config::{
        AutoModeConfig, Config, Configurable, LogsCollectorConfig, NvueCollectorConfig,
        NvueGnmiConfig, PeriodicLogConfig,
    };
    use crate::endpoint::test_support::endpoint_with_creds;
    use crate::endpoint::{
        BmcAddr, BmcCredentials, EndpointMetadata, MachineData, SwitchData, SwitchEndpointRole,
    };
    use crate::limiter::{NoopLimiter, RateLimiter};
    use crate::metrics::MetricsManager;
    use crate::sink::{CollectorEvent, EventContext};

    struct NoopSink;

    impl DataSink for NoopSink {
        fn sink_type(&self) -> &'static str {
            "noop"
        }

        fn handle_event(&self, _context: &EventContext, _event: &CollectorEvent) {}
    }

    fn context_with_config(config: Config, metrics_name: &str) -> DiscoveryLoopContext {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopLimiter);
        let metrics_manager =
            Arc::new(MetricsManager::new(metrics_name).expect("metrics manager should initialize"));
        DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(config))
            .expect("context should initialize")
    }

    fn test_endpoint(
        ip: Ipv4Addr,
        mac: &str,
        metadata: Option<EndpointMetadata>,
    ) -> Arc<BmcEndpoint> {
        Arc::new(endpoint_with_creds(
            BmcAddr {
                ip: IpAddr::V4(ip),
                port: Some(443),
                mac: MacAddress::from_str(mac).expect("valid mac address"),
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            metadata,
            None,
        ))
    }

    fn switch_metadata_with_role(
        endpoint_role: SwitchEndpointRole,
        is_primary: bool,
        nmxt_enabled: bool,
        serial: &str,
    ) -> EndpointMetadata {
        EndpointMetadata::Switch(SwitchData {
            id: None,
            serial: serial.to_string(),
            slot_number: None,
            tray_index: None,
            endpoint_role,
            is_primary,
            nmxt_enabled,
        })
    }

    fn switch_metadata() -> EndpointMetadata {
        switch_metadata_with_role(SwitchEndpointRole::Host, false, false, "switch-serial-1")
    }

    fn machine_metadata() -> EndpointMetadata {
        EndpointMetadata::Machine(MachineData {
            machine_id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
                .parse()
                .expect("valid machine id"),
            machine_serial: None,
            slot_number: None,
            tray_index: None,
            nvlink_domain_uuid: None,
        })
    }

    #[test]
    fn test_logs_state_file_path_replaces_endpoint_id() {
        let path = logs_state_file_path("/tmp/logs_{machine_id}.json", "endpoint-42");
        assert_eq!(path, PathBuf::from("/tmp/logs_endpoint-42.json"));
    }

    #[tokio::test]
    async fn test_endpoint_log_identity_falls_back_to_mac_without_metadata() {
        let endpoint = test_endpoint(Ipv4Addr::new(10, 0, 0, 1), "aa:bb:cc:dd:ee:ff", None);

        assert_eq!(endpoint.log_identity().as_ref(), "AA:BB:CC:DD:EE:FF");
    }

    #[tokio::test]
    async fn test_endpoint_log_identity_uses_switch_serial_when_available() {
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 2),
            "11:22:33:44:55:66",
            Some(switch_metadata()),
        );

        assert_eq!(endpoint.log_identity().as_ref(), "switch-serial-1");
    }

    #[tokio::test]
    async fn test_switch_endpoint_does_not_start_generic_redfish_collectors() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Enabled(Default::default());
        config.collectors.logs = Configurable::Enabled(Default::default());
        config.collectors.firmware = Configurable::Enabled(Default::default());
        config.collectors.leak_detector = Configurable::Enabled(Default::default());
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_switch_generic_redfish_gate");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 6),
            "55:66:77:88:99:aa",
            Some(switch_metadata()),
        );

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_switch_generic_redfish_gate",
        )
        .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Firmware), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::LeakDetector), 0);
    }

    #[tokio::test]
    async fn test_switch_bmc_endpoint_starts_redfish_but_not_switch_host_collectors() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Enabled(Default::default());
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Enabled(Default::default());
        config.collectors.nvue = Configurable::Enabled(NvueCollectorConfig {
            rest: Configurable::Enabled(Default::default()),
            gnmi: Configurable::Enabled(NvueGnmiConfig::default()),
        });

        let mut ctx = context_with_config(config, "test_switch_bmc_redfish_only");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 8),
            "55:66:77:88:99:bb",
            Some(switch_metadata_with_role(
                SwitchEndpointRole::Bmc,
                true,
                false,
                "switch-bmc",
            )),
        );

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test_switch_bmc_redfish_only")
            .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueGnmi), 0);
    }

    #[tokio::test]
    async fn test_switch_host_primary_starts_nmxt_and_nvue_collectors_when_globally_enabled() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Enabled(Default::default());
        config.collectors.nvue = Configurable::Enabled(NvueCollectorConfig {
            rest: Configurable::Enabled(Default::default()),
            gnmi: Configurable::Enabled(NvueGnmiConfig::default()),
        });

        let mut ctx = context_with_config(config, "test_switch_host_nmxt_nvue_enabled");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 9),
            "55:66:77:88:99:cc",
            Some(switch_metadata_with_role(
                SwitchEndpointRole::Host,
                true,
                true,
                "switch-host",
            )),
        );

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueGnmi), 1);
    }

    #[tokio::test]
    async fn test_switch_host_policy_gates_nmxt_but_not_nvue_rest() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Enabled(Default::default());
        config.collectors.nvue = Configurable::Enabled(Default::default());

        let mut ctx = context_with_config(config, "test_switch_host_nmxt_endpoint_disabled");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 10),
            "55:66:77:88:99:dd",
            Some(switch_metadata_with_role(
                SwitchEndpointRole::Host,
                false,
                false,
                "switch-host",
            )),
        );

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 1);
    }

    #[tokio::test]
    async fn test_switch_host_does_not_start_host_collectors_when_globally_disabled() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_switch_host_collectors_global_disabled");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 11),
            "55:66:77:88:99:ee",
            Some(switch_metadata_with_role(
                SwitchEndpointRole::Host,
                true,
                true,
                "switch-host",
            )),
        );

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 0);
    }

    #[tokio::test]
    async fn test_machine_endpoint_still_starts_sse_logs_collector() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Enabled(Default::default());
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_machine_sse_logs_collector");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 7),
            "66:77:88:99:aa:bb",
            Some(machine_metadata()),
        );

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_machine_sse_logs_collector",
        )
        .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 1);
    }

    #[tokio::test]
    async fn test_nvue_collectors_still_spawn_when_credentials_currently_unavailable() {
        use crate::bmc::{BmcClient, BoxFuture, CredentialProvider};
        use crate::endpoint::test_support::reqwest;

        struct FailingProvider;
        impl CredentialProvider for FailingProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                Box::pin(async move {
                    Err(HealthError::GenericError(
                        "simulated credential provider failure".to_string(),
                    ))
                })
            }
        }

        let addr = BmcAddr {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            port: Some(443),
            mac: MacAddress::from_str("99:88:77:66:55:44").expect("valid mac"),
        };
        let bmc = Arc::new(
            BmcClient::new(reqwest(), addr.clone(), Arc::new(FailingProvider), None, 10)
                .expect("constructor succeeds"),
        );
        let endpoint = Arc::new(BmcEndpoint {
            addr,
            metadata: Some(switch_metadata_with_role(
                SwitchEndpointRole::Host,
                true,
                true,
                "failing-switch-host",
            )),
            rack_id: None,
            bmc,
        });

        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Enabled(Default::default());
        config.collectors.nvue = Configurable::Enabled(NvueCollectorConfig {
            rest: Configurable::Enabled(Default::default()),
            gnmi: Configurable::Enabled(NvueGnmiConfig::default()),
        });

        let mut ctx = context_with_config(config, "test_nvue_spawn_despite_cred_failure");

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            None,
            "test_nvue_spawn_despite_cred_failure",
        )
        .expect("spawn returns Ok even when the credential provider is failing");

        assert_eq!(
            ctx.collectors.len(CollectorKind::NvueRest),
            1,
            "NVUE REST must still spawn — credential fetch is now per-iteration, \
             not part of the spawn contract"
        );
        assert_eq!(
            ctx.collectors.len(CollectorKind::NvueGnmi),
            1,
            "NVUE gNMI must still spawn — credential fetch is per-stream connection, \
             not part of the spawn contract"
        );
        assert_eq!(
            ctx.collectors.len(CollectorKind::Nmxt),
            1,
            "NMX-T must still start — it doesn't depend on BMC credentials"
        );
    }

    #[tokio::test]
    async fn test_spawn_is_idempotent_when_collectors_are_disabled() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_disabled_collectors");
        let endpoint = test_endpoint(Ipv4Addr::new(10, 0, 0, 1), "aa:bb:cc:dd:ee:ff", None);

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .expect("first spawn should succeed");
        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test")
            .expect("second spawn should also succeed without duplicate registry errors");

        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Firmware), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::LeakDetector), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Nmxt), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueRest), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::NvueGnmi), 0)
    }

    #[tokio::test]
    async fn machine_endpoint_with_sensors_starts_discovery_and_sensor_only() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Enabled(Default::default());
        config.collectors.metrics = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_discovery_with_sensors");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 20),
            "aa:bb:cc:00:00:20",
            Some(machine_metadata()),
        );

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_discovery_with_sensors",
        )
        .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Discovery), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Metrics), 0);
    }

    #[tokio::test]
    async fn metrics_only_still_starts_discovery() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.metrics = Configurable::Enabled(Default::default());
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_discovery_with_metrics_only");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 21),
            "aa:bb:cc:00:00:21",
            Some(machine_metadata()),
        );

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_discovery_with_metrics_only",
        )
        .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Discovery), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Metrics), 1);
    }

    #[tokio::test]
    async fn no_discovery_when_both_readers_disabled() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.metrics = Configurable::Disabled;
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_no_discovery");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 22),
            "aa:bb:cc:00:00:22",
            Some(machine_metadata()),
        );

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, Some(Arc::new(NoopSink)), "test")
            .expect("spawn should succeed");

        assert_eq!(ctx.collectors.len(CollectorKind::Discovery), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 0);
        assert_eq!(ctx.collectors.len(CollectorKind::Metrics), 0);
    }

    #[tokio::test]
    async fn discovery_sensor_and_metrics_spawn_is_idempotent() {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Enabled(Default::default());
        config.collectors.metrics = Configurable::Enabled(Default::default());
        config.collectors.logs = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;

        let mut ctx = context_with_config(config, "test_discovery_idempotent");
        let endpoint = test_endpoint(
            Ipv4Addr::new(10, 0, 0, 23),
            "aa:bb:cc:00:00:23",
            Some(machine_metadata()),
        );

        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_discovery_idempotent",
        )
        .expect("first spawn should succeed");
        spawn_collectors_for_endpoint(
            &mut ctx,
            &endpoint,
            Some(Arc::new(NoopSink)),
            "test_discovery_idempotent",
        )
        .expect("second spawn should be a no-op without duplicate registry errors");

        assert_eq!(ctx.collectors.len(CollectorKind::Discovery), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Sensor), 1);
        assert_eq!(ctx.collectors.len(CollectorKind::Metrics), 1);
    }

    fn auto_mode_config() -> Config {
        let mut config = Config::default();
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.firmware = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Disabled;
        config.collectors.nvue = Configurable::Disabled;
        config.collectors.logs = Configurable::Enabled(LogsCollectorConfig {
            mode: LogCollectionMode::Auto,
            sse: None,
            periodic: Some(PeriodicLogConfig::default()),
            auto: Some(AutoModeConfig::default()),
        });
        config
    }

    #[tokio::test]
    async fn test_auto_mode_with_downgraded_endpoint_spawns_periodic() {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopLimiter);
        let metrics_manager = Arc::new(
            MetricsManager::new("test_auto_downgraded").expect("metrics manager should initialize"),
        );
        let mut ctx =
            DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(auto_mode_config()))
                .expect("context should initialize");

        let endpoint = test_endpoint(Ipv4Addr::new(10, 0, 0, 1), "aa:bb:cc:dd:ee:01", None);
        ctx.log_downgrade_registry
            .mark_downgraded(endpoint.key().into(), DowngradeReason::SseNotAvailable);

        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test_auto_downgraded")
            .expect("spawn should succeed for downgraded auto endpoint");

        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 1);
    }

    #[tokio::test]
    async fn test_auto_mode_without_downgrade_and_no_data_sink_skips_spawn() {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopLimiter);
        let metrics_manager = Arc::new(
            MetricsManager::new("test_auto_no_sink").expect("metrics manager should initialize"),
        );
        let mut ctx =
            DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(auto_mode_config()))
                .expect("context should initialize");

        let endpoint = test_endpoint(Ipv4Addr::new(10, 0, 0, 2), "aa:bb:cc:dd:ee:02", None);
        spawn_collectors_for_endpoint(&mut ctx, &endpoint, None, "test_auto_no_sink")
            .expect("spawn should succeed (gracefully skip) without data sink");

        assert_eq!(ctx.collectors.len(CollectorKind::Logs), 0);
        assert!(!ctx.log_downgrade_registry.is_downgraded(&endpoint.key()));
    }
}
