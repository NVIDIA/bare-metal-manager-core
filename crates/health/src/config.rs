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

use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub endpoint_sources: EndpointSourcesConfig,

    pub sinks: SinksConfig,

    pub rate_limit: Configurable<RateLimitConfig>,

    pub collectors: CollectorsConfig,

    pub processors: ProcessorsConfig,

    pub metrics: MetricsConfig,

    /// Shard ordinal for this instance
    pub shard: usize,

    /// Total number of shards in the StatefulSet
    pub shards_count: usize,

    /// Maximum cache size per BMC, uses etags
    pub cache_size: usize,

    /// BMC proxy URL
    pub bmc_proxy_url: Option<Url>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint_sources: EndpointSourcesConfig::default(),
            sinks: SinksConfig::default(),
            rate_limit: Configurable::Enabled(RateLimitConfig::default()),
            collectors: CollectorsConfig::default(),
            processors: ProcessorsConfig::default(),
            metrics: MetricsConfig::default(),
            shard: 0,
            shards_count: 1,
            cache_size: 100,
            bmc_proxy_url: None,
        }
    }
}

/// Configuration for where BMC endpoints are discovered from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointSourcesConfig {
    /// Carbide API connection settings (if present, Carbide API discovery is enabled)
    pub carbide_api: Configurable<CarbideApiConnectionConfig>,

    /// Static BMC endpoints
    pub static_bmc_endpoints: Vec<StaticBmcEndpoint>,
}

impl Default for EndpointSourcesConfig {
    fn default() -> Self {
        Self {
            carbide_api: Configurable::Enabled(CarbideApiConnectionConfig::default()),
            static_bmc_endpoints: Vec::new(),
        }
    }
}

/// A single static BMC endpoint configuration.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct StaticBmcEndpoint {
    pub ip: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub mac: String,
    pub username: String,
    pub password: Option<String>,
    pub switch_serial: Option<String>,
    pub machine_id: Option<String>,
    pub rack_id: Option<String>,
}

impl Debug for StaticBmcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticBmcEndpoint")
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("mac", &self.mac)
            .field("switch_serial", &self.switch_serial)
            .field("machine_id", &self.machine_id)
            .field("rack_id", &self.rack_id)
            .finish()
    }
}

/// Configuration for output sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SinksConfig {
    /// Tracing sink: logs all collector events through `tracing`.
    pub tracing: Configurable<TracingSinkConfig>,

    /// Prometheus sink: stores metric events in Prometheus exporter format.
    pub prometheus: Configurable<PrometheusSinkConfig>,

    /// Health report sink: sends health report events to Carbide API.
    #[serde(alias = "carbide_override", alias = "health_override")]
    pub health_report: Configurable<HealthReportSinkConfig>,

    /// Rack health report sink: sends rack-level health reports to Carbide API.
    #[serde(alias = "rack_health_override")]
    pub rack_health_report: Configurable<RackHealthReportSinkConfig>,

    /// Log file sink: writes log events as JSONL to rotating files on disk.
    pub log_file: Configurable<LogFileSinkConfig>,

    /// OTLP log export sink: streams events to an OpenTelemetry collector via gRPC.
    pub otlp: Configurable<OtlpSinkConfig>,
}

impl Default for SinksConfig {
    fn default() -> Self {
        Self {
            tracing: Configurable::Disabled,
            prometheus: Configurable::Enabled(PrometheusSinkConfig::default()),
            health_report: Configurable::Enabled(HealthReportSinkConfig::default()),
            rack_health_report: Configurable::Enabled(RackHealthReportSinkConfig::default()),
            log_file: Configurable::Disabled,
            otlp: Configurable::Disabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TracingSinkConfig {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrometheusSinkConfig {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogFileSinkConfig {
    pub output_dir: String,
    pub max_file_size: u64,
    pub max_backups: usize,
}

impl Default for LogFileSinkConfig {
    fn default() -> Self {
        Self {
            output_dir: "/tmp/logs".to_string(),
            max_file_size: 104_857_600, // 100MB
            max_backups: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpSinkConfig {
    pub endpoint: String,
    pub batch_size: usize,
    #[serde(with = "humantime_serde")]
    pub flush_interval: std::time::Duration,
}

impl Default for OtlpSinkConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            batch_size: 512,
            flush_interval: std::time::Duration::from_secs(2),
        }
    }
}

/// Shared Carbide API connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CarbideApiConnectionConfig {
    /// Path to the root CA certificate for Carbide API connections
    pub root_ca: String,

    /// Path to the client certificate for Carbide API connections
    pub client_cert: String,

    /// Path to the client key for Carbide API connections
    pub client_key: String,

    /// Carbide API server endpoint
    pub api_url: Url,
}

impl Default for CarbideApiConnectionConfig {
    fn default() -> Self {
        Self {
            root_ca: "/var/run/secrets/spiffe.io/ca.crt".to_string(),
            client_cert: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            client_key: "/var/run/secrets/spiffe.io/tls.key".to_string(),
            api_url: Url::parse("https://carbide-api.forge-system.svc.cluster.local:1079").unwrap(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthReportSinkConfig {
    #[serde(flatten)]
    pub connection: CarbideApiConnectionConfig,

    /// Number of concurrent workers submitting reports to Carbide API.
    pub workers: usize,
}

impl Default for HealthReportSinkConfig {
    fn default() -> Self {
        Self {
            connection: CarbideApiConnectionConfig::default(),
            workers: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RackHealthReportSinkConfig {
    #[serde(flatten)]
    pub connection: CarbideApiConnectionConfig,

    /// Number of concurrent workers submitting rack-level reports to Carbide API.
    pub workers: usize,
}

impl Default for RackHealthReportSinkConfig {
    fn default() -> Self {
        Self {
            connection: CarbideApiConnectionConfig::default(),
            workers: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Burst value for explorations, optimal to set to max rate limit.
    pub bucket_burst: usize,

    /// Interval between bucket replenishment.
    /// Default value 30ms will rate limit for 2000 rpm.
    #[serde(with = "humantime_serde")]
    pub bucket_replenish: Duration,

    /// Maximum jitter added to exploration intervals.
    #[serde(with = "humantime_serde")]
    pub max_jitter: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorsConfig {
    /// Sensor collector configuration (if present, sensor collector is enabled)
    #[serde(alias = "health")]
    pub sensors: Configurable<SensorCollectorConfig>,

    /// Firmware collector configuration (if present, firmware collector is enabled)
    pub firmware: Configurable<FirmwareCollectorConfig>,

    /// Logs collector configuration (if present, logs collector is enabled)
    pub logs: Configurable<LogsCollectorConfig>,

    /// Switch NMX-T collector configuration (if present, nmxt collector is enabled)
    pub nmxt: Configurable<NmxtCollectorConfig>,

    /// NVUE collector configuration for direct NVUE HTTP(s) polling of NVLink switches
    pub nvue: Configurable<NvueCollectorConfig>,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            sensors: Configurable::Enabled(SensorCollectorConfig::default()),
            firmware: Configurable::Disabled,
            logs: Configurable::Disabled,
            nmxt: Configurable::Disabled,
            nvue: Configurable::Disabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessorsConfig {
    /// Leak detection processor configuration (if present, leak detection is enabled)
    pub leak_detection: Configurable<LeakDetectionProcessorConfig>,

    /// Rack-level leak processor: aggregates tray leak reports per rack.
    pub rack_leak: Configurable<RackLeakProcessorConfig>,
}

impl Default for ProcessorsConfig {
    fn default() -> Self {
        Self {
            leak_detection: Configurable::Enabled(LeakDetectionProcessorConfig::default()),
            rack_leak: Configurable::Enabled(RackLeakProcessorConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LeakDetectionProcessorConfig {
    /// Minimum number of leak-detector alerts required in one report window
    /// to emit a derived leak health report.
    pub minimum_alerts_per_report: usize,
}

impl Default for LeakDetectionProcessorConfig {
    fn default() -> Self {
        Self {
            minimum_alerts_per_report: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RackLeakProcessorConfig {
    /// Number of leaking trays in a rack required to trigger a rack-level leak override.
    pub leaking_tray_threshold: usize,
}

impl Default for RackLeakProcessorConfig {
    fn default() -> Self {
        Self {
            leaking_tray_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SensorCollectorConfig {
    /// Interval between BMC endpoint rediscovery.
    #[serde(with = "humantime_serde")]
    pub rediscover_interval: Duration,

    /// Interval between entity state refresh.
    #[serde(with = "humantime_serde")]
    pub state_refresh_interval: Duration,

    /// Interval between sensor fetch iterations.
    #[serde(with = "humantime_serde")]
    pub sensor_fetch_interval: Duration,

    /// Number of concurrent sensor fetches.
    pub sensor_fetch_concurrency: usize,

    /// Include sensor thresholds in the metrics attributes.
    pub include_sensor_thresholds: bool,
}

impl Default for SensorCollectorConfig {
    fn default() -> Self {
        Self {
            rediscover_interval: Duration::from_secs(300),
            state_refresh_interval: Duration::from_secs(9000),
            sensor_fetch_interval: Duration::from_secs(60),
            sensor_fetch_concurrency: 10,
            include_sensor_thresholds: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirmwareCollectorConfig {
    /// Interval between firmware inventory refresh.
    #[serde(with = "humantime_serde")]
    pub firmware_refresh_interval: Duration,
}

impl Default for FirmwareCollectorConfig {
    fn default() -> Self {
        Self {
            firmware_refresh_interval: Duration::from_secs(60 * 60 * 2), // 2 hours
        }
    }
}

/// SSE is the preferred mode for real-time log streaming.
/// Periodic polling is retained as a fallback for BMCs that lack SSE support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogCollectionMode {
    Sse,
    Periodic,
}

impl Default for LogCollectionMode {
    fn default() -> Self {
        Self::Sse
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsCollectorConfig {
    /// Collection mode: "sse" (default, preferred) or "periodic" (fallback).
    pub mode: LogCollectionMode,

    /// Configuration for periodic log polling
    pub periodic: Option<PeriodicLogConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PeriodicLogConfig {
    /// Interval between log collection.
    #[serde(with = "humantime_serde")]
    pub logs_collection_interval: Duration,

    /// Interval between log service state refresh.
    #[serde(with = "humantime_serde")]
    pub state_refresh_interval: Duration,

    /// Path to logs collector state file (supports {machine_id} placeholder).
    pub logs_state_file: String,
}

impl Default for PeriodicLogConfig {
    fn default() -> Self {
        Self {
            logs_collection_interval: Duration::from_secs(300),
            state_refresh_interval: Duration::from_secs(1800),
            logs_state_file: "/tmp/logs_collector_{machine_id}.json".to_string(),
        }
    }
}

impl LogsCollectorConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self.mode {
            LogCollectionMode::Periodic if self.periodic.is_none() => {
                Err("[collectors.logs.periodic] is required when mode = \"periodic\"".to_string())
            }
            LogCollectionMode::Sse if self.periodic.is_some() => {
                Err("[collectors.logs.periodic] should not be set when mode = \"sse\"".to_string())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NmxtCollectorConfig {
    /// Interval between switch NMX-T metric scrapes.
    #[serde(with = "humantime_serde")]
    pub scrape_interval: Duration,

    /// Timeout for individual NMX-T HTTP requests.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
}

impl Default for NmxtCollectorConfig {
    fn default() -> Self {
        Self {
            scrape_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NvueCollectorConfig {
    pub rest: Configurable<NvueRestConfig>,
}

impl Default for NvueCollectorConfig {
    fn default() -> Self {
        Self {
            rest: Configurable::Enabled(NvueRestConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NvueRestConfig {
    /// Interval between NVUE REST poll iterations.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,

    /// Timeout for individual REST requests.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,

    /// NVUE REST paths to poll.
    pub paths: NvueRestPaths,
}

impl Default for NvueRestConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(300),
            request_timeout: Duration::from_secs(30),
            paths: NvueRestPaths::default(),
        }
    }
}

/// Supported NVUE REST API paths.
/// - system_health_enabled: Poll `/nvue_v1/system/health`.
/// - cluster_apps_enabled: Poll `/nvue_v1/cluster/apps`.
/// - sdn_partitions_enabled: Poll `/nvue_v1/sdn/partition` (including per-partition details)
/// - interfaces_enabled: Poll `/nvue_v1/interface`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NvueRestPaths {
    pub system_health_enabled: bool,
    pub cluster_apps_enabled: bool,
    pub sdn_partitions_enabled: bool,
    pub interfaces_enabled: bool,
}

impl Default for NvueRestPaths {
    fn default() -> Self {
        Self {
            system_health_enabled: true,
            cluster_apps_enabled: true,
            sdn_partitions_enabled: true,
            interfaces_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Metrics listener.
    pub endpoint: String,
    /// Prefix for all metrics, defaults to carbide_hardware_health
    pub prefix: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            bucket_burst: 100,
            bucket_replenish: Duration::from_millis(30),
            max_jitter: Duration::from_millis(50),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            endpoint: "0.0.0.0:9009".to_string(),
            prefix: "carbide_hardware_health".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from optional path
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let mut figment = Figment::new().merge(Serialized::defaults(Config::default()));

        if let Some(path) = config_path {
            figment = figment.merge(Toml::file(path));
        }

        figment = figment.merge(Env::prefixed("CARBIDE_HEALTH__").split("__"));

        let config: Config = figment
            .extract()
            .map_err(|e| format!("Failed to load configuration: {}", e))?;

        config.validate()?;
        Ok(config)
    }

    /// Get the metrics listener address
    pub fn metrics_addr(&self) -> Result<SocketAddr, String> {
        self.metrics
            .endpoint
            .parse()
            .map_err(|_| format!("Invalid metrics endpoint: {}", self.metrics.endpoint))
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.shard >= self.shards_count {
            return Err(format!(
                "shard ({}) must be less than shards_count ({})",
                self.shard, self.shards_count
            ));
        }

        if let Configurable::Enabled(rate_limit) = &self.rate_limit
            && rate_limit.bucket_replenish.is_zero()
        {
            return Err(
                "bucket_replenish must be greater than 0 when rate limiting is enabled".to_string(),
            );
        }

        if let Configurable::Enabled(leak_detection) = &self.processors.leak_detection
            && leak_detection.minimum_alerts_per_report == 0
        {
            return Err(
                "processors.leak_detection.minimum_alerts_per_report must be greater than 0"
                    .to_string(),
            );
        }

        if let Configurable::Enabled(health_report) = &self.sinks.health_report
            && health_report.workers == 0
        {
            return Err("sinks.health_report.workers must be greater than 0".to_string());
        }

        if let Configurable::Enabled(logs) = &self.collectors.logs {
            logs.validate()?;
        }

        if let Configurable::Enabled(ref otlp) = self.sinks.otlp {
            tonic::transport::Channel::from_shared(otlp.endpoint.clone())
                .map_err(|_| format!("invalid sinks.otlp.endpoint: {}", otlp.endpoint))?;
        }

        self.metrics_addr()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Configurable<T> {
    Enabled(T),
    Disabled,
}

impl<T> Configurable<T> {
    pub fn as_option(&self) -> Option<&T> {
        match self {
            Self::Enabled(v) => Some(v),
            Self::Disabled => None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }
}

impl<'de, T> Deserialize<'de> for Configurable<T>
where
    T: Deserialize<'de> + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<T> {
            #[serde(default = "default_true")]
            enabled: bool,
            #[serde(flatten)]
            config: Option<T>,
        }

        fn default_true() -> bool {
            true
        }

        let helper_opt = Option::<Helper<T>>::deserialize(deserializer)?;

        match helper_opt {
            None => Ok(Configurable::Disabled),
            Some(helper) => {
                if !helper.enabled {
                    Ok(Configurable::Disabled)
                } else if let Some(cfg) = helper.config {
                    Ok(Configurable::Enabled(cfg))
                } else {
                    Ok(Configurable::Enabled(T::default()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_config() {
        let toml_content = include_str!("../example/config.example.toml");
        let config: Config = Figment::new()
            .merge(Toml::string(toml_content))
            .extract()
            .expect("could not parse config toml file");

        if let Configurable::Enabled(ref carbide_api) = config.endpoint_sources.carbide_api {
            assert_eq!(carbide_api.root_ca, "/var/run/secrets/spiffe.io/ca.crt");
            assert_eq!(
                carbide_api.client_cert,
                "/var/run/secrets/spiffe.io/tls.crt"
            );
            assert_eq!(carbide_api.client_key, "/var/run/secrets/spiffe.io/tls.key");
            assert!(
                carbide_api
                    .api_url
                    .as_str()
                    .starts_with("https://carbide-api.forge-system.svc.cluster.local:1079"),
            );
        } else {
            panic!("carbide api empty for sources")
        }

        if let Configurable::Enabled(ref health_report) = config.sinks.health_report {
            assert_eq!(
                health_report.connection.root_ca,
                "/var/run/secrets/spiffe.io/ca.crt"
            );
            assert_eq!(health_report.workers, 8);
        } else {
            panic!("health report sink is disabled")
        }

        if let Configurable::Enabled(ref rate_limit) = config.rate_limit {
            assert_eq!(rate_limit.bucket_replenish, Duration::from_millis(35));
            assert_eq!(rate_limit.bucket_burst, 200);
            assert_eq!(rate_limit.max_jitter, Duration::from_millis(40));
        } else {
            panic!("rate limit empty")
        }

        assert!(config.collectors.sensors.is_enabled());
        assert!(config.collectors.firmware.is_enabled());
        assert!(config.collectors.logs.is_enabled());
        assert!(config.collectors.nvue.is_enabled());
        assert!(!config.sinks.tracing.is_enabled());
        assert!(config.sinks.prometheus.is_enabled());

        if let Configurable::Enabled(ref sensors) = config.collectors.sensors {
            assert_eq!(sensors.rediscover_interval, Duration::from_secs(300));
            assert_eq!(sensors.sensor_fetch_concurrency, 10);
        } else {
            panic!("sensors empty")
        }

        if let Configurable::Enabled(ref logs) = config.collectors.logs {
            assert_eq!(logs.mode, LogCollectionMode::Sse);
            assert!(
                logs.periodic.is_none(),
                "SSE mode should not have periodic config"
            );
            assert!(logs.validate().is_ok());
        } else {
            panic!("logs empty")
        }

        if let Configurable::Enabled(ref leak_detection) = config.processors.leak_detection {
            assert_eq!(leak_detection.minimum_alerts_per_report, 1);
        } else {
            panic!("leak detection processor is disabled")
        }

        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");

        assert_eq!(config.shard, 0);
        assert_eq!(config.shards_count, 1);

        assert_eq!(config.cache_size, 100);

        if let Configurable::Enabled(ref nvue) = config.collectors.nvue {
            if let Configurable::Enabled(ref rest) = nvue.rest {
                assert_eq!(rest.poll_interval, Duration::from_secs(60));
                assert_eq!(rest.request_timeout, Duration::from_secs(30));
            } else {
                panic!("nvue rest config should be enabled in example config");
            }
        } else {
            panic!("nvue config should be enabled in example config");
        }
    }

    #[test]
    fn test_static_only_config() {
        let toml_content = r#"
[[endpoint_sources.static_bmc_endpoints]]
ip = "192.168.1.100"
mac = "00:11:22:33:44:55"
username = "root"
password = "pass"

[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[collectors.sensors]
rediscover_interval = "1m"
sensor_fetch_interval = "30s"
state_refresh_interval = "10m"
sensor_fetch_concurrency = 5
include_sensor_thresholds = false

[metrics]
endpoint = "127.0.0.1:9009"
prefix = "carbide_hardware_new_health"

shard = 0
shards_count = 1
cache_size = 50
"#;

        let config: Config = Figment::new()
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse");

        assert!(!config.endpoint_sources.carbide_api.is_enabled());
        assert!(!config.sinks.health_report.is_enabled());

        assert_eq!(config.endpoint_sources.static_bmc_endpoints.len(), 1);
        assert_eq!(
            config.endpoint_sources.static_bmc_endpoints[0].ip,
            "192.168.1.100"
        );
        assert_eq!(
            config.endpoint_sources.static_bmc_endpoints[0].mac,
            "00:11:22:33:44:55"
        );

        assert_eq!(config.metrics.prefix, "carbide_hardware_new_health");

        if let Configurable::Enabled(ref rate_limit) = config.rate_limit {
            assert_eq!(rate_limit.bucket_replenish, Duration::from_millis(30));
            assert_eq!(rate_limit.bucket_burst, 100);
            assert_eq!(rate_limit.max_jitter, Duration::from_millis(50));
        } else {
            panic!("rate limit empty")
        }

        assert!(config.collectors.sensors.is_enabled());
        if let Configurable::Enabled(ref sensors) = config.collectors.sensors {
            assert_eq!(sensors.rediscover_interval, Duration::from_secs(60));
            assert_eq!(sensors.sensor_fetch_interval, Duration::from_secs(30));
            assert!(!sensors.include_sensor_thresholds);
        } else {
            panic!("sensors empty")
        }

        assert!(!config.collectors.firmware.is_enabled());
        assert!(!config.collectors.logs.is_enabled());
        assert!(config.processors.leak_detection.is_enabled());

        config.validate().expect("config should be valid");
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();

        config.validate().expect("config should be valid");

        config.shard = 5;
        config.shards_count = 3;
        assert!(config.validate().is_err());

        config.shard = 0;
        config.shards_count = 1;
        assert!(config.validate().is_ok());

        config.rate_limit = Configurable::Enabled(RateLimitConfig {
            bucket_burst: 200,
            bucket_replenish: Duration::from_secs(0),
            max_jitter: Duration::from_secs(0),
        });
        assert!(config.validate().is_err());

        config.rate_limit = Configurable::Enabled(RateLimitConfig::default());
        config.processors.leak_detection = Configurable::Enabled(LeakDetectionProcessorConfig {
            minimum_alerts_per_report: 0,
        });
        assert!(config.validate().is_err());

        config.processors.leak_detection =
            Configurable::Enabled(LeakDetectionProcessorConfig::default());
        config.sinks.health_report = Configurable::Enabled(HealthReportSinkConfig {
            workers: 0,
            ..HealthReportSinkConfig::default()
        });
        assert!(config.validate().is_err());

        config.sinks.health_report = Configurable::Enabled(HealthReportSinkConfig::default());

        config.collectors.logs = Configurable::Enabled(LogsCollectorConfig {
            mode: LogCollectionMode::Periodic,
            periodic: None,
        });
        assert!(config.validate().is_err());

        config.collectors.logs = Configurable::Enabled(LogsCollectorConfig {
            mode: LogCollectionMode::Sse,
            periodic: Some(PeriodicLogConfig::default()),
        });
        assert!(config.validate().is_err());

        config.collectors.logs = Configurable::Enabled(LogsCollectorConfig {
            mode: LogCollectionMode::Sse,
            periodic: None,
        });
        assert!(config.validate().is_ok());

        config.collectors.logs = Configurable::Disabled;
        assert!(config.validate().is_ok());

        config.sinks.otlp = Configurable::Enabled(OtlpSinkConfig {
            endpoint: "not a valid uri\n".to_string(),
            ..OtlpSinkConfig::default()
        });
        assert!(config.validate().is_err());

        config.sinks.otlp = Configurable::Enabled(OtlpSinkConfig::default());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_defaults() {
        let config = Config::load(None).expect("should load defaults");
        assert_eq!(config.shard, 0);
        assert_eq!(config.shards_count, 1);
        assert_eq!(config.cache_size, 100);
        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");
        assert!(config.rate_limit.is_enabled());
        assert!(config.processors.leak_detection.is_enabled());
        assert!(!config.collectors.nvue.is_enabled());
    }

    #[test]
    fn test_nvue_config_defaults() {
        let defaults = NvueCollectorConfig::default();
        assert!(defaults.rest.is_enabled());

        if let Configurable::Enabled(ref rest) = defaults.rest {
            assert_eq!(rest.poll_interval, Duration::from_secs(300));
            assert_eq!(rest.request_timeout, Duration::from_secs(30));
            assert!(rest.paths.system_health_enabled);
            assert!(rest.paths.cluster_apps_enabled);
            assert!(rest.paths.sdn_partitions_enabled);
            assert!(rest.paths.interfaces_enabled);
        }
    }

    #[test]
    fn test_nvue_config_parsing() {
        let toml_content = r#"
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[collectors.nvue.rest]
poll_interval = "2m"
request_timeout = "45s"
"#;

        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse nvue config");

        assert!(config.collectors.nvue.is_enabled());

        if let Configurable::Enabled(ref nvue) = config.collectors.nvue {
            if let Configurable::Enabled(ref rest) = nvue.rest {
                assert_eq!(rest.poll_interval, Duration::from_secs(120));
                assert_eq!(rest.request_timeout, Duration::from_secs(45));
                assert!(rest.paths.system_health_enabled);
            } else {
                panic!("nvue rest config should be enabled");
            }
        } else {
            panic!("nvue config should be enabled");
        }
    }

    #[test]
    fn test_nvue_config_disabled_by_default() {
        let config = Config::default();
        assert!(!config.collectors.nvue.is_enabled());
    }

    #[test]
    fn test_nvue_config_explicit_disable() {
        let toml_content = r#"
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[collectors.nvue]
enabled = false
"#;

        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse");

        assert!(!config.collectors.nvue.is_enabled());
    }

    #[test]
    fn test_nvue_config_rest_only() {
        let toml_content = r#"
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[collectors.nvue.rest]
poll_interval = "1m"
"#;

        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse");

        assert!(config.collectors.nvue.is_enabled());
        if let Configurable::Enabled(ref nvue) = config.collectors.nvue {
            assert!(nvue.rest.is_enabled());
        }
    }

    #[test]
    fn test_nvue_config_selective_endpoints() {
        let toml_content = r#"
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[collectors.nvue.rest]
poll_interval = "1m"

[collectors.nvue.rest.paths]
system_health_enabled = true
cluster_apps_enabled = false
sdn_partitions_enabled = true
interfaces_enabled = false
"#;

        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse nvue config with selective endpoints");

        if let Configurable::Enabled(ref nvue) = config.collectors.nvue {
            if let Configurable::Enabled(ref rest) = nvue.rest {
                assert!(rest.paths.system_health_enabled);
                assert!(!rest.paths.cluster_apps_enabled);
                assert!(rest.paths.sdn_partitions_enabled);
                assert!(!rest.paths.interfaces_enabled);
            } else {
                panic!("nvue rest config should be enabled");
            }
        } else {
            panic!("nvue config should be enabled");
        }
    }

    #[test]
    fn test_static_endpoint_with_switch_serial() {
        let toml_content = r#"
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[[endpoint_sources.static_bmc_endpoints]]
ip = "10.0.0.1"
mac = "aa:bb:cc:dd:ee:ff"
username = "admin"
password = "pass"

[[endpoint_sources.static_bmc_endpoints]]
ip = "10.0.1.1"
mac = "11:22:33:44:55:66"
username = "cumulus"
password = "pass"
switch_serial = "SN-SW-001"
"#;

        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string(toml_content))
            .extract()
            .expect("failed to parse static switch endpoint config");

        assert_eq!(config.endpoint_sources.static_bmc_endpoints.len(), 2);
        assert!(
            config.endpoint_sources.static_bmc_endpoints[0]
                .switch_serial
                .is_none()
        );
        assert_eq!(
            config.endpoint_sources.static_bmc_endpoints[1]
                .switch_serial
                .as_deref(),
            Some("SN-SW-001")
        );
    }

    #[test]
    fn test_example_config_static_endpoint_has_switch_serial() {
        let toml_content = include_str!("../example/config.example.toml");
        let config: Config = Figment::new()
            .merge(Toml::string(toml_content))
            .extract()
            .expect("could not parse config toml file");

        assert_eq!(config.endpoint_sources.static_bmc_endpoints.len(), 2);
        assert!(
            config.endpoint_sources.static_bmc_endpoints[0]
                .switch_serial
                .is_none()
        );
        assert_eq!(
            config.endpoint_sources.static_bmc_endpoints[1]
                .switch_serial
                .as_deref(),
            Some("SN-SWITCH-001")
        );
        if let Configurable::Enabled(ref health_report) = config.sinks.health_report {
            assert_eq!(health_report.workers, 8);
        } else {
            panic!("health report sink is disabled");
        }
    }

    #[test]
    fn test_log_config_sse_mode_rejects_periodic_config() {
        let toml = r#"
            mode = "sse"
            [periodic]
            logs_collection_interval = "5m"
        "#;
        let config: LogsCollectorConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("should parse");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_log_config_periodic_mode_requires_periodic_config() {
        let toml = r#"
            mode = "periodic"
        "#;
        let config: LogsCollectorConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("should parse");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_log_config_periodic_mode_with_periodic_config_valid() {
        let toml = r#"
            mode = "periodic"
            [periodic]
            logs_collection_interval = "5m"
        "#;
        let config: LogsCollectorConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("should parse");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_log_config_sse_mode_without_periodic_config_valid() {
        let toml = r#"
            mode = "sse"
        "#;
        let config: LogsCollectorConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("should parse");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_log_config_default_is_sse() {
        let config = LogsCollectorConfig::default();
        assert_eq!(config.mode, LogCollectionMode::Sse);
        assert!(config.periodic.is_none());
        assert!(config.validate().is_ok());
    }
}
