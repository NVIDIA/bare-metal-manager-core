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

    pub health_sinks: HealthSinksConfig,

    pub rate_limit: Configurable<RateLimitConfig>,

    pub collectors: CollectorsConfig,

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
            health_sinks: HealthSinksConfig::default(),
            rate_limit: Configurable::Enabled(RateLimitConfig::default()),
            collectors: CollectorsConfig::default(),
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
    pub password: String,
}

/// Debug structure omits credentials
impl Debug for StaticBmcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticBmcEndpoint")
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("mac", &self.mac)
            .finish()
    }
}

/// Configuration for where health reports are sent to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthSinksConfig {
    /// Carbide API connection settings for reporting (if present, Carbide API sink is enabled)
    pub carbide_api: Configurable<CarbideApiConnectionConfig>,

    /// Represents console health report sink, will write reports to the console
    pub console: bool,
}

impl Default for HealthSinksConfig {
    fn default() -> Self {
        Self {
            carbide_api: Configurable::Enabled(CarbideApiConnectionConfig::default()),
            console: false,
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
    /// Health collector configuration (if present, health collector is enabled)
    pub health: Configurable<HealthCollectorConfig>,

    /// Firmware collector configuration (if present, firmware collector is enabled)
    pub firmware: Configurable<FirmwareCollectorConfig>,

    /// Logs collector configuration (if present, logs collector is enabled)
    pub logs: Configurable<LogsCollectorConfig>,

    /// Switch NMX-T collector configuration (if present, nmxt collector is enabled)
    pub nmxt: Configurable<NmxtCollectorConfig>,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            health: Configurable::Enabled(HealthCollectorConfig::default()),
            firmware: Configurable::Disabled,
            logs: Configurable::Enabled(LogsCollectorConfig::default()),
            nmxt: Configurable::Disabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCollectorConfig {
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

impl Default for HealthCollectorConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsCollectorConfig {
    /// Interval between log collection.
    #[serde(with = "humantime_serde")]
    pub logs_collection_interval: Duration,

    /// Path to logs collector state file (supports {machine_id} placeholder).
    pub logs_state_file: String,

    /// Directory path for log output files.
    pub logs_output_dir: String,

    /// Maximum log file size before rotation (in bytes).
    pub logs_max_file_size: u64,

    /// Maximum number of rotated log files to keep.
    pub logs_max_backups: usize,
}

impl Default for LogsCollectorConfig {
    fn default() -> Self {
        Self {
            logs_collection_interval: Duration::from_secs(300),
            logs_state_file: "/tmp/logs_collector_{machine_id}.json".to_string(),
            logs_output_dir: "/tmp/logs".to_string(),
            logs_max_file_size: 104857600,
            logs_max_backups: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NmxtCollectorConfig {
    /// Interval between switch NMX-T metric scrapes.
    #[serde(with = "humantime_serde")]
    pub scrape_interval: Duration,
}

impl Default for NmxtCollectorConfig {
    fn default() -> Self {
        Self {
            scrape_interval: Duration::from_secs(60),
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

        if let Configurable::Enabled(ref carbide_api) = config.health_sinks.carbide_api {
            assert_eq!(carbide_api.root_ca, "/var/run/secrets/spiffe.io/ca.crt");
        } else {
            panic!("carbide api empty for sinks")
        }

        if let Configurable::Enabled(ref rate_limit) = config.rate_limit {
            assert_eq!(rate_limit.bucket_replenish, Duration::from_millis(35));
            assert_eq!(rate_limit.bucket_burst, 200);
            assert_eq!(rate_limit.max_jitter, Duration::from_millis(40));
        } else {
            panic!("rate limit empty")
        }

        assert!(config.collectors.health.is_enabled());
        assert!(config.collectors.firmware.is_enabled());
        assert!(config.collectors.logs.is_enabled());
        assert!(config.health_sinks.console);

        if let Configurable::Enabled(ref health) = config.collectors.health {
            assert_eq!(health.rediscover_interval, Duration::from_secs(300));
            assert_eq!(health.sensor_fetch_concurrency, 10);
        } else {
            panic!("health empty")
        }

        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");

        assert_eq!(config.shard, 0);
        assert_eq!(config.shards_count, 1);

        assert_eq!(config.cache_size, 100);
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

[health_sinks.carbide_api]
enabled = false

[collectors.health]
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
        assert!(!config.health_sinks.carbide_api.is_enabled());

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

        assert!(config.collectors.health.is_enabled());
        if let Configurable::Enabled(ref health) = config.collectors.health {
            assert_eq!(health.rediscover_interval, Duration::from_secs(60));
            assert_eq!(health.sensor_fetch_interval, Duration::from_secs(30));
            assert!(!health.include_sensor_thresholds);
        } else {
            panic!("health empty")
        }

        assert!(!config.collectors.firmware.is_enabled());
        assert!(config.collectors.logs.is_enabled());

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
    }

    #[test]
    fn test_load_defaults() {
        let config = Config::load(None).expect("should load defaults");
        assert_eq!(config.shard, 0);
        assert_eq!(config.shards_count, 1);
        assert_eq!(config.cache_size, 100);
        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");
        assert!(config.rate_limit.is_enabled());
    }
}
