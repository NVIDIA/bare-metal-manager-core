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

use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mqtt: MqttConfig,

    pub cache: CacheConfig,

    pub carbide_api: Option<CarbideApiConnectionConfig>,

    pub metrics: MetricsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mqtt: MqttConfig::default(),
            cache: CacheConfig::default(),
            carbide_api: Some(CarbideApiConnectionConfig::default()),
            metrics: MetricsConfig::default(),
        }
    }
}

/// MQTT configuration for connecting to the DSX Exchange Event Bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqttConfig {
    /// MQTT broker endpoint hostname.
    pub endpoint: String,

    /// MQTT broker port.
    pub port: u16,

    /// Client ID for this MQTT connection.
    pub client_id: String,

    /// Topic prefix for Cronus events.
    pub topic_prefix: String,

    /// Maximum number of messages to buffer in the processing queue.
    /// Messages are dropped when this limit is exceeded.
    pub queue_capacity: usize,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            endpoint: "mqtt.forge".to_string(),
            port: 1884,
            client_id: "carbide-dsx-exchange-consumer".to_string(),
            topic_prefix: "cronus/v1".to_string(),
            queue_capacity: 1024,
        }
    }
}

/// Cache configuration for metadata and value state caching.
/// Uses moka crate for automatic TTL-based eviction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Time-to-live for metadata cache entries.
    #[serde(with = "humantime_serde")]
    pub metadata_ttl: Duration,

    /// Time-to-live for value state cache entries (for deduplication).
    #[serde(with = "humantime_serde")]
    pub value_state_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            metadata_ttl: Duration::from_secs(3600),    // 1 hour
            value_state_ttl: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Carbide API connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CarbideApiConnectionConfig {
    /// Path to the root CA certificate for Carbide API connections.
    pub root_ca: String,

    /// Path to the client certificate for Carbide API connections.
    pub client_cert: String,

    /// Path to the client key for Carbide API connections.
    pub client_key: String,

    /// Carbide API server endpoint.
    pub api_url: Url,
}

impl Default for CarbideApiConnectionConfig {
    fn default() -> Self {
        Self {
            root_ca: "/var/run/secrets/spiffe.io/ca.crt".to_string(),
            client_cert: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            client_key: "/var/run/secrets/spiffe.io/tls.key".to_string(),
            api_url: Url::parse("https://carbide-api.forge-system.svc.cluster.local:1079")
                .expect("valid default URL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Metrics listener endpoint.
    pub endpoint: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            endpoint: "0.0.0.0:9009".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from optional path.
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let mut figment = Figment::new().merge(Serialized::defaults(Config::default()));

        if let Some(path) = config_path {
            figment = figment.merge(Toml::file(path));
        }

        figment = figment.merge(Env::prefixed("CARBIDE_DSX_CONSUMER__").split("__"));

        let config: Config = figment
            .extract()
            .map_err(|e| format!("Failed to load configuration: {}", e))?;

        config.validate()?;
        Ok(config)
    }

    /// Get the metrics listener address.
    pub fn metrics_addr(&self) -> Result<SocketAddr, String> {
        self.metrics
            .endpoint
            .parse()
            .map_err(|_| format!("Invalid metrics endpoint: {}", self.metrics.endpoint))
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.metrics_addr()?;
        Ok(())
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

        assert_eq!(config.mqtt.endpoint, "mqtt.forge");
        assert_eq!(config.mqtt.port, 1884);
        assert_eq!(config.mqtt.client_id, "carbide-dsx-exchange-consumer");
        assert_eq!(config.mqtt.topic_prefix, "cronus/v1");

        if let Some(ref carbide_api) = config.carbide_api {
            assert_eq!(carbide_api.root_ca, "/var/run/secrets/spiffe.io/ca.crt");
            assert_eq!(
                carbide_api.client_cert,
                "/var/run/secrets/spiffe.io/tls.crt"
            );
            assert_eq!(carbide_api.client_key, "/var/run/secrets/spiffe.io/tls.key");
        } else {
            panic!("carbide api should be enabled")
        }

        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");
    }

    #[test]
    fn test_load_defaults() {
        let config = Config::load(None).expect("should load defaults");
        assert_eq!(config.mqtt.endpoint, "mqtt.forge");
        assert_eq!(config.mqtt.port, 1884);
        assert_eq!(config.metrics.endpoint, "0.0.0.0:9009");
    }
}
