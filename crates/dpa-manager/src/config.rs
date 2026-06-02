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

use std::net::Ipv4Addr;

use carbide_utils::config::{as_duration, as_std_duration};
use duration_str::{deserialize_duration, deserialize_duration_chrono};
use serde::{Deserialize, Serialize};

fn default_mqtt_endpoint() -> String {
    "mqtt.forge".to_string()
}

fn default_mqtt_broker_port() -> u16 {
    1884
}

/// MQTT authentication mode.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MqttAuthMode {
    /// No authentication.
    #[default]
    None,
    /// Username/password basic authentication.
    BasicAuth,
    /// OAuth2 token-based authentication.
    Oauth2,
}

/// OAuth2 configuration for MQTT broker authentication.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct MqttOAuth2Config {
    /// OAuth2 token endpoint URL.
    pub token_url: String,

    /// OAuth2 scopes to request when obtaining a token.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// HTTP timeout for token endpoint requests. Default is 30 seconds.
    #[serde(
        default = "MqttOAuth2Config::default_http_timeout",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub http_timeout: std::time::Duration,

    /// Username sent with the MQTT CONNECT packet when using OAuth2.
    /// Default is "oauth2token".
    #[serde(default = "MqttOAuth2Config::default_username")]
    pub username: String,
}

impl MqttOAuth2Config {
    fn default_http_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    fn default_username() -> String {
        "oauth2token".to_string()
    }
}

/// MQTT authentication configuration shared by DPA and DSX event bus.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct MqttAuthConfig {
    /// Authentication mechanism to use for MQTT connections.
    #[serde(default)]
    pub auth_mode: MqttAuthMode,

    /// OAuth2 settings, required when `auth_mode` is `Oauth2`.
    pub oauth2: Option<MqttOAuth2Config>,
}

/// DPA (aka Cluster Interconnect Network) related configuration.
/// Enables DPA, and specifies basic network settings.
/// The VNI to be used by DPA will be the same as the parent VPC.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct DpaConfig {
    /// Global enable/disable of Cluster Interconnect Network.
    #[serde(default)]
    pub enabled: bool,

    /// MQTT broker host (name or IP address) used to create client connections.
    #[serde(default = "default_mqtt_endpoint")]
    pub mqtt_endpoint: String,

    /// MQTT broker port to use to establish client connections.
    #[serde(default = "default_mqtt_broker_port")]
    pub mqtt_broker_port: u16,

    /// Base IPv4 address of the DPA/Cluster Interconnect subnet.
    #[serde(default = "DpaConfig::default_subnet_ip")]
    pub subnet_ip: Ipv4Addr,

    /// CIDR prefix length for the DPA subnet.
    #[serde(default)]
    pub subnet_mask: i32,

    /// Interval at which we issue heartbeat requests to the DPA.
    /// Defaults to 120 seconds if not specified.
    #[serde(
        default = "DpaConfig::default_hb_interval",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub hb_interval: chrono::TimeDelta,

    /// The interval at which we run the DPA monitor.
    #[serde(
        default = "DpaConfig::default_monitor_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub monitor_run_interval: std::time::Duration,

    #[serde(default)]
    pub auth: MqttAuthConfig,
}

impl DpaConfig {
    pub const fn default_hb_interval() -> chrono::TimeDelta {
        chrono::TimeDelta::minutes(2)
    }

    pub const fn default_monitor_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }

    pub const fn default_subnet_ip() -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
}

impl Default for DpaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mqtt_endpoint: default_mqtt_endpoint(),
            mqtt_broker_port: default_mqtt_broker_port(),
            subnet_ip: Self::default_subnet_ip(),
            subnet_mask: 0,
            hb_interval: Self::default_hb_interval(),
            monitor_run_interval: Self::default_monitor_run_interval(),
            auth: MqttAuthConfig::default(),
        }
    }
}
