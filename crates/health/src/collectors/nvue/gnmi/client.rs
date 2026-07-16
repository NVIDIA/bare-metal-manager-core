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

use std::time::Duration;

use tonic::metadata::MetadataMap;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Extensions, Request};

use super::proto::g_nmi_client::GNmiClient as TonicGnmiClient;
use super::proto::subscription_list::Mode as SubscriptionListMode;
use super::proto::{
    self, Encoding, Path, PathElem, SubscribeRequest, Subscription, SubscriptionList,
    SubscriptionMode,
};
use crate::HealthError;
use crate::config::{MtlsProfileConfig, NvueGnmiPaths};

pub fn nvue_subscribe_paths(paths_config: &NvueGnmiPaths) -> Vec<Path> {
    let mut paths = Vec::with_capacity(4);
    if paths_config.components_enabled {
        paths.push(Path {
            elem: vec![
                PathElem {
                    name: "components".into(),
                    key: Default::default(),
                },
                PathElem {
                    name: "component".into(),
                    key: Default::default(),
                },
            ],
            ..Default::default()
        });
    }
    if paths_config.interfaces_enabled {
        paths.push(Path {
            elem: vec![
                PathElem {
                    name: "interfaces".into(),
                    key: Default::default(),
                },
                PathElem {
                    name: "interface".into(),
                    key: Default::default(),
                },
            ],
            ..Default::default()
        });
    }
    if paths_config.platform_general_enabled {
        // `/platform-general/state` carries the memory and disk
        // utilization leaves
        paths.push(Path {
            elem: vec![
                PathElem {
                    name: "platform-general".into(),
                    key: Default::default(),
                },
                PathElem {
                    name: "state".into(),
                    key: Default::default(),
                },
            ],
            ..Default::default()
        });
        // `/platform-general/versions` carries the OS/BMC/EROT
        // firmware version leaves
        paths.push(Path {
            elem: vec![
                PathElem {
                    name: "platform-general".into(),
                    key: Default::default(),
                },
                PathElem {
                    name: "versions".into(),
                    key: Default::default(),
                },
            ],
            ..Default::default()
        });
    }
    paths
}

#[derive(Clone)]
pub struct GnmiClient {
    switch_id: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    request_timeout: Duration,
    dangerously_skip_tls_verification: bool,
    tls_config: Option<MtlsProfileConfig>,
}

/// Configuration used to build one gNMI client instance.
pub(super) struct GnmiClientConfig {
    /// Switch identifier used in logs and error messages.
    pub switch_id: String,

    /// Switch host or IP address used for the gNMI channel.
    pub host: String,

    /// gNMI TCP port on the switch host.
    pub port: u16,

    /// Optional username sent as gNMI `username` metadata.
    pub username: Option<String>,

    /// Optional password sent as gNMI `password` metadata.
    pub password: Option<String>,

    /// Timeout applied to gNMI connection and RPC operations.
    pub request_timeout: Duration,

    /// Whether legacy non-mTLS connections accept invalid switch certificates.
    pub dangerously_skip_tls_verification: bool,

    /// mTLS profile used when opening the gNMI channel.
    pub tls_config: Option<MtlsProfileConfig>,
}

async fn configure_tls_endpoint(
    endpoint: Endpoint,
    switch_id: &str,
    dangerously_skip_tls_verification: bool,
    tls_config: Option<&MtlsProfileConfig>,
) -> Result<Endpoint, HealthError> {
    if let Some(config) = tls_config {
        // mTLS config supplies both trust roots and client identity. Use it as
        // the complete TLS policy for this channel.
        let tls_config = crate::tls::tonic_tls_config(config).await?;

        return endpoint.tls_config(tls_config).map_err(|e| {
            HealthError::GnmiError(format!("switch {switch_id}: invalid gNMI TLS config: {e}"))
        });
    }

    if !dangerously_skip_tls_verification {
        return Ok(endpoint);
    }

    // Use tonic's verifier hook (https endpoints get a strict verifier
    // otherwise). No roots on ClientTlsConfig — roots + verifier is an error.
    endpoint
        .tls_config_with_verifier(
            ClientTlsConfig::new(),
            crate::collectors::nvue::tls::accept_any_cert_verifier(),
        )
        .map_err(|e| {
            HealthError::GnmiError(format!("switch {switch_id}: invalid gNMI TLS config: {e}"))
        })
}

impl GnmiClient {
    pub(super) fn new(config: GnmiClientConfig) -> Self {
        Self {
            switch_id: config.switch_id,
            host: config.host,
            port: config.port,
            username: config.username,
            password: config.password,
            request_timeout: config.request_timeout,
            dangerously_skip_tls_verification: config.dangerously_skip_tls_verification,
            tls_config: config.tls_config,
        }
    }

    async fn connect(&self) -> Result<TonicGnmiClient<Channel>, HealthError> {
        let target = format!("{}:{}", self.host, self.port);

        let uri = http::Uri::builder()
            .scheme("https")
            .authority(target.as_str())
            .path_and_query("/")
            .build()
            .map_err(|e| {
                HealthError::GnmiError(format!(
                    "switch {}: invalid endpoint URI: {e}",
                    self.switch_id
                ))
            })?;

        let endpoint = configure_tls_endpoint(
            Endpoint::from(uri),
            &self.switch_id,
            self.dangerously_skip_tls_verification,
            self.tls_config.as_ref(),
        )
        .await?
        .connect_timeout(self.request_timeout)
        .timeout(self.request_timeout);

        let channel = endpoint.connect().await.map_err(|e| {
            HealthError::GnmiError(format!(
                "switch {}: connection failed to {target}: {e}",
                self.switch_id
            ))
        })?;

        if self.dangerously_skip_tls_verification {
            tracing::debug!(
                switch_id = %self.switch_id,
                target = %target,
                "gNMI TLS channel established with certificate verification disabled"
            );
        } else {
            tracing::debug!(
                switch_id = %self.switch_id,
                target = %target,
                "gNMI TLS channel established"
            );
        }

        Ok(TonicGnmiClient::new(channel))
    }

    /// open a gNMI SAMPLE streaming subscription
    pub async fn subscribe_sample(
        &self,
        paths: &[Path],
        sample_interval_nanos: u64,
    ) -> Result<tonic::Streaming<proto::SubscribeResponse>, HealthError> {
        let mut client = self.connect().await?;

        let subscribe_request = build_sample_subscribe_request(paths, sample_interval_nanos);

        let auth = build_auth_metadata(&self.username, &self.password)?;
        let stream = tokio_stream::once(subscribe_request);
        let request = Request::from_parts(auth, Extensions::default(), stream);

        let response = client
            .subscribe(request)
            .await
            .map_err(HealthError::GnmiStatus)?;

        tracing::debug!(
            switch_id = %self.switch_id,
            sample_interval_nanoseconds = sample_interval_nanos,
            "gNMI SAMPLE stream opened"
        );

        Ok(response.into_inner())
    }

    /// open a gNMI ON_CHANGE streaming subscription
    pub async fn subscribe_on_change(
        &self,
        prefix: &Path,
        paths: &[Path],
    ) -> Result<tonic::Streaming<proto::SubscribeResponse>, HealthError> {
        let mut client = self.connect().await?;

        let subscribe_request = build_on_change_subscribe_request(prefix, paths);

        let auth = build_auth_metadata(&self.username, &self.password)?;
        let stream = tokio_stream::once(subscribe_request);
        let request = Request::from_parts(auth, Extensions::default(), stream);

        let response = client
            .subscribe(request)
            .await
            .map_err(HealthError::GnmiStatus)?;

        tracing::debug!(
            switch_id = %self.switch_id,
            "gNMI ON_CHANGE stream opened"
        );

        Ok(response.into_inner())
    }
}

pub(crate) fn system_events_prefix() -> Path {
    Path {
        target: "nvos".to_string(),
        elem: vec![PathElem {
            name: "system-events".to_string(),
            key: Default::default(),
        }],
        ..Default::default()
    }
}

/// gNMI path for ON_CHANGE system event subscriptions. An empty path subscribes
/// to all events below the `system-events` prefix.
pub(crate) fn system_events_subscribe_path() -> Vec<Path> {
    vec![Path::default()]
}

fn build_on_change_subscribe_request(prefix: &Path, paths: &[Path]) -> SubscribeRequest {
    let subscription_list = SubscriptionList {
        prefix: Some(prefix.clone()),
        subscription: paths
            .iter()
            .map(|path| Subscription {
                path: Some(path.clone()),
                mode: SubscriptionMode::OnChange.into(),
                ..Default::default()
            })
            .collect(),
        mode: SubscriptionListMode::Stream.into(),
        encoding: Encoding::Json.into(),
        updates_only: true,
        ..Default::default()
    };

    SubscribeRequest {
        request: Some(proto::subscribe_request::Request::Subscribe(
            subscription_list,
        )),
        extension: vec![],
    }
}

fn build_sample_subscribe_request(paths: &[Path], sample_interval_nanos: u64) -> SubscribeRequest {
    let subscription_list = SubscriptionList {
        prefix: Some(Path {
            target: "nvos".to_string(),
            ..Default::default()
        }),
        subscription: paths
            .iter()
            .map(|path| Subscription {
                path: Some(path.clone()),
                mode: SubscriptionMode::Sample.into(),
                sample_interval: sample_interval_nanos,
                ..Default::default()
            })
            .collect(),
        mode: SubscriptionListMode::Stream.into(),
        encoding: Encoding::Json.into(),
        ..Default::default()
    };

    SubscribeRequest {
        request: Some(proto::subscribe_request::Request::Subscribe(
            subscription_list,
        )),
        extension: vec![],
    }
}

fn build_auth_metadata(
    username: &Option<String>,
    password: &Option<String>,
) -> Result<MetadataMap, HealthError> {
    let mut meta = MetadataMap::new();
    if let Some(username) = username {
        let value = username.parse().map_err(|e| {
            HealthError::GnmiError(format!("invalid username for gRPC metadata: {e}"))
        })?;
        meta.insert("username", value);
    }
    if let Some(password) = password {
        let value = password
            .parse()
            .map_err(|_e| HealthError::GnmiError("invalid password for gRPC metadata".into()))?;
        meta.insert("password", value);
    }
    Ok(meta)
}

/// Extract a string from a `TypedValue`, handling JSON-encoded bytes as well
/// as native string values.
#[allow(deprecated)]
pub fn typed_value_to_string(val: &proto::TypedValue) -> Option<String> {
    use proto::typed_value::Value;
    match &val.value {
        Some(Value::StringVal(s)) => Some(s.clone()),
        Some(Value::JsonVal(bytes)) | Some(Value::JsonIetfVal(bytes)) => {
            let s = String::from_utf8_lossy(bytes);
            let trimmed = s.trim().trim_matches('"');
            Some(trimmed.to_string())
        }
        Some(Value::AsciiVal(s)) => Some(s.clone()),
        Some(Value::IntVal(v)) => Some(v.to_string()),
        Some(Value::UintVal(v)) => Some(v.to_string()),
        Some(Value::BoolVal(v)) => Some(v.to_string()),
        Some(Value::FloatVal(v)) => Some(v.to_string()),
        Some(Value::DoubleVal(v)) => Some(v.to_string()),
        _ => None,
    }
}

/// Extract a float from a `TypedValue`, handling JSON-encoded bytes, native
/// numeric values, and string representations.
#[allow(deprecated)]
pub fn typed_value_to_f64(val: &proto::TypedValue) -> Option<f64> {
    use proto::typed_value::Value;
    match &val.value {
        Some(Value::DoubleVal(v)) => Some(*v),
        Some(Value::FloatVal(v)) => Some(*v as f64),
        Some(Value::IntVal(v)) => Some(*v as f64),
        Some(Value::UintVal(v)) => Some(*v as f64),
        Some(Value::StringVal(s)) => s.parse().ok(),
        Some(Value::JsonVal(bytes)) | Some(Value::JsonIetfVal(bytes)) => {
            let s = String::from_utf8_lossy(bytes);
            s.trim().trim_matches('"').parse().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_value_to_string_string_val() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::StringVal("healthy".to_string())),
        };
        assert_eq!(typed_value_to_string(&val), Some("healthy".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_json_val() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::JsonVal(b"\"degraded\"".to_vec())),
        };
        assert_eq!(typed_value_to_string(&val), Some("degraded".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_json_unquoted() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::JsonVal(b"42".to_vec())),
        };
        assert_eq!(typed_value_to_string(&val), Some("42".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_int() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::IntVal(-5)),
        };
        assert_eq!(typed_value_to_string(&val), Some("-5".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_uint() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::UintVal(100)),
        };
        assert_eq!(typed_value_to_string(&val), Some("100".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_bool() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::BoolVal(true)),
        };
        assert_eq!(typed_value_to_string(&val), Some("true".to_string()));
    }

    #[test]
    fn test_typed_value_to_string_none() {
        let val = proto::TypedValue { value: None };
        assert_eq!(typed_value_to_string(&val), None);
    }

    #[test]
    fn test_typed_value_to_f64_double() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::DoubleVal(42.5)),
        };
        assert_eq!(typed_value_to_f64(&val), Some(42.5));
    }

    #[test]
    fn test_typed_value_to_f64_int() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::IntVal(42)),
        };
        assert_eq!(typed_value_to_f64(&val), Some(42.0));
    }

    #[test]
    fn test_typed_value_to_f64_json_string() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::JsonVal(b"\"1.5e-3\"".to_vec())),
        };
        assert_eq!(typed_value_to_f64(&val), Some(0.0015));
    }

    #[test]
    fn test_typed_value_to_f64_json_number() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::JsonVal(b"99.9".to_vec())),
        };
        assert_eq!(typed_value_to_f64(&val), Some(99.9));
    }

    #[test]
    fn test_typed_value_to_f64_string() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::StringVal("1.23".to_string())),
        };
        assert_eq!(typed_value_to_f64(&val), Some(1.23));
    }

    #[test]
    fn test_typed_value_to_f64_non_numeric_string() {
        let val = proto::TypedValue {
            value: Some(proto::typed_value::Value::StringVal("hello".to_string())),
        };
        assert_eq!(typed_value_to_f64(&val), None);
    }

    #[test]
    fn test_typed_value_to_f64_none() {
        let val = proto::TypedValue { value: None };
        assert_eq!(typed_value_to_f64(&val), None);
    }

    #[test]
    fn test_gnmi_client_stores_dangerous_tls_skip_flag() {
        let strict = GnmiClient::new(GnmiClientConfig {
            switch_id: "switch-1".to_string(),
            host: "10.0.0.9".to_string(),
            port: 9339,
            username: None,
            password: None,
            request_timeout: Duration::from_secs(30),
            dangerously_skip_tls_verification: false,
            tls_config: None,
        });

        assert!(!strict.dangerously_skip_tls_verification);

        let dangerous = GnmiClient::new(GnmiClientConfig {
            switch_id: "switch-1".to_string(),
            host: "10.0.0.9".to_string(),
            port: 9339,
            username: None,
            password: None,
            request_timeout: Duration::from_secs(30),
            dangerously_skip_tls_verification: true,
            tls_config: None,
        });

        assert!(dangerous.dangerously_skip_tls_verification);
    }

    #[test]
    fn test_nvue_subscribe_paths_all_enabled() {
        let paths = nvue_subscribe_paths(&NvueGnmiPaths::default());
        assert_eq!(paths.len(), 4);

        assert_eq!(paths[0].elem.len(), 2);
        assert_eq!(paths[0].elem[0].name, "components");
        assert_eq!(paths[0].elem[1].name, "component");

        assert_eq!(paths[1].elem.len(), 2);
        assert_eq!(paths[1].elem[0].name, "interfaces");
        assert_eq!(paths[1].elem[1].name, "interface");

        assert_eq!(paths[2].elem.len(), 2);
        assert_eq!(paths[2].elem[0].name, "platform-general");
        assert_eq!(paths[2].elem[1].name, "state");

        assert_eq!(paths[3].elem.len(), 2);
        assert_eq!(paths[3].elem[0].name, "platform-general");
        assert_eq!(paths[3].elem[1].name, "versions");
    }

    #[test]
    fn test_nvue_subscribe_paths_selective() {
        let paths = nvue_subscribe_paths(&NvueGnmiPaths {
            components_enabled: false,
            interfaces_enabled: true,
            platform_general_enabled: false,
        });
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].elem.len(), 2);
        assert_eq!(paths[0].elem[0].name, "interfaces");
        assert_eq!(paths[0].elem[1].name, "interface");
    }

    #[test]
    fn test_nvue_subscribe_paths_platform_general_only() {
        let paths = nvue_subscribe_paths(&NvueGnmiPaths {
            components_enabled: false,
            interfaces_enabled: false,
            platform_general_enabled: true,
        });
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].elem.len(), 2);
        assert_eq!(paths[0].elem[0].name, "platform-general");
        assert_eq!(paths[0].elem[1].name, "state");
        assert_eq!(paths[1].elem.len(), 2);
        assert_eq!(paths[1].elem[0].name, "platform-general");
        assert_eq!(paths[1].elem[1].name, "versions");
    }

    #[test]
    fn test_nvue_subscribe_paths_none_enabled() {
        let paths = nvue_subscribe_paths(&NvueGnmiPaths {
            components_enabled: false,
            interfaces_enabled: false,
            platform_general_enabled: false,
        });
        assert!(paths.is_empty());
    }

    #[test]
    fn test_build_sample_subscribe_request() {
        let paths = nvue_subscribe_paths(&NvueGnmiPaths::default());
        let interval_nanos = 300_000_000_000u64;

        let req = build_sample_subscribe_request(&paths, interval_nanos);

        let sub_list = match req.request {
            Some(proto::subscribe_request::Request::Subscribe(sl)) => sl,
            _ => panic!("expected Subscribe variant"),
        };

        assert_eq!(
            sub_list.mode,
            i32::from(SubscriptionListMode::Stream),
            "must use Stream mode for SAMPLE subscriptions"
        );
        assert_eq!(
            sub_list.encoding,
            i32::from(Encoding::Json),
            "encoding must be JSON"
        );

        let prefix = sub_list.prefix.expect("prefix must be set");
        assert_eq!(prefix.target, "nvos", "target must be nvos");

        assert_eq!(sub_list.subscription.len(), 4);
        for sub in &sub_list.subscription {
            assert_eq!(
                sub.mode,
                i32::from(SubscriptionMode::Sample),
                "each subscription must use Sample mode"
            );
            assert_eq!(
                sub.sample_interval, interval_nanos,
                "sample_interval must match the requested interval"
            );
            assert!(sub.path.is_some(), "each subscription must have a path");
        }
    }

    #[test]
    fn test_system_events_prefix() {
        let prefix = system_events_prefix();
        assert_eq!(prefix.target, "nvos");
        assert_eq!(prefix.elem.len(), 1);
        assert_eq!(prefix.elem[0].name, "system-events");
    }

    #[test]
    fn test_system_events_subscribe_path() {
        let paths = system_events_subscribe_path();
        assert_eq!(paths.len(), 1);
        assert!(
            paths[0].elem.is_empty(),
            "empty path subscribes to all events under prefix"
        );
    }

    #[test]
    fn test_build_on_change_subscribe_request() {
        let prefix = system_events_prefix();
        let paths = system_events_subscribe_path();

        let req = build_on_change_subscribe_request(&prefix, &paths);

        let sub_list = match req.request {
            Some(proto::subscribe_request::Request::Subscribe(sl)) => sl,
            _ => panic!("expected Subscribe variant"),
        };

        assert_eq!(
            sub_list.mode,
            i32::from(SubscriptionListMode::Stream),
            "must use Stream mode"
        );
        assert_eq!(
            sub_list.encoding,
            i32::from(Encoding::Json),
            "encoding must be JSON"
        );
        assert!(sub_list.updates_only, "ON_CHANGE must use updates_only");

        let req_prefix = sub_list.prefix.expect("prefix must be set");
        assert_eq!(req_prefix.target, "nvos");
        assert_eq!(req_prefix.elem.len(), 1);
        assert_eq!(req_prefix.elem[0].name, "system-events");

        assert_eq!(sub_list.subscription.len(), 1);
        assert_eq!(
            sub_list.subscription[0].mode,
            i32::from(SubscriptionMode::OnChange),
            "subscription must use OnChange mode"
        );
    }
}
