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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use base64::Engine as _;
use http::HeaderValue;
use http::header::{ACCEPT, AUTHORIZATION};
use reqwest::Client;
use serde::Deserialize;
use serde::de::Error as _;
use url::Url;

use crate::HealthError;
use crate::config::NvueRestPaths;
use crate::tls::{MtlsHttpClient, MtlsHttpClientProvider};

const NVUE_SYSTEM_HEALTH: &str = "/nvue_v1/system/health";
const NVUE_SYSTEM_REBOOT_REASON: &str = "/nvue_v1/system/reboot/reason";
const NVUE_CLUSTER_APPS: &str = "/nvue_v1/cluster/apps";
const NVUE_SDN_PARTITIONS: &str = "/nvue_v1/sdn/partition";
const NVUE_INTERFACES: &str = "/nvue_v1/interface";
const NVUE_PLATFORM_ENVIRONMENT_FAN: &str = "/nvue_v1/platform/environment/fan";
const NVUE_PLATFORM_ENVIRONMENT_TEMPERATURE: &str = "/nvue_v1/platform/environment/temperature";
const NVUE_PLATFORM_ENVIRONMENT_LEAKAGE: &str = "/nvue_v1/platform/environment/leakage";
const NVUE_PLATFORM_ENVIRONMENT: &str = "/nvue_v1/platform/environment";

#[derive(Clone)]
pub struct UsernamePassword {
    pub username: String,
    pub password: Option<String>,
}

impl std::fmt::Debug for UsernamePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernamePassword")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Result envelope for NVUE REST paths where HTTP 200 `null` is meaningful.
///
/// `Null` means the request succeeded and NVUE returned a JSON `null` body, so
/// the collector can apply endpoint-specific unavailable handling instead of
/// acting as if the path was disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionalNvueResponse<T> {
    /// Path disabled by caller; no HTTP request was made.
    Disabled,

    /// Path was polled and returned a top-level JSON `null`.
    Null,

    /// Path was polled and returned a concrete response payload.
    Present(T),
}

pub struct RestClient {
    pub(crate) switch_id: String,
    base_url: Url,
    credentials: ArcSwapOption<UsernamePassword>,
    paths: NvueRestPaths,
    http_client: RestHttpClient,
}

enum RestHttpClient {
    Legacy(Client),

    // Share the mTLS HTTP client provider across switch targets. Hyper-rustls
    // applies `[tls.switch].tls_server_name` only to SNI and certificate
    // verification, so the request URL and HTTP Host header remain the
    // discovered switch IP.
    Tls {
        provider: MtlsHttpClientProvider,

        // Per-iteration client clone prepared by `ensure_http_client`. It is
        // cleared before refresh so an expired reload window cannot fall back
        // to stale TLS material in the same collector iteration.
        current_client: ArcSwapOption<MtlsHttpClient>,

        request_timeout: Duration,
    },
}

impl RestClient {
    pub fn new(
        switch_id: String,
        connect_ip: IpAddr,
        port: Option<u16>,
        request_timeout: Duration,
        self_signed_tls: bool,
        tls_http_client_provider: Option<MtlsHttpClientProvider>,
        paths: NvueRestPaths,
    ) -> Result<Self, HealthError> {
        let port = port.unwrap_or(443);

        let host = match connect_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };

        let raw_url = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };

        let base_url = Url::parse(&raw_url)
            .map_err(|e| HealthError::HttpError(format!("{raw_url}: invalid base URL: {e}")))?;

        let http_client = match tls_http_client_provider {
            Some(provider) => RestHttpClient::Tls {
                provider,
                current_client: ArcSwapOption::empty(),
                request_timeout,
            },
            None => {
                let mut builder = Client::builder().timeout(request_timeout);

                if self_signed_tls {
                    // ! dangerously accept the self-signed certificate.
                    builder = builder.danger_accept_invalid_certs(true);
                }

                let client = builder.build().map_err(|e| {
                    HealthError::HttpError(format!("{base_url}: failed to create HTTP client: {e}"))
                })?;

                RestHttpClient::Legacy(client)
            }
        };

        Ok(Self {
            switch_id,
            base_url,
            credentials: ArcSwapOption::empty(),
            paths,
            http_client,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_base_url_for_test(
        switch_id: String,
        base_url: Url,
        request_timeout: Duration,
        paths: NvueRestPaths,
    ) -> Result<Self, HealthError> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| {
                HealthError::HttpError(format!("{base_url}: failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            switch_id,
            base_url,
            credentials: ArcSwapOption::empty(),
            paths,
            http_client: RestHttpClient::Legacy(client),
        })
    }

    /// Checks the shared mTLS HTTP client cache before NVUE REST requests.
    ///
    /// When an mTLS profile is configured, this asks the shared provider to
    /// refresh at most once per reload window before the collector starts
    /// issuing target-specific requests.
    pub async fn ensure_http_client(&mut self) -> Result<(), HealthError> {
        if let RestHttpClient::Tls {
            provider,
            current_client,
            ..
        } = &mut self.http_client
        {
            // Clear the old clone before refresh so a failed reload cannot be
            // followed by accidental use of stale cert material in this
            // collector iteration.
            current_client.store(None);

            let client = provider.client().await?;

            current_client.store(Some(Arc::new(client)));
        }

        Ok(())
    }

    pub fn set_credentials(&self, creds: UsernamePassword) {
        self.credentials.store(Some(Arc::new(creds)));
    }

    pub fn clear_credentials(&self) {
        self.credentials.store(None);
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials.load().is_some()
    }

    pub async fn get_system_health(&self) -> Result<Option<SystemHealthResponse>, HealthError> {
        if !self.paths.system_health_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_SYSTEM_HEALTH)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_system_reboot_reason(
        &self,
    ) -> Result<OptionalNvueResponse<RebootReasonResponse>, HealthError> {
        if !self.paths.system_reboot_reason_enabled {
            return Ok(OptionalNvueResponse::Disabled);
        }

        let url = self.join_path(NVUE_SYSTEM_REBOOT_REASON)?;
        self.do_get_nullable(url, &[]).await
    }

    pub async fn get_cluster_apps(&self) -> Result<Option<ClusterAppsResponse>, HealthError> {
        if !self.paths.cluster_apps_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_CLUSTER_APPS)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_sdn_partitions(&self) -> Result<Option<SdnPartitionsResponse>, HealthError> {
        if !self.paths.sdn_partitions_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_SDN_PARTITIONS)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_platform_environment_fan(
        &self,
    ) -> Result<Option<FanEnvironmentResponse>, HealthError> {
        if !self.paths.platform_environment_fan_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_PLATFORM_ENVIRONMENT_FAN)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_platform_environment_temperature(
        &self,
    ) -> Result<Option<TemperatureEnvironmentResponse>, HealthError> {
        if !self.paths.platform_environment_temperature_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_PLATFORM_ENVIRONMENT_TEMPERATURE)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_platform_environment_leakage(
        &self,
    ) -> Result<OptionalNvueResponse<LeakageEnvironmentResponse>, HealthError> {
        if !self.paths.platform_environment_leakage_enabled {
            return Ok(OptionalNvueResponse::Disabled);
        }

        let url = self.join_path(NVUE_PLATFORM_ENVIRONMENT_LEAKAGE)?;
        self.do_get_nullable(url, &[]).await
    }

    pub async fn get_platform_environment(
        &self,
    ) -> Result<Option<PlatformEnvironmentResponse>, HealthError> {
        if !self.paths.platform_environment_status_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_PLATFORM_ENVIRONMENT)?;
        self.do_get(url, &[]).await.map(Some)
    }

    pub async fn get_interfaces(&self) -> Result<Option<InterfacesResponse>, HealthError> {
        if !self.paths.interfaces_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_INTERFACES)?;
        self.do_get(
            url,
            &[
                ("filter_", "type=nvl"),
                ("include", "/*/type"),
                ("include", "/*/link/diagnostics"),
            ],
        )
        .await
        .map(Some)
    }

    /// Fetch link diagnostics by flattening the interfaces response into
    /// per-interface per-code diagnostic results.
    pub async fn get_link_diagnostics(&self) -> Result<Vec<LinkDiagnosticResult>, HealthError> {
        let Some(interfaces) = self.get_interfaces().await? else {
            return Ok(Vec::new());
        };

        let mut results = Vec::new();
        for (iface_name, iface_data) in interfaces {
            for (code, diag_status) in iface_data.link.diagnostics {
                results.push(LinkDiagnosticResult {
                    interface: iface_name.clone(),
                    code,
                    status: diag_status.status,
                });
            }
        }
        Ok(results)
    }

    fn join_path(&self, path: &str) -> Result<Url, HealthError> {
        self.base_url.join(path).map_err(|e| {
            HealthError::HttpError(format!(
                "{}: failed to join path {path}: {e}",
                self.base_url
            ))
        })
    }

    async fn do_get<T: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        extra_query: &[(&str, &str)],
    ) -> Result<T, HealthError> {
        let mut url = url;

        // GET /interface (returning a collection) defaults to rev=applied, not
        // operational. There is inconsistency across the NVUE endpoints, so we
        // need to check each. We want the actual system state (rev=operational),
        // rather than defaults or what's configured (rev=applied).
        url.query_pairs_mut().append_pair("rev", "operational");

        if !extra_query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(extra_query.iter().copied());
        }

        let (status, body) = match &self.http_client {
            RestHttpClient::Legacy(client) => {
                let mut request = client
                    .get(url.as_str())
                    .header("accept", "application/json");

                if let Some(creds) = self.credentials.load_full() {
                    request = request.basic_auth(&creds.username, creds.password.as_ref());
                }

                let response = request.send().await.map_err(|e| {
                    HealthError::HttpError(format!(
                        "{url}: request failed for switch {}: {e}",
                        self.switch_id
                    ))
                })?;

                let status = response.status();

                let body = response.bytes().await.map_err(|e| {
                    HealthError::HttpError(format!(
                        "{url}: failed to read response for switch {}: {e}",
                        self.switch_id
                    ))
                })?;

                (status, body)
            }
            RestHttpClient::Tls {
                provider,
                current_client,
                request_timeout,
            } => {
                let client = match current_client.load_full() {
                    Some(client) => client,
                    None => Arc::new(provider.client().await?),
                };

                let mut headers = vec![(ACCEPT, HeaderValue::from_static("application/json"))];

                if let Some(creds) = self.credentials.load_full() {
                    let password = creds.password.as_deref().unwrap_or_default();
                    let encoded = base64::engine::general_purpose::STANDARD
                        .encode(format!("{}:{password}", creds.username));

                    let value =
                        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|e| {
                            HealthError::HttpError(format!(
                                "{url}: failed to build authorization header for switch {}: {e}",
                                self.switch_id
                            ))
                        })?;

                    headers.push((AUTHORIZATION, value));
                }

                let response = client
                    .get(&url, headers, *request_timeout)
                    .await
                    .map_err(|e| {
                        HealthError::HttpError(format!(
                            "{url}: request failed for switch {}: {e}",
                            self.switch_id
                        ))
                    })?;

                (response.status, response.body)
            }
        };

        if !status.is_success() {
            let body = String::from_utf8_lossy(&body);

            return Err(HealthError::HttpError(format!(
                "{url}: HTTP {status} for switch {}: {body}",
                self.switch_id
            )));
        }

        serde_json::from_slice(&body).map_err(|e| {
            HealthError::HttpError(format!(
                "{url}: failed to parse response for switch {}: {e}",
                self.switch_id
            ))
        })
    }

    async fn do_get_nullable<T: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        extra_query: &[(&str, &str)],
    ) -> Result<OptionalNvueResponse<T>, HealthError> {
        // A report-backed NVUE endpoint can return HTTP 200 with body `null`.
        // Keep that distinct from a disabled path so downstream health reports
        // still show that the probe ran but the switch did not provide data.
        match self.do_get::<Option<T>>(url, extra_query).await? {
            Some(value) => Ok(OptionalNvueResponse::Present(value)),
            None => Ok(OptionalNvueResponse::Null),
        }
    }
}

// ---------------------------------------------------------------------------
// NVUE REST response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SystemHealthResponse {
    pub status: Option<String>,
    #[cfg(test)]
    #[serde(rename = "status-led")]
    pub status_led: Option<String>,
    #[cfg(test)]
    pub issues: Option<HashMap<String, IssueInfo>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize)]
pub struct IssueInfo {
    pub issue: Option<String>,
}

/// `/nvue_v1/system/reboot/reason` response.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RebootReasonResponse {
    /// Reason reported by NVUE for the last or pending reboot action.
    pub reason: Option<String>,

    /// NVUE generation time for the reboot reason.
    pub gentime: Option<String>,

    /// User associated with the reboot reason when NVUE provides one.
    pub user: Option<String>,
}

pub type ClusterAppsResponse = HashMap<String, ClusterApp>;

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterApp {
    pub status: Option<String>,
    #[cfg(test)]
    pub reason: Option<String>,
    // addition_info: Option<String>,   -- "addition-info" in JSON
    // app_id: Option<String>,          -- "app-id" in JSON
    // app_ver: Option<String>,         -- "app-ver" in JSON
    // capabilities: Option<String>,
    // components_ver: Option<String>,  -- "components-ver" in JSON
}

pub type SdnPartitionsResponse = HashMap<String, SdnPartition>;

fn deserialize_optional_u32_from_number_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U32OrString {
        Number(u32),
        String(String),
    }

    match Option::<U32OrString>::deserialize(deserializer)? {
        Some(U32OrString::Number(value)) => Ok(Some(value)),
        Some(U32OrString::String(value)) => value.parse::<u32>().map(Some).map_err(|error| {
            D::Error::custom(format!("invalid numeric string for num-gpus: {error}"))
        }),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SdnPartition {
    pub name: Option<String>,
    pub health: Option<String>,
    #[serde(
        default,
        rename = "num-gpus",
        deserialize_with = "deserialize_optional_u32_from_number_or_string"
    )]
    pub num_gpus: Option<u32>,
}

pub type FanEnvironmentResponse = HashMap<String, FanData>;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FanData {
    /// Fan maximum speed in RPM, scraped as string (e.g. "33000")
    #[serde(rename = "max-speed")]
    pub max_speed: Option<String>,
}

pub type TemperatureEnvironmentResponse = HashMap<String, TempData>;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TempData {
    /// Current temperature Celsius, scraped as string (e.g. "43.00").
    /// Field is optional per sensor
    pub current: Option<String>,
    /// Maximum (warning) threshold in Celsius as string (e.g. "105.00").
    pub max: Option<String>,
    /// Critical threshold in Celsius as a string (e.g. "120.00").
    pub crit: Option<String>,
    /// Sensor state as string (e.g. "ok").
    pub state: Option<String>,
}

/// `/nvue_v1/platform/environment/leakage` response keyed by leakage sensor
/// name.
///
/// NVUE may encode an individual sensor as JSON `null`; the collector maps that
/// sensor to `unknown` and reports it as a sensor failure.
pub type LeakageEnvironmentResponse = HashMap<String, Option<LeakageSensorData>>;

/// Leakage sensor entry inside `/nvue_v1/platform/environment/leakage`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LeakageSensorData {
    /// Leakage sensor state, expected as "ok" or "leak".
    pub state: Option<String>,
}

/// `/nvue_v1/platform/environment` summary. Keys are aggregate status
/// entries (e.g. `FAN_STATUS`) as well as the `fan`/`temperature` subtrees
pub type PlatformEnvironmentResponse = HashMap<String, EnvItem>;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EnvItem {
    /// Aggregate status string (e.g. "green"/"amber" for `FAN_STATUS`).
    pub state: Option<String>,
}

pub type InterfacesResponse = HashMap<String, InterfaceData>;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InterfaceData {
    #[cfg(test)]
    #[serde(rename = "type")]
    pub iface_type: Option<String>,
    #[serde(default)]
    pub link: InterfaceLink,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InterfaceLink {
    #[cfg(test)]
    pub speed: Option<String>,
    // state: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub diagnostics: HashMap<String, DiagnosticStatus>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiagnosticStatus {
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct LinkDiagnosticResult {
    pub interface: String,
    pub code: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_health() {
        let json = r#"{
            "status": "Not OK",
            "status-led": "amber",
            "issues": {
                "Containers": {"issue": "Not OK"},
                "PSU1": {"issue": "not OK"},
                "FAN2/1": {"issue": "out of range"},
                "PSU1/FAN": {"issue": "missing"},
                "Disk space log": {"issue": "not OK"}
            }
        }"#;

        let resp: SystemHealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("Not OK"));
        assert_eq!(resp.status_led.as_deref(), Some("amber"));
        let issues = resp.issues.unwrap();
        assert_eq!(issues.len(), 5);
        assert_eq!(issues["FAN2/1"].issue.as_deref(), Some("out of range"));
        assert_eq!(issues["PSU1/FAN"].issue.as_deref(), Some("missing"));
    }

    #[test]
    fn test_parse_system_health_ok() {
        let json = r#"{"issues": {}, "status": "OK", "status-led": "green"}"#;
        let resp: SystemHealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("OK"));
        assert_eq!(resp.status_led.as_deref(), Some("green"));
        assert!(resp.issues.unwrap().is_empty());
    }

    #[test]
    fn test_parse_reboot_reason() {
        let json = r#"{"reason":"reboot command","gentime":"2026-07-05 12:34:56","user":"admin"}"#;

        let resp: RebootReasonResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.reason.as_deref(), Some("reboot command"));
        assert_eq!(resp.gentime.as_deref(), Some("2026-07-05 12:34:56"));
        assert_eq!(resp.user.as_deref(), Some("admin"));
    }

    #[test]
    fn test_parse_cluster_apps() {
        let json = r#"{
            "nmx-controller": {
                "app-id": "nmx-c-nvos",
                "app-ver": "0.3",
                "components-ver": "sm:1.2.3, gfm:4.5.6, fib-fe:8.9.10",
                "capabilities": "sm, gfm, fib, gw-api",
                "addition-info": "Chassis mapping is missing",
                "status": "ok",
                "reason": ""
            },
            "nmx-telemetry": {
                "app-id": "nmx-telemetry",
                "app-ver": "0.3",
                "components-ver": "nmx-telemetry:0.3, nmx-connector:0.3",
                "capabilities": "ib-telemetry",
                "addition-info": "",
                "status": "not ok",
                "reason": "some reason here"
            }
        }"#;

        let resp: ClusterAppsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp["nmx-controller"].status.as_deref(), Some("ok"));
        assert_eq!(resp["nmx-telemetry"].status.as_deref(), Some("not ok"));
        assert_eq!(
            resp["nmx-telemetry"].reason.as_deref(),
            Some("some reason here")
        );
    }

    #[test]
    fn test_parse_sdn_partition() {
        let json = r#"{
            "name": "Partition1",
            "num-gpus": 8,
            "health": "healthy",
            "resiliency-mode": "full_bandwidth",
            "mcast-limit": 1024,
            "partition-type": "location_based"
        }"#;

        let resp: SdnPartition = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name.as_deref(), Some("Partition1"));
        assert_eq!(resp.health.as_deref(), Some("healthy"));
        assert_eq!(resp.num_gpus, Some(8));
    }

    #[test]
    fn test_parse_sdn_partition_string_num_gpus() {
        let json = r#"{
            "name": "Default Partition",
            "num-gpus": "8",
            "health": "unhealthy",
            "resiliency-mode": "adaptive_bandwidth",
            "mcast-limit": 1024,
            "partition-type": "gpuuid_based"
        }"#;

        let resp: SdnPartition = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name.as_deref(), Some("Default Partition"));
        assert_eq!(resp.health.as_deref(), Some("unhealthy"));
        assert_eq!(resp.num_gpus, Some(8));
    }

    #[test]
    fn test_parse_sdn_partitions_map() {
        let json = r#"{
            "1": {
                "name": "Partition1",
                "num-gpus": 8,
                "health": "healthy",
                "resiliency-mode": "full_bandwidth",
                "mcast-limit": 1024,
                "partition-type": "location_based"
            },
            "2": {
                "name": "Partition2",
                "num-gpus": 4,
                "health": "degraded",
                "resiliency-mode": "adaptive_bandwidth",
                "mcast-limit": 1024,
                "partition-type": "gpuuid_based"
            },
            "3": {
                "name": "Partition3",
                "num-gpus": 4,
                "health": "unhealthy",
                "resiliency-mode": "user_action_required",
                "mcast-limit": 1024,
                "partition-type": "gpuuid_based"
            }
        }"#;

        let resp: SdnPartitionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 3);
        assert_eq!(resp["1"].health.as_deref(), Some("healthy"));
        assert_eq!(resp["2"].health.as_deref(), Some("degraded"));
        assert_eq!(resp["3"].health.as_deref(), Some("unhealthy"));
        assert_eq!(resp["1"].num_gpus, Some(8));
        assert_eq!(resp["2"].num_gpus, Some(4));
    }

    #[test]
    fn test_parse_interfaces_with_diagnostics() {
        let json = r#"{
            "sw1p1s1": {
                "type": "nvl",
                "link": {
                    "diagnostics": {
                        "0": {"status": "No issue observed"}
                    }
                }
            },
            "sw1p1s2": {
                "type": "nvl",
                "link": {
                    "diagnostics": {
                        "1024": {"status": "Cable is unplugged"}
                    }
                }
            },
            "acp1": {
                "type": "nvl",
                "link": {
                    "diagnostics": {
                        "2": {"status": "Negotiation failure"}
                    }
                }
            }
        }"#;

        let resp: InterfacesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 3);

        assert_eq!(resp["sw1p1s1"].iface_type.as_deref(), Some("nvl"));
        assert_eq!(
            resp["sw1p1s1"].link.diagnostics["0"].status,
            "No issue observed"
        );
        assert_eq!(
            resp["sw1p1s2"].link.diagnostics["1024"].status,
            "Cable is unplugged"
        );
        assert_eq!(
            resp["acp1"].link.diagnostics["2"].status,
            "Negotiation failure"
        );
    }

    #[test]
    fn test_parse_interface_missing_link() {
        let json = r#"{
            "eth0": {"type": "ethernet"}
        }"#;

        let resp: InterfacesResponse = serde_json::from_str(json).unwrap();
        let eth0 = &resp["eth0"];
        assert_eq!(eth0.iface_type.as_deref(), Some("ethernet"));
        assert!(eth0.link.diagnostics.is_empty());
        assert!(eth0.link.speed.is_none());
    }

    #[test]
    fn test_parse_platform_environment_fan() {
        let json = r#"{
            "FAN1/1": {
                "current-speed": "10096",
                "direction": "F2B",
                "max-speed": "33000",
                "min-speed": "6000",
                "state": "ok"
            },
            "FAN1/2": {
                "current-speed": "9800",
                "direction": "F2B",
                "max-speed": "33000",
                "min-speed": "6000",
                "state": "ok"
            }
        }"#;

        let resp: FanEnvironmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp["FAN1/1"].max_speed.as_deref(), Some("33000"));
        assert_eq!(resp["FAN1/2"].max_speed.as_deref(), Some("33000"));
    }

    #[test]
    fn test_parse_platform_environment_fan_missing_max_speed() {
        let json = r#"{
            "FAN1/1": {
                "current-speed": "10096",
                "direction": "F2B",
                "min-speed": "6000",
                "state": "ok"
            }
        }"#;

        let resp: FanEnvironmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 1);
        assert!(resp["FAN1/1"].max_speed.is_none());
    }

    #[test]
    fn test_parse_platform_environment_temperature() {
        let json = r#"{
            "ASIC1": {"crit": "120.00", "current": "43.00", "max": "105.00", "state": "ok"},
            "Ambient-MNG-Temp": {"current": "27.00", "state": "ok"},
            "PDB-Conv-1-Temp": {"crit": "115.00", "current": "38.00", "state": "ok"}
        }"#;

        let resp: TemperatureEnvironmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 3);

        let asic1 = &resp["ASIC1"];
        assert_eq!(asic1.current.as_deref(), Some("43.00"));
        assert_eq!(asic1.max.as_deref(), Some("105.00"));
        assert_eq!(asic1.crit.as_deref(), Some("120.00"));
        assert_eq!(asic1.state.as_deref(), Some("ok"));

        // Ambient sensor reports only current + state.
        let ambient = &resp["Ambient-MNG-Temp"];
        assert_eq!(ambient.current.as_deref(), Some("27.00"));
        assert!(ambient.max.is_none());
        assert!(ambient.crit.is_none());
        assert_eq!(ambient.state.as_deref(), Some("ok"));

        // PDB sensor has crit + current + state but no max.
        let pdb = &resp["PDB-Conv-1-Temp"];
        assert_eq!(pdb.crit.as_deref(), Some("115.00"));
        assert!(pdb.max.is_none());
    }

    #[test]
    fn test_parse_platform_environment_leakage() {
        let json = r#"{"LEAK0":null,"LEAK1":{"state":"ok"},"LEAK2":{"state":"leak"}}"#;

        let resp: LeakageEnvironmentResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.len(), 3);
        assert!(resp["LEAK0"].is_none());

        assert_eq!(
            resp["LEAK1"]
                .as_ref()
                .and_then(|sensor| sensor.state.as_deref()),
            Some("ok")
        );

        assert_eq!(
            resp["LEAK2"]
                .as_ref()
                .and_then(|sensor| sensor.state.as_deref()),
            Some("leak")
        );
    }

    #[test]
    fn test_parse_platform_environment_fan_status() {
        // Parent summary carries the aggregate `FAN_STATUS` LED entry alongside
        // nested `fan`/`temperature` subtree objects of a different shape. The
        // LED entry parses into `state`; the nested objects parse with `state`
        // absent (serde ignores unknown keys) and are skipped by callers.
        let json = r#"{
            "FAN_STATUS": {"state": "green", "type": "led"},
            "PSU_STATUS": {"state": "amber", "type": "led"},
            "fan": {
                "FAN1/1": {"current-speed": "10096", "max-speed": "33000", "state": "ok"}
            },
            "temperature": {
                "ASIC1": {"current": "43.00", "state": "ok"}
            }
        }"#;

        let resp: PlatformEnvironmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp["FAN_STATUS"].state.as_deref(), Some("green"));
        assert_eq!(resp["PSU_STATUS"].state.as_deref(), Some("amber"));
        // nested subtree objects have no top-level state -> None.
        assert!(resp["fan"].state.is_none());
        assert!(resp["temperature"].state.is_none());
    }

    #[test]
    fn test_parse_empty_responses() {
        let empty_map: ClusterAppsResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_map.is_empty());

        let empty_partitions: SdnPartitionsResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_partitions.is_empty());

        let empty_interfaces: InterfacesResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_interfaces.is_empty());

        let empty_fans: FanEnvironmentResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_fans.is_empty());

        let empty_temps: TemperatureEnvironmentResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_temps.is_empty());

        let empty_leakage: LeakageEnvironmentResponse = serde_json::from_str("{}").unwrap();

        assert!(empty_leakage.is_empty());

        let empty_env: PlatformEnvironmentResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_env.is_empty());
    }
}
