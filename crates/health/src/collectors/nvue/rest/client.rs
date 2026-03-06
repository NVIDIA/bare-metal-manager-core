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
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::HealthError;
use crate::config::NvueRestPaths;

const NVUE_SYSTEM_HEALTH: &str = "/nvue_v1/system/health";
const NVUE_CLUSTER_APPS: &str = "/nvue_v1/cluster/apps";
const NVUE_SDN_PARTITIONS: &str = "/nvue_v1/sdn/partition";
const NVUE_INTERFACES: &str = "/nvue_v1/interface";

/// Client for NVUE REST API on NVUE-managed switches.
pub struct RestClient {
    pub(crate) switch_id: String,
    base_url: Url,
    username: Option<String>,
    password: Option<String>,
    paths: NvueRestPaths,
    client: Client,
}

impl RestClient {
    pub fn new(
        switch_id: String,
        host: &str,
        username: Option<String>,
        password: Option<String>,
        request_timeout: Duration,
        self_signed_tls: bool,
        paths: NvueRestPaths,
    ) -> Result<Self, HealthError> {
        let base_url = Url::parse(&format!("https://{host}")).map_err(|e| {
            HealthError::HttpError(format!("https://{host}: invalid base URL: {e}"))
        })?;

        let mut builder = Client::builder().timeout(request_timeout);

        if self_signed_tls {
            // ! dangerously accept the self-signed certificate.
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().map_err(|e| {
            HealthError::HttpError(format!("{base_url}: failed to create HTTP client: {e}"))
        })?;

        Ok(Self {
            switch_id,
            base_url,
            username,
            password,
            paths,
            client,
        })
    }

    pub async fn get_system_health(&self) -> Result<Option<SystemHealthResponse>, HealthError> {
        if !self.paths.system_health_enabled {
            return Ok(None);
        }
        let url = self.join_path(NVUE_SYSTEM_HEALTH)?;
        self.do_get(url, &[]).await.map(Some)
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
        let mut request = self.client.get(url.as_str());

        // GET /interface (returning a collection) defaults to rev=applied, not operational.
        // There is inconsistency across the NVUE Endpoints, so we need to check each.
        // We want the actual system state (rev=operational), rather than defaults or what's configured (rev=applied).
        request = request.query(&[("rev", "operational")]);
        if !extra_query.is_empty() {
            request = request.query(extra_query);
        }

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            request = request.basic_auth(user, Some(pass));
        }

        request = request.header("Accept", "application/json");

        let response = request.send().await.map_err(|e| {
            HealthError::HttpError(format!(
                "{url}: request failed for switch {}: {e}",
                self.switch_id
            ))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(HealthError::HttpError(format!(
                "{url}: HTTP {status} for switch {}: {body}",
                self.switch_id
            )));
        }

        response.json().await.map_err(|e| {
            HealthError::HttpError(format!(
                "{url}: failed to parse response for switch {}: {e}",
                self.switch_id
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// NVUE REST response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemHealthResponse {
    pub status: Option<String>,
    #[serde(rename = "status-led")]
    pub status_led: Option<String>,
    pub issues: Option<HashMap<String, IssueInfo>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssueInfo {
    pub issue: Option<String>,
}

pub type ClusterAppsResponse = HashMap<String, ClusterApp>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterApp {
    pub status: Option<String>,
    pub reason: Option<String>,
    #[serde(rename = "addition-info")]
    pub addition_info: Option<String>,
    #[serde(rename = "app-id")]
    pub app_id: Option<String>,
    #[serde(rename = "app-ver")]
    pub app_ver: Option<String>,
    pub capabilities: Option<String>,
    #[serde(rename = "components-ver")]
    pub components_ver: Option<String>,
}

pub type SdnPartitionsResponse = HashMap<String, SdnPartition>;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SdnPartition {
    pub name: Option<String>,
    pub health: Option<String>,
    #[serde(rename = "num-gpus")]
    pub num_gpus: Option<u32>,
}

pub type InterfacesResponse = HashMap<String, InterfaceData>;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct InterfaceData {
    #[serde(rename = "type")]
    pub iface_type: Option<String>,
    #[serde(default)]
    pub link: InterfaceLink,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct InterfaceLink {
    pub speed: Option<String>,
    pub state: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub diagnostics: HashMap<String, DiagnosticStatus>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    fn test_parse_empty_responses() {
        let empty_map: ClusterAppsResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_map.is_empty());

        let empty_partitions: SdnPartitionsResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_partitions.is_empty());

        let empty_interfaces: InterfacesResponse = serde_json::from_str("{}").unwrap();
        assert!(empty_interfaces.is_empty());
    }
}
