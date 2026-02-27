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
        let base_url =
            Url::parse(&format!("https://{host}")).map_err(|e| HealthError::HttpError {
                protocol: "HTTPS",
                message: format!("https://{host}: invalid base URL: {e}"),
            })?;

        let mut builder = Client::builder()
            .timeout(request_timeout)
            .connect_timeout(Duration::from_secs(10));

        if self_signed_tls {
            // ! dangerously accept the self-signed certificate.
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().map_err(|e| HealthError::HttpError {
            protocol: "HTTPS",
            message: format!("{base_url}: failed to create HTTP client: {e}"),
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

    pub async fn get_partition_detail(
        &self,
        partition_id: &str,
    ) -> Result<Option<SdnPartition>, HealthError> {
        if !self.paths.sdn_partitions_enabled {
            return Ok(None);
        }
        let url = self.join_path(&format!("{NVUE_SDN_PARTITIONS}/{partition_id}"))?;
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
        self.base_url
            .join(path)
            .map_err(|e| HealthError::HttpError {
                protocol: "HTTPS",
                message: format!("{}: failed to join path {path}: {e}", self.base_url),
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

        let response = request.send().await.map_err(|e| HealthError::HttpError {
            protocol: "HTTPS",
            message: format!("{url}: request failed for switch {}: {e}", self.switch_id),
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(HealthError::HttpError {
                protocol: "HTTPS",
                message: format!("{url}: HTTP {status} for switch {}: {body}", self.switch_id),
            });
        }

        response.json().await.map_err(|e| HealthError::HttpError {
            protocol: "HTTPS",
            message: format!(
                "{url}: failed to parse response for switch {}: {e}",
                self.switch_id
            ),
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
    pub severity: Option<String>,
    pub message: Option<String>,
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
    pub state: Option<String>,
    pub gpu: Option<HashMap<String, GpuInfo>>,
    pub health: Option<String>,
    #[serde(rename = "health-led")]
    pub health_led: Option<String>,
    pub issues: Option<HashMap<String, IssueInfo>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GpuInfo {
    pub guid: Option<String>,
    #[serde(rename = "pcie-addr")]
    pub pcie_addr: Option<String>,
    pub state: Option<String>,
    pub nvlink: Option<HashMap<String, NvLinkInfo>>,
    pub interface: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvLinkInfo {
    #[serde(rename = "remote-gpu")]
    pub remote_gpu: Option<String>,
    #[serde(rename = "remote-link")]
    pub remote_link: Option<String>,
    pub state: Option<String>,
    pub interface: Option<String>,
    #[serde(rename = "switch-id")]
    pub switch_id: Option<String>,
    #[serde(rename = "switch-port")]
    pub switch_port: Option<String>,
    #[serde(rename = "switch-lid")]
    pub switch_lid: Option<String>,
    #[serde(rename = "switch-guid")]
    pub switch_guid: Option<String>,
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
            "status": "healthy",
            "status-led": "green",
            "issues": {
                "1": {"severity": "warning", "message": "high temperature"}
            }
        }"#;

        let resp: SystemHealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("healthy"));
        assert_eq!(resp.status_led.as_deref(), Some("green"));
        let issues = resp.issues.unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues["1"].message.as_deref(), Some("high temperature"));
    }

    #[test]
    fn test_parse_system_health_minimal() {
        let json = r#"{"status": "unhealthy"}"#;
        let resp: SystemHealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("unhealthy"));
        assert!(resp.status_led.is_none());
        assert!(resp.issues.is_none());
    }

    #[test]
    fn test_parse_cluster_apps() {
        let json = r#"{
            "nmx-m": {
                "status": "running",
                "reason": null,
                "addition-info": null,
                "app-id": "nmx-m",
                "app-ver": "1.2.3",
                "capabilities": "telemetry",
                "components-ver": "1.2.3"
            },
            "nmx-t": {
                "status": "running",
                "reason": null,
                "addition-info": null,
                "app-id": "nmx-t",
                "app-ver": "2.0.0",
                "capabilities": null,
                "components-ver": null
            }
        }"#;

        let resp: ClusterAppsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp["nmx-m"].status.as_deref(), Some("running"));
        assert_eq!(resp["nmx-t"].app_ver.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn test_parse_sdn_partition() {
        let json = r#"{
            "name": "partition-1",
            "state": "active",
            "health": "healthy",
            "health-led": "green",
            "gpu": {
                "gpu-0": {
                    "guid": "0xabc",
                    "pcie-addr": "0000:07:00.0",
                    "state": "active",
                    "nvlink": {
                        "link-0": {
                            "remote-gpu": "gpu-1",
                            "remote-link": "link-0",
                            "state": "up",
                            "interface": "nvl0",
                            "switch-id": "switch-0",
                            "switch-port": "port-1",
                            "switch-lid": "10",
                            "switch-guid": "0xdef"
                        }
                    },
                    "interface": {}
                }
            },
            "issues": {}
        }"#;

        let resp: SdnPartition = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name.as_deref(), Some("partition-1"));
        assert_eq!(resp.state.as_deref(), Some("active"));
        assert_eq!(resp.health.as_deref(), Some("healthy"));

        let gpus = resp.gpu.unwrap();
        assert_eq!(gpus.len(), 1);
        let gpu = &gpus["gpu-0"];
        assert_eq!(gpu.pcie_addr.as_deref(), Some("0000:07:00.0"));

        let nvlinks = gpu.nvlink.as_ref().unwrap();
        assert_eq!(nvlinks["link-0"].state.as_deref(), Some("up"));
        assert_eq!(nvlinks["link-0"].remote_gpu.as_deref(), Some("gpu-1"));
    }

    #[test]
    fn test_parse_sdn_partitions_map() {
        let json = r#"{
            "part-1": {"name": "partition-1", "state": "active"},
            "part-2": {"name": "partition-2", "state": "inactive"}
        }"#;

        let resp: SdnPartitionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp["part-1"].state.as_deref(), Some("active"));
        assert_eq!(resp["part-2"].state.as_deref(), Some("inactive"));
    }

    #[test]
    fn test_parse_interfaces_with_diagnostics() {
        let json = r#"{
            "nvl0": {
                "type": "nvlink",
                "link": {
                    "speed": "400G",
                    "state": {"up": {}},
                    "diagnostics": {
                        "0": {"status": "ok"},
                        "1": {"status": "warning"}
                    }
                }
            },
            "nvl1": {
                "type": "nvlink",
                "link": {
                    "speed": "400G",
                    "diagnostics": {}
                }
            }
        }"#;

        let resp: InterfacesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.len(), 2);

        let nvl0 = &resp["nvl0"];
        assert_eq!(nvl0.iface_type.as_deref(), Some("nvlink"));
        assert_eq!(nvl0.link.speed.as_deref(), Some("400G"));
        assert_eq!(nvl0.link.diagnostics.len(), 2);
        assert_eq!(nvl0.link.diagnostics["0"].status, "ok");
        assert_eq!(nvl0.link.diagnostics["1"].status, "warning");

        let nvl1 = &resp["nvl1"];
        assert!(nvl1.link.diagnostics.is_empty());
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
