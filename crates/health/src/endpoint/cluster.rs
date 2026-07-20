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

use std::net::IpAddr;
use std::sync::Arc;

use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use nv_redfish::bmc_http::reqwest::Client as ReqwestClient;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::HealthError;
use crate::bmc::{BmcClient, FixedCredentialProvider};
use crate::config::ClusterEndpointSourceConfig;
use crate::endpoint::{BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, EndpointSource};

// ── Inventory file shape ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct FileInventory {
    default_credentials: FileCredentials,
    nodes: Vec<FileNode>,
}

#[derive(Deserialize)]
struct FileCredentials {
    username: String,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FileNode {
    hostname: String,
    bmc_ip: IpAddr,
    rack: String,
}

// ── Canonical internal node shape (both paths produce this) ──────────────────

struct ClusterNode {
    hostname: String,
    bmc_ip: IpAddr,
    rack: Option<String>,
    username: String,
    password: Option<String>,
}

// ── Cluster Manager JSON RPC ────────────────────────────────────────────────
//
// The cluster manager exposes a JSON RPC API at /json/ for inventory and credential queries.
// Two calls are made:
//
//   1. cmdevice.getDevices — inventory: one entry per PhysicalNode with hostname
//      and BMC interface IP.
//
//   2. cmpart.getPartition("<partition>") — credentials: the bmcsettings sub-object
//      holds the cluster-wide BMC username and password (stored by the cluster manager daemon).
//      Default partition is "base".
//
// Exact call names and response field paths need verification against the live
// head node:
//   GET  https://<head-node>:8081/api           — lists available services + calls
//   POST https://<head-node>:8081/json/          — JSON RPC endpoint
//
// When Joab confirms the real call names, update MANAGER_DEVICE_CALL and
// MANAGER_PARTITION_CALL below, and the field extractors.

const MANAGER_DEVICE_CALL: &str = "getDevices";
const MANAGER_PARTITION_CALL: &str = "getPartition";

fn build_http() -> Result<HttpClient, HealthError> {
    HttpClient::builder().build().map_err(|e| {
        HealthError::GenericError(format!("Cluster manager HTTP client build failed: {e}"))
    })
}

async fn manager_rpc(
    http: &HttpClient,
    json_rpc_url: &Url,
    service: &str,
    call: &str,
    arg: serde_json::Value,
) -> Result<serde_json::Value, HealthError> {
    let body = json!({ "service": service, "call": call, "arg": arg });

    tracing::debug!(service, call, url = %json_rpc_url, "cluster manager JSON RPC call");

    let response = http
        .post(json_rpc_url.as_str())
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            HealthError::GenericError(format!("cluster manager RPC {service}.{call} failed: {e}"))
        })?;

    if !response.status().is_success() {
        return Err(HealthError::GenericError(format!(
            "cluster manager RPC {service}.{call} returned HTTP {}",
            response.status()
        )));
    }

    response.json().await.map_err(|e| {
        HealthError::GenericError(format!(
            "cluster manager RPC {service}.{call} parse failed: {e}"
        ))
    })
}

async fn fetch_manager_credentials(
    http: &HttpClient,
    json_rpc_url: &Url,
    cfg: &ClusterEndpointSourceConfig,
) -> (String, Option<String>) {
    // cmsh equivalent: partition use <partition> → bmcsettings → get username / get password
    // Password stored by the cluster manager daemon at partition level.
    let result = manager_rpc(
        http,
        json_rpc_url,
        "cmpart",
        MANAGER_PARTITION_CALL,
        json!(cfg.cluster_manager_partition),
    )
    .await;

    let raw = match result {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                partition = %cfg.cluster_manager_partition,
                "Failed to fetch cluster manager partition credentials; using config fallback"
            );
            return (cfg.default_username.clone(), cfg.default_password.clone());
        }
    };

    tracing::debug!("Raw cluster manager partition response received");

    // Navigate to bmcsettings — try likely paths.
    // Update once live /api confirms the exact field layout.
    let bmc_settings = raw
        .pointer("/bmcSettings")
        .or_else(|| raw.pointer("/result/bmcSettings"))
        .or_else(|| raw.pointer("/data/bmcSettings"));

    let username = bmc_settings
        .and_then(|s| s.get("username").or_else(|| s.get("userName")))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            tracing::debug!(
                "Cluster manager partition response missing bmcSettings.username; using config fallback. \
                 Probe /api on head node to find correct field path."
            );
            cfg.default_username.clone()
        });

    let password = bmc_settings
        .and_then(|s| s.get("password").or_else(|| s.get("bmcPassword")))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            tracing::debug!(
                "Cluster manager partition response missing bmcSettings.password; using config fallback."
            );
            cfg.default_password.clone()
        });

    (username, password)
}

fn extract_manager_devices(
    raw: &serde_json::Value,
    username: String,
    password: Option<String>,
) -> Result<Vec<ClusterNode>, HealthError> {
    // The device list may be a top-level array or wrapped in result/data/items.
    // Update once live /api confirms the exact response shape.
    let items: Vec<&serde_json::Value> = if let Some(arr) = raw.as_array() {
        arr.iter().collect()
    } else {
        match ["result", "data", "items", "devices"]
            .iter()
            .find_map(|key| raw.get(key).and_then(|v| v.as_array()))
        {
            Some(arr) => arr.iter().collect(),
            None => {
                return Err(HealthError::GenericError(
                    "Cluster manager getDevices response has no recognized shape; \
                     probe /api on head node and update extract_manager_devices in cluster.rs"
                        .to_string(),
                ));
            }
        }
    };

    let item_count = items.len();
    let mut nodes = Vec::new();
    for item in items {
        let hostname = item
            .get("hostname")
            .or_else(|| item.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // BMC IP lives in the BMC interface, not at the top level of the device.
        // cmsh: device → interfaces → use ipmi0/ilo0/rf0 → get ip
        // Try common field paths; update once confirmed.
        let bmc_ip_str = item
            .pointer("/interfaces/ipmi0/ip")
            .or_else(|| item.pointer("/interfaces/bmc/ip"))
            .or_else(|| item.pointer("/interfaces/ilo0/ip"))
            .or_else(|| item.pointer("/interfaces/rf0/ip"))
            .or_else(|| item.get("bmcAddress"))
            .or_else(|| item.get("bmcIp"))
            .or_else(|| item.get("ipmiAddress"))
            .and_then(|v| v.as_str());

        // Cluster manager category maps to our rack identifier.
        let rack = item
            .get("category")
            .or_else(|| item.get("partition"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let (Some(hostname), Some(bmc_ip_str)) = (hostname, bmc_ip_str) else {
            tracing::debug!(
                item_keys = ?item.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
                "Cluster manager device entry missing hostname or BMC IP; skipping. \
                 Update field paths in extract_manager_devices once head node is probed."
            );
            continue;
        };

        let bmc_ip: IpAddr = match bmc_ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                tracing::warn!(
                    hostname,
                    bmc_ip_address = bmc_ip_str,
                    error = %e,
                    "Invalid BMC IP; skipping"
                );
                continue;
            }
        };

        nodes.push(ClusterNode {
            hostname,
            bmc_ip,
            rack,
            username: username.clone(),
            password: password.clone(),
        });
    }

    if nodes.is_empty() && item_count > 0 {
        return Err(HealthError::GenericError(
            "Cluster manager getDevices returned entries but none had a recognized hostname or BMC IP; \
             probe /api on head node and update extract_manager_devices in cluster.rs"
                .to_string(),
        ));
    }

    Ok(nodes)
}

// ── Source implementations ────────────────────────────────────────────────────

pub struct ClusterEndpointSource {
    cfg: ClusterEndpointSourceConfig,
    reqwest: ReqwestClient,
    proxy_url: Option<Url>,
    cache_size: usize,
}

impl ClusterEndpointSource {
    pub fn from_config(
        cfg: ClusterEndpointSourceConfig,
        reqwest: &ReqwestClient,
        proxy_url: Option<&Url>,
        cache_size: usize,
    ) -> Self {
        Self {
            cfg,
            reqwest: reqwest.clone(),
            proxy_url: proxy_url.cloned(),
            cache_size,
        }
    }

    async fn load_endpoints(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
        let nodes = if let Some(ref cluster_manager_url) = self.cfg.cluster_manager_url {
            fetch_from_manager(&self.cfg, cluster_manager_url).await?
        } else {
            read_from_file(&self.cfg)?
        };
        let endpoints = build_endpoints(
            nodes,
            self.cfg.port,
            &self.reqwest,
            self.proxy_url.as_ref(),
            self.cache_size,
        );
        tracing::info!(endpoint_count = endpoints.len(), "Loaded cluster endpoints");
        Ok(endpoints)
    }
}

async fn fetch_from_manager(
    cfg: &ClusterEndpointSourceConfig,
    cluster_manager_url: &Url,
) -> Result<Vec<ClusterNode>, HealthError> {
    let http = build_http()?;
    let json_rpc_url = cluster_manager_url
        .join("/json/")
        .map_err(|e| HealthError::GenericError(format!("Invalid cluster manager URL: {e}")))?;

    tracing::info!(url = %json_rpc_url, partition = %cfg.cluster_manager_partition, "Fetching cluster inventory from cluster manager");

    // Call 1: partition-level BMC credentials
    let (username, password) = fetch_manager_credentials(&http, &json_rpc_url, cfg).await;

    // Call 2: device inventory
    let raw = manager_rpc(
        &http,
        &json_rpc_url,
        "cmdevice",
        MANAGER_DEVICE_CALL,
        json!({"type": "PhysicalNode"}),
    )
    .await?;

    tracing::debug!(
        response_keys = ?raw.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
        response_is_array = raw.is_array(),
        "Raw cluster manager device response received"
    );

    let nodes = extract_manager_devices(&raw, username, password)?;
    tracing::info!(
        loaded_node_count = nodes.len(),
        "Cluster manager device fetch complete"
    );
    Ok(nodes)
}

fn read_from_file(cfg: &ClusterEndpointSourceConfig) -> Result<Vec<ClusterNode>, HealthError> {
    let contents = std::fs::read_to_string(&cfg.inventory_path).map_err(|e| {
        HealthError::GenericError(format!(
            "Failed to read cluster inventory {}: {e}",
            cfg.inventory_path.display()
        ))
    })?;
    let inventory: FileInventory = serde_json::from_str(&contents)?;
    let username = inventory.default_credentials.username;
    let password = inventory.default_credentials.password;
    Ok(inventory
        .nodes
        .into_iter()
        .map(|n| ClusterNode {
            hostname: n.hostname,
            bmc_ip: n.bmc_ip,
            rack: Some(n.rack).filter(|s| !s.is_empty()),
            username: username.clone(),
            password: password.clone(),
        })
        .collect())
}

fn build_endpoints(
    nodes: Vec<ClusterNode>,
    port: Option<u16>,
    reqwest: &ReqwestClient,
    proxy_url: Option<&Url>,
    cache_size: usize,
) -> Vec<Arc<BmcEndpoint>> {
    let mut endpoints = Vec::with_capacity(nodes.len());
    for node in nodes {
        let IpAddr::V4(v4) = node.bmc_ip else {
            tracing::warn!(
                hostname = %node.hostname,
                bmc_ip_address = %node.bmc_ip,
                "cluster endpoint has non-IPv4 BMC address; skipping"
            );
            continue;
        };

        // Deterministic locally-administered MAC: 02:00:<o1>:<o2>:<o3>:<o4>.
        // MAC is an internal cache key only; connectivity is IP-based.
        let [o1, o2, o3, o4] = v4.octets();
        let mac = MacAddress::new([0x02, 0x00, o1, o2, o3, o4]);

        let addr = BmcAddr {
            ip: node.bmc_ip,
            port,
            mac,
        };
        let credentials = BmcCredentials::UsernamePassword {
            username: node.username,
            password: node.password,
        };
        let provider = Arc::new(FixedCredentialProvider::new(credentials));
        let bmc = match BmcClient::new(
            reqwest.clone(),
            addr.clone(),
            provider,
            proxy_url.cloned(),
            cache_size,
        ) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    hostname = %node.hostname,
                    "Failed to construct BmcClient for cluster endpoint; skipping"
                );
                continue;
            }
        };
        endpoints.push(Arc::new(BmcEndpoint {
            addr,
            metadata: None,
            rack_id: node.rack.as_deref().map(RackId::new),
            bmc,
        }));
    }
    endpoints
}

impl EndpointSource for ClusterEndpointSource {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
        Box::pin(self.load_endpoints())
    }
}
