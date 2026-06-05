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
mod nmxc_api;
mod response;

// Generated gRPC types and client from nmx_c.proto
pub mod nmxc_model {
    #![allow(clippy::all, non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/nmx_c.rs"));
}

use std::path::PathBuf;
use std::time::Duration;

use http::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::debug;

use crate::nmxc_api::NmxcApi;
use crate::nmxc_model::nmx_controller_client::NmxControllerClient;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// `gateway_id` sent on NMX-C gRPC requests from Carbide and the `nmxc` test client.
pub const NMX_C_GATEWAY_ID: &str = "carbide";

#[derive(thiserror::Error, Debug)]
pub enum NmxcError {
    #[error("Invalid endpoint URL: {0}")]
    InvalidEndpoint(String),

    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC status: {0}")]
    Status(#[from] tonic::Status),

    #[error("Connection not initialized")]
    Uninitialized,

    #[error("NMX-C {operation} response missing server_header")]
    MissingServerHeader { operation: &'static str },

    #[error("NMX-C {operation} returned status code {return_code}")]
    NmxReturnCode {
        return_code: i32,
        operation: &'static str,
    },
}

impl NmxcError {
    /// Creates an error for invalid or missing response from the server.
    pub fn invalid_response(msg: impl Into<String>) -> Self {
        NmxcError::Status(tonic::Status::unknown(msg.into()))
    }

    /// NMX-C `server_header.return_code` when this error is [`NmxcError::NmxReturnCode`].
    pub fn nmx_return_code(&self) -> Option<i32> {
        match self {
            NmxcError::NmxReturnCode { return_code, .. } => Some(*return_code),
            _ => None,
        }
    }

    /// True when NMX-C returned `NMX_ST_RESOURCE_EXHAUSTED`.
    pub fn is_nmx_resource_exhausted(&self) -> bool {
        self.nmx_return_code() == Some(nmxc_model::StReturnCode::NmxStResourceExhausted as i32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Base URI for the NMX-C gRPC service (e.g. `https://host:50051` or `http://localhost:50051`).
    pub uri: Uri,
}

impl Endpoint {
    pub fn new(url: impl AsRef<str>) -> Result<Self, NmxcError> {
        let uri = url
            .as_ref()
            .parse::<Uri>()
            .map_err(|e| NmxcError::InvalidEndpoint(format!("{}: {e}", url.as_ref())))?;
        Ok(Self { uri })
    }
}

/// Optional TLS paths for HTTPS connections to NMX-C.
///
/// When both `client_cert_path` and `client_key_path` are set, the client presents a certificate
/// for mutual TLS. `ca_cert_path` adds an extra CA bundle for verifying the server (system roots
/// are still used unless configured otherwise by tonic).
///
/// `authority` sets the TLS server name (SNI / certificate verification hostname). If unset, the
/// host portion of the gRPC endpoint URL is used.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NmxcTlsConfig {
    pub ca_cert_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
    pub authority: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NmxcClientPoolBuilder {
    pub timeout: Duration,
    pub tls: Option<NmxcTlsConfig>,
}

impl Default for NmxcClientPoolBuilder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            tls: None,
        }
    }
}

impl NmxcClientPoolBuilder {
    pub fn build(self) -> Result<NmxcClientPool, NmxcError> {
        Ok(NmxcClientPool {
            timeout: self.timeout,
            tls: self.tls,
        })
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn tls(mut self, tls: NmxcTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

#[derive(Clone, Debug)]
pub struct NmxcClientPool {
    timeout: Duration,
    tls: Option<NmxcTlsConfig>,
}

impl NmxcClientPool {
    pub fn builder() -> NmxcClientPoolBuilder {
        NmxcClientPoolBuilder::default()
    }

    pub async fn create_client(&self, endpoint: Endpoint) -> Result<Box<dyn Nmxc>, NmxcError> {
        let channel = self.connect(&endpoint).await?;
        let client = NmxControllerClient::new(channel).max_decoding_message_size(usize::MAX);
        let nmxc = NmxcApi::new(client);
        Ok(Box::new(nmxc))
    }

    async fn build_https_tls_config(
        &self,
        uri: &Uri,
        t: &NmxcTlsConfig,
    ) -> Result<ClientTlsConfig, NmxcError> {
        let mut config = ClientTlsConfig::new();

        if let Some(ref path) = t.ca_cert_path {
            let pem = tokio::fs::read(path).await.map_err(|e| {
                NmxcError::InvalidEndpoint(format!(
                    "read NMX-C TLS CA cert {}: {e}",
                    path.display()
                ))
            })?;
            config = config.ca_certificate(Certificate::from_pem(pem));
        }

        match (&t.client_cert_path, &t.client_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let cert = tokio::fs::read(cert_path).await.map_err(|e| {
                    NmxcError::InvalidEndpoint(format!(
                        "read NMX-C TLS client cert {}: {e}",
                        cert_path.display()
                    ))
                })?;
                let key = tokio::fs::read(key_path).await.map_err(|e| {
                    NmxcError::InvalidEndpoint(format!(
                        "read NMX-C TLS client key {}: {e}",
                        key_path.display()
                    ))
                })?;
                config = config.identity(Identity::from_pem(cert, key));
            }
            (None, None) => {}
            _ => {
                return Err(NmxcError::InvalidEndpoint(
                    "NMX-C TLS client cert path and key path must both be set for mTLS".to_string(),
                ));
            }
        }

        let domain = t
            .authority
            .clone()
            .or_else(|| uri.host().map(|h| h.to_string()))
            .filter(|s| !s.is_empty());
        if let Some(d) = domain {
            config = config.domain_name(d);
        }

        Ok(config)
    }

    async fn connect(&self, endpoint: &Endpoint) -> Result<Channel, NmxcError> {
        let uri = &endpoint.uri;
        let scheme = uri.scheme_str().unwrap_or("http");
        let channel = if scheme.eq_ignore_ascii_case("https") {
            let endpoint_builder = tonic::transport::Endpoint::from_shared(uri.to_string())
                .map_err(|e| NmxcError::InvalidEndpoint(e.to_string()))?
                .connect_timeout(self.timeout);

            let tls_config = match &self.tls {
                Some(t) => self.build_https_tls_config(uri, t).await?,
                None => ClientTlsConfig::new(),
            };
            endpoint_builder
                .tls_config(tls_config)
                .map_err(|e| NmxcError::InvalidEndpoint(e.to_string()))?
                .connect()
                .await?
        } else {
            tonic::transport::Channel::from_shared(uri.to_string())
                .map_err(|e| NmxcError::InvalidEndpoint(e.to_string()))?
                .connect_timeout(self.timeout)
                .connect()
                .await?
        };

        debug!("Connected to NMX-C at {}", endpoint.uri);
        Ok(channel)
    }
}

/// Abstraction over [`NmxcClientPool`] and test doubles (e.g. `NmxcSimClient` in carbide-api).
#[async_trait::async_trait]
pub trait NmxcPool: Send + Sync + 'static {
    async fn create_client(&self, endpoint: Endpoint) -> Result<Box<dyn Nmxc>, NmxcError>;
}

#[async_trait::async_trait]
impl NmxcPool for NmxcClientPool {
    async fn create_client(&self, endpoint: Endpoint) -> Result<Box<dyn Nmxc>, NmxcError> {
        NmxcClientPool::create_client(self, endpoint).await
    }
}

#[async_trait::async_trait]
pub trait Nmxc: Send + Sync + 'static {
    /// Perform Hello handshake with the NMX-C controller.
    async fn hello(&mut self, gateway_id: &str) -> Result<nmxc_model::ServerHello, NmxcError>;

    async fn get_domain_properties(
        &mut self,
        context: Option<nmxc_model::Context>,
        gateway_id: &str,
    ) -> Result<nmxc_model::DomainProperties, NmxcError>;

    async fn get_domain_state_info(
        &mut self,
        context: Option<nmxc_model::Context>,
        gateway_id: &str,
    ) -> Result<nmxc_model::DomainStateInfo, NmxcError>;

    async fn get_topology_info(
        &mut self,
        context: Option<nmxc_model::Context>,
        gateway_id: &str,
    ) -> Result<nmxc_model::FmTopologyInfo, NmxcError>;

    async fn get_compute_node_count(
        &mut self,
        req: nmxc_model::GetComputeNodeCountRequest,
    ) -> Result<nmxc_model::GetComputeNodeCountResponse, NmxcError>;

    async fn get_compute_node_info_list(
        &mut self,
        req: nmxc_model::GetComputeNodeInfoListRequest,
    ) -> Result<nmxc_model::GetComputeNodeInfoListResponse, NmxcError>;

    async fn get_gpu_info_list(
        &mut self,
        req: nmxc_model::GetGpuInfoListRequest,
    ) -> Result<nmxc_model::GetGpuInfoListResponse, NmxcError>;

    async fn get_switch_node_count(
        &mut self,
        req: nmxc_model::GetSwitchNodeCountRequest,
    ) -> Result<nmxc_model::GetSwitchNodeCountResponse, NmxcError>;

    async fn get_switch_node_info_list(
        &mut self,
        req: nmxc_model::GetSwitchNodeInfoListRequest,
    ) -> Result<nmxc_model::GetSwitchNodeInfoListResponse, NmxcError>;

    async fn get_partition_count(
        &mut self,
        req: nmxc_model::GetPartitionCountRequest,
    ) -> Result<nmxc_model::GetPartitionCountResponse, NmxcError>;

    async fn get_partition_id_list(
        &mut self,
        req: nmxc_model::GetPartitionIdListRequest,
    ) -> Result<nmxc_model::GetPartitionIdListResponse, NmxcError>;

    async fn get_partition_info_list(
        &mut self,
        req: nmxc_model::GetPartitionInfoListRequest,
    ) -> Result<nmxc_model::GetPartitionInfoListResponse, NmxcError>;

    async fn create_partition(
        &mut self,
        req: nmxc_model::CreatePartitionRequest,
    ) -> Result<nmxc_model::CreatePartitionResponse, NmxcError>;

    async fn delete_partition(
        &mut self,
        req: nmxc_model::DeletePartitionRequest,
    ) -> Result<nmxc_model::DeletePartitionResponse, NmxcError>;

    async fn add_gpus_to_partition(
        &mut self,
        req: nmxc_model::UpdatePartitionRequest,
    ) -> Result<nmxc_model::UpdatePartitionResponse, NmxcError>;

    async fn remove_gpus_from_partition(
        &mut self,
        req: nmxc_model::UpdatePartitionRequest,
    ) -> Result<nmxc_model::UpdatePartitionResponse, NmxcError>;
}
