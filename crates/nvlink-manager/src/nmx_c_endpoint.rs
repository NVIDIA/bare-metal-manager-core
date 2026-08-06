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

use crate::config::NvLinkConfig;

/// Whether an NMX-C monitor group is keyed by chassis serial or rack id.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ManagedHostGroupType {
    Chassis,
    Rack,
}

impl ManagedHostGroupType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chassis => "chassis",
            Self::Rack => "rack",
        }
    }
}

impl std::fmt::Display for ManagedHostGroupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default NMX-C gRPC port when switch NVOS info does not specify one.
pub const NMX_C_DEFAULT_GRPC_PORT: u16 = 9370;

fn nmx_c_endpoint_uses_tls(config: &NvLinkConfig) -> bool {
    config.nmx_c_tls_client_cert_path.is_some() && config.nmx_c_tls_client_key_path.is_some()
}

fn nmx_c_endpoint_scheme(config: &NvLinkConfig) -> &'static str {
    if config.allow_insecure && !nmx_c_endpoint_uses_tls(config) {
        "http"
    } else {
        "https"
    }
}

/// Builds an NMX-C gRPC URL from a switch NVOS IP (same data as RPC `SwitchNvosInfo`).
pub fn nmx_c_endpoint_url_from_nvos_ip(
    ip: &IpAddr,
    port: Option<u16>,
    config: &NvLinkConfig,
) -> String {
    format!(
        "{}://{}:{}",
        nmx_c_endpoint_scheme(config),
        ip,
        port.or(config.nmx_c_endpoint_port)
            .unwrap_or(NMX_C_DEFAULT_GRPC_PORT)
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn endpoint_url_uses_http_when_allow_insecure() {
        let config = NvLinkConfig {
            allow_insecure: true,
            ..Default::default()
        };
        assert_eq!(
            nmx_c_endpoint_url_from_nvos_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, &config),
            "http://10.0.0.1:9370"
        );
    }

    #[test]
    fn endpoint_url_uses_https_by_default() {
        let config = NvLinkConfig::default();
        assert_eq!(
            nmx_c_endpoint_url_from_nvos_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, &config),
            "https://10.0.0.1:9370"
        );
    }

    #[test]
    fn endpoint_url_uses_configured_port() {
        let config = NvLinkConfig {
            nmx_c_endpoint_port: Some(9601),
            ..Default::default()
        };
        assert_eq!(
            nmx_c_endpoint_url_from_nvos_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, &config),
            "https://10.0.0.1:9601"
        );
    }
}
