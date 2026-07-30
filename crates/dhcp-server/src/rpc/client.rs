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
use std::collections::HashSet;

use rpc::forge::{DhcpDiscovery, DhcpRecord, GetSuppressedDhcpMacsRequest, RecordDhcpDiscoverSuppressedRequest};
use rpc::forge_tls_client::{ApiConfig, ForgeTlsClient};

use crate::Config;
use crate::errors::DhcpError;

pub async fn discover_dhcp(
    discovery_request: DhcpDiscovery,
    config: &Config,
) -> Result<DhcpRecord, DhcpError> {
    let Some(carbide_api_url) = &config.dhcp_config.carbide_api_url else {
        return Err(DhcpError::MissingArgument(
            "carbide_api_url in DhcpConfig".to_string(),
        ));
    };

    let api_config = ApiConfig::new(carbide_api_url, &config.forge_client_config);

    let mut client = ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|x| DhcpError::GenericError(x.to_string()))?;

    let request = tonic::Request::new(discovery_request);

    Ok(client.discover_dhcp(request).await?.into_inner())
}

/// Load the set of BMC MAC addresses that have `suppress_dhcp = true`.
/// Called on server startup and on `InvalidateDhcpCache` to rebuild the
/// in-memory suppression set.
pub async fn get_suppressed_dhcp_macs(config: &Config) -> Result<HashSet<String>, DhcpError> {
    let Some(carbide_api_url) = &config.dhcp_config.carbide_api_url else {
        return Ok(HashSet::new());
    };

    let api_config = ApiConfig::new(carbide_api_url, &config.forge_client_config);
    let mut client = ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|e| DhcpError::GenericError(e.to_string()))?;

    let response = client
        .get_suppressed_dhcp_macs(tonic::Request::new(GetSuppressedDhcpMacsRequest {}))
        .await?
        .into_inner();

    Ok(response.bmc_mac_addresses.into_iter().collect())
}

/// Notify the Core API that a DHCPDISCOVER from `mac` was suppressed.
/// The Core API writes `dhcp_discover_suppressed_at` in `ignored_bmc_macs`.
/// This is fire-and-forget: errors are logged but do not affect packet handling.
pub async fn record_dhcp_discover_suppressed(
    mac: &str,
    config: &Config,
) -> Result<(), DhcpError> {
    let Some(carbide_api_url) = &config.dhcp_config.carbide_api_url else {
        return Ok(());
    };

    let api_config = ApiConfig::new(carbide_api_url, &config.forge_client_config);
    let mut client = ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|e| DhcpError::GenericError(e.to_string()))?;

    client
        .record_dhcp_discover_suppressed(tonic::Request::new(
            RecordDhcpDiscoverSuppressedRequest {
                bmc_mac_address: mac.to_string(),
            },
        ))
        .await?;

    Ok(())
}
