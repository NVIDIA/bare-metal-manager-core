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
use forge_tls::client_config::ClientCert;
use forge_tls::default::{default_client_cert, default_client_key, default_root_ca};
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig, ForgeTlsClient};

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

    let client_config = ForgeClientConfig::new(
        default_root_ca().to_string(),
        Some(ClientCert {
            cert_path: default_client_cert().to_string(),
            key_path: default_client_key().to_string(),
        }),
    );

    let api_config = ApiConfig::new(carbide_api_url, &client_config);

    let mut client = ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|x| DhcpError::GenericError(x.to_string()))?;

    let request = tonic::Request::new(discovery_request);

    Ok(client.discover_dhcp(request).await?.into_inner())
}
