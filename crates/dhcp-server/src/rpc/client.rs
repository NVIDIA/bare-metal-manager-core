/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
