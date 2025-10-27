/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_client_ip::ClientIp;
use forge_tls::client_config::ClientCert;
use rpc::forge::CloudInitInstructionsRequest;
use rpc::forge_tls_client;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};

use crate::common::{AppState, Machine};
use crate::rpc_error::PxeRequestError;

impl FromRequestParts<AppState> for Machine {
    type Rejection = PxeRequestError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let client_config = ForgeClientConfig::new(
            state.runtime_config.forge_root_ca_path.clone(),
            Some(ClientCert {
                cert_path: state.runtime_config.server_cert_path.clone(),
                key_path: state.runtime_config.server_key_path.clone(),
            }),
        );
        let api_config = ApiConfig::new(&state.runtime_config.internal_api_url, &client_config);

        let mut client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
            .await
            .map_err(|err| {
                eprintln!(
                    "error connecting to forge api from pxe - {:?} - url: {:?}",
                    err, state.runtime_config.internal_api_url
                );
                PxeRequestError::MissingClientConfig
            })?;

        // the implementation defaults to a proxied XFF header with the correct IP,
        // and falls back to client IP from socket if not
        let client_ip = ClientIp::from_request_parts(parts, state)
            .await
            .map_err(PxeRequestError::MissingIp)?
            .0;

        client
            .get_cloud_init_instructions(tonic::Request::new(CloudInitInstructionsRequest {
                ip: client_ip.to_string(),
            }))
            .await
            .map(|response| Machine {
                instructions: response.into_inner(),
            })
            .map_err(PxeRequestError::CarbideApiError)
    }
}
