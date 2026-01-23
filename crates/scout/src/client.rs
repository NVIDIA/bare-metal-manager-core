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

use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use forge_tls::client_config::ClientCert;
pub use scout::{CarbideClientError, CarbideClientResult};

use crate::Options;

pub(crate) async fn create_forge_client(
    config: &Options,
) -> CarbideClientResult<forge_tls_client::ForgeClientT> {
    let client_config = ForgeClientConfig::new(
        config.root_ca.clone(),
        Some(ClientCert {
            cert_path: config.client_cert.clone(),
            key_path: config.client_key.clone(),
        }),
    );
    let api_config = ApiConfig::new(&config.api, &client_config);

    let client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|err| CarbideClientError::TransportError(err.to_string()))?;
    Ok(client)
}
