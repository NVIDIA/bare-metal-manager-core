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

use crate::Options;
use ::rpc::forge_tls_client::{self, ForgeClientCert, ForgeTlsConfig};
pub use scout::{CarbideClientError, CarbideClientResult};

pub(crate) async fn create_forge_client(
    config: &Options,
) -> CarbideClientResult<forge_tls_client::ForgeClientT> {
    let forge_tls_config = ForgeTlsConfig {
        root_ca_path: config.root_ca.clone(),
        client_cert: Some(ForgeClientCert {
            cert_path: config.client_cert.clone(),
            key_path: config.client_key.clone(),
        }),
    };
    let client = forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(&config.api)
        .await
        .map_err(|err| CarbideClientError::TransportError(err.to_string()))?;
    Ok(client)
}
