/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig, ForgeClientT, ForgeTlsClient};

// Forge Communication
pub async fn create_forge_client(
    forge_api: &str,
    client_config: &ForgeClientConfig,
) -> Result<ForgeClientT, eyre::Error> {
    match ForgeTlsClient::retry_build(&ApiConfig::new(forge_api, client_config)).await {
        Ok(client) => Ok(client),
        Err(err) => Err(eyre::eyre!(
            "Could not connect to Forge API server at {}: {err}",
            forge_api
        )),
    }
}
