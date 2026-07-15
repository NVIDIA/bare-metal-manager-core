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

use std::net::SocketAddr;

use super::grpcurl::grpcurl_id;

pub async fn create(carbide_api_addrs: &[SocketAddr], tenant_org_id: &str) -> eyre::Result<String> {
    tracing::info!("Creating VPC");

    // Default VPC type is ETV. ETV rejects `routing_profile_type` at the
    // API gate (it's FNN-only -- see `model::vpc::capability`), so this
    // fixture intentionally omits the field. The FNN-specific fixture
    // (`create_fnn`) sets it.
    let data = serde_json::json!({
        "metadata": { "name": "tenant_vpc" },
        "tenantOrganizationId": tenant_org_id,
    });
    let vpc_id = grpcurl_id(carbide_api_addrs, "CreateVpc", &data.to_string()).await?;
    tracing::info!(
        vpc_id = %vpc_id,
        "VPC created",
    );
    Ok(vpc_id)
}

pub async fn create_fnn(
    carbide_api_addrs: &[SocketAddr],
    tenant_org_id: &str,
) -> eyre::Result<String> {
    tracing::info!("Creating FNN VPC");

    let data = serde_json::json!({
        "metadata": { "name": "tenant_vpc_fnn" },
        "tenantOrganizationId": tenant_org_id,
        "routing_profile_type": "EXTERNAL".to_string(),
        "network_virtualization_type": 5, // FNN
    });
    let vpc_id = grpcurl_id(carbide_api_addrs, "CreateVpc", &data.to_string()).await?;
    tracing::info!(
        vpc_id = %vpc_id,
        "FNN VPC created",
    );
    Ok(vpc_id)
}

pub async fn create_flat(
    carbide_api_addrs: &[SocketAddr],
    tenant_org_id: &str,
) -> eyre::Result<String> {
    tracing::info!("Creating Flat VPC");

    // Flat VPCs reject `routing_profile_type` -- there's no NICo-managed
    // data plane to apply a routing profile to.
    let data = serde_json::json!({
        "metadata": { "name": "tenant_vpc_flat" },
        "tenantOrganizationId": tenant_org_id,
        "network_virtualization_type": 6, // FLAT
    });
    let vpc_id = grpcurl_id(carbide_api_addrs, "CreateVpc", &data.to_string()).await?;
    tracing::info!(
        vpc_id = %vpc_id,
        "Flat VPC created",
    );
    Ok(vpc_id)
}
