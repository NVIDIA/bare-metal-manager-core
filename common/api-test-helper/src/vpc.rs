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

use std::net::SocketAddr;

use super::grpcurl::grpcurl_id;

pub async fn create(carbide_api_addrs: &[SocketAddr]) -> eyre::Result<String> {
    tracing::info!("Creating VPC");

    let data = serde_json::json!({
        "name": "tenant_vpc",
        "tenantOrganizationId": "tenant_organization1"
    });
    let vpc_id = grpcurl_id(carbide_api_addrs, "CreateVpc", &data.to_string()).await?;
    tracing::info!("VPC created with ID {vpc_id}");
    Ok(vpc_id)
}
