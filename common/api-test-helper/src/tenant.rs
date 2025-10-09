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

use super::grpcurl::grpcurl;

pub async fn create(
    carbide_api_addrs: &[SocketAddr],
    organization_id: &str,
    name: &str,
) -> eyre::Result<()> {
    tracing::info!("Creating tenant");

    let data = serde_json::json!({
        "organization_id": organization_id,
        "metadata": {
            "name": name,
        }
    });
    grpcurl(carbide_api_addrs, "CreateTenant", Some(&data.to_string())).await?;
    tracing::info!("Tenant created with name {name}");
    Ok(())
}

pub mod keyset {
    use uuid::Uuid;

    use super::*;

    pub async fn create(
        carbide_api_addrs: &[SocketAddr],
        organization_id: &str,
        id: Uuid,
        public_keys: &[&str],
    ) -> eyre::Result<()> {
        tracing::info!("Creating tenant keyset");

        let data = serde_json::json!({
            "keyset_identifier": {
                "organization_id": organization_id,
                "keyset_id": &id.to_string(),
            },
            "keyset_content": {
                "public_keys": public_keys.iter().map(|k| serde_json::json!({
                    "public_key": k,
                })).collect::<Vec<_>>(),
            },
            "version": "V1",
        });
        grpcurl(
            carbide_api_addrs,
            "CreateTenantKeyset",
            Some(&data.to_string()),
        )
        .await?;
        tracing::info!("Tenant keyset created with id {id}");
        Ok(())
    }
}
