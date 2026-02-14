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

use super::grpcurl::grpcurl;

pub async fn create(
    carbide_api_addrs: &[SocketAddr],
    organization_id: &str,
    name: &str,
) -> eyre::Result<()> {
    tracing::info!("Creating tenant");

    let data = serde_json::json!({
        "organization_id": organization_id,
        "routing_profile_type": 0, // EXTERNAL
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
