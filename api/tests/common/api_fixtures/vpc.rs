/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use super::TestEnv;
use crate::common::api_fixtures::instance::default_tenant_config;
use ::rpc::forge as rpc;
use rpc::forge_server::Forge;

pub async fn create_vpc(env: &TestEnv, name: String) -> (uuid::Uuid, rpc::Vpc) {
    let tenant_config = default_tenant_config();

    let vpc_id = uuid::Uuid::new_v4();
    let config = rpc::VpcCreationRequest {
        name,
        tenant_organization_id: tenant_config.tenant_organization_id,
        tenant_keyset_id: None,
        network_virtualization_type: None,
        id: Some(rpc::Uuid {
            value: vpc_id.to_string(),
        }),
    };

    let response = env.api.create_vpc(tonic::Request::new(config)).await;
    let vpc = response.unwrap().into_inner();

    (vpc_id, vpc)
}
