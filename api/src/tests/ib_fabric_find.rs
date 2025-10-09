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

use ::rpc::forge as rpc;
use rpc::forge_server::Forge;

use crate::cfg::file::IBFabricConfig;
use crate::tests::common::api_fixtures::{self};

#[crate::sqlx_test]
async fn test_find_ib_fabric_ids_disabled(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool.clone()).await;

    let ids_all = env
        .api
        .find_ib_fabric_ids(tonic::Request::new(rpc::IbFabricSearchFilter::default()))
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.ib_fabric_ids, Vec::<String>::new());
}

#[crate::sqlx_test]
async fn test_find_ib_fabric_ids_enabled(pool: sqlx::PgPool) {
    let mut config = api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        api_fixtures::TestEnvOverrides::with_config(config),
    )
    .await;

    let ids_all = env
        .api
        .find_ib_fabric_ids(tonic::Request::new(rpc::IbFabricSearchFilter::default()))
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.ib_fabric_ids, vec!["default".to_string()]);
}
