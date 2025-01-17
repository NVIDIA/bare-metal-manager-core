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

use crate::tests::common;

use common::api_fixtures::{create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn test_machine_metadata(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    let version: config_version::ConfigVersion = host_machine.version.parse().unwrap();
    assert_eq!(version.version_nr(), 1);

    let expected_metadata = rpc::forge::Metadata {
        name: host_machine.id.as_ref().unwrap().to_string(),
        description: "".to_string(),
        labels: Vec::new(),
    };
    assert_eq!(host_machine.metadata.as_ref().unwrap(), &expected_metadata);

    Ok(())
}
