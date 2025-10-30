/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use common::api_fixtures::dpu::loopback_ip;
use common::api_fixtures::{create_managed_host, create_test_env};
use rpc::forge::forge_server::Forge;

use crate::tests::common;

#[crate::sqlx_test]
async fn test_get_dpu_info_list(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let dpu_machine_id_1 = create_managed_host(&env).await.dpu().id;
    let dpu_machine_id_2 = create_managed_host(&env).await.dpu().id;

    // Make RPC call to get list of DPU information
    let dpu_list = env
        .api
        .get_dpu_info_list(tonic::Request::new(::rpc::forge::GetDpuInfoListRequest {}))
        .await
        .unwrap()
        .into_inner()
        .dpu_list;

    // Check that the DPU returns list of expected DPU ids
    let mut dpu_ids: Vec<String> = dpu_list.iter().map(|dpu| dpu.id.clone()).collect();
    let mut exp_ids: Vec<String> = vec![dpu_machine_id_1.to_string(), dpu_machine_id_2.to_string()];
    dpu_ids.sort();
    exp_ids.sort();
    assert_eq!(dpu_ids, exp_ids);

    // Check that the DPU returns a list of expected DPU loopback IP addresses
    let mut txn = env.pool.begin().await.unwrap();
    let exp_dpu_loopback_ip_1 = loopback_ip(&mut txn, &dpu_machine_id_1).await;
    let exp_dpu_loopback_ip_2 = loopback_ip(&mut txn, &dpu_machine_id_2).await;

    let mut dpu_loopback_ips: Vec<String> = dpu_list
        .iter()
        .map(|dpu| dpu.loopback_ip.to_string())
        .collect();
    let mut exp_loopback_ips: Vec<String> = vec![
        exp_dpu_loopback_ip_1.to_string(),
        exp_dpu_loopback_ip_2.to_string(),
    ];
    dpu_loopback_ips.sort();
    exp_loopback_ips.sort();
    assert_eq!(dpu_loopback_ips, exp_loopback_ips);
}
