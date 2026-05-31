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
