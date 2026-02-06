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

use common::api_fixtures::{create_managed_host_with_config, create_test_env};
use rpc::forge::forge_server::Forge;
use sqlx::PgPool;

use crate::tests::common;

#[crate::sqlx_test]
async fn fetch_bmc_credentials(pool: PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let host_bmc_mac = host_config.bmc_mac_address;
    let mh = create_managed_host_with_config(&env, host_config).await;

    let host_machine = mh.host().rpc_machine().await;
    let bmc_info = host_machine.bmc_info.clone().unwrap();
    assert_eq!(bmc_info.mac, Some(host_bmc_mac.to_string()));
    let host_bmc_ip = bmc_info.ip.clone().expect("Host BMC IP must be available");

    for request in vec![
        rpc::forge::BmcMetaDataGetRequest {
            machine_id: host_machine.id,
            request_type: rpc::forge::BmcRequestType::Redfish.into(),
            role: rpc::forge::UserRoles::Administrator.into(),
            bmc_endpoint_request: None,
        },
        rpc::forge::BmcMetaDataGetRequest {
            machine_id: None,
            request_type: rpc::forge::BmcRequestType::Redfish.into(),
            role: rpc::forge::UserRoles::Administrator.into(),
            bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
                ip_address: host_bmc_ip.clone(),
                mac_address: None,
            }),
        },
    ]
    .into_iter()
    {
        tracing::info!("Looking up credentials for {:?}", request);
        let metadata = env
            .api
            .get_bmc_meta_data(tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(metadata.ip, host_bmc_ip);
        assert_eq!(metadata.port, None);
        assert_eq!(metadata.mac, host_bmc_mac.to_string());
        assert!(!metadata.password.is_empty());
        assert!(!metadata.user.is_empty());
    }
}
