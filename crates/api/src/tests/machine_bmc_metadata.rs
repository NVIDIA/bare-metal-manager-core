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
