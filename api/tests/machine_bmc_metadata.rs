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

use std::sync::Arc;

use carbide::db::bmc_metadata::{
    BmcMetaDataGetRequest, BmcMetaDataUpdateRequest, BmcMetadataItem, UserRoles,
};
use carbide::model::bmc_info::BmcInfo;
use carbide::model::machine::machine_id::try_parse_machine_id;
use sqlx::PgPool;
pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};
use common::test_credentials::TestCredentialProvider;

const DATA: [(UserRoles, &str, &str); 3] = [
    (UserRoles::Administrator, "forge_admin", "randompassword"),
    (UserRoles::User, "forge_user", "randompassword"),
    (UserRoles::Operator, "forge_operator", "randompassword"),
];

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn machine_bmc_credential_update(pool: PgPool) {
    let env = create_test_env(pool).await;
    // TODO: This probably should test with a host machine instead of a DPU,
    // since for DPUs we don't really store BMC credentials
    let host_sim = env.start_managed_host_sim();
    let dpu_rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    let credentials_provider = Arc::new(TestCredentialProvider::new());
    BmcMetaDataUpdateRequest {
        machine_id: dpu_machine_id.clone(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0,
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),

        bmc_info: BmcInfo {
            ip: Some("127.0.0.2".to_string()),
            port: None,
            mac: Some("01:02:03:04:05:06".to_string()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    }
    .update_bmc_meta_data(&mut txn, credentials_provider.as_ref())
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataGetRequest {
            machine_id: dpu_machine_id.clone(),
            role: d.0,
        };

        let response = ipmi_req
            .get_bmc_meta_data(&mut txn, credentials_provider.as_ref())
            .await
            .unwrap();
        assert_eq!(response.ip, "127.0.0.2".to_string());
        assert_eq!(response.port, None);
        assert_eq!(response.user, d.1.to_string());
        assert_eq!(response.password, d.2.to_string());
        assert_eq!(response.mac, "01:02:03:04:05:06".to_string());
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn machine_bmc_credential_update_with_port(pool: PgPool) {
    let env = create_test_env(pool).await;
    // TODO: This probably should test with a host machine instead of a DPU,
    // since for DPUs we don't really store BMC credentials
    let host_sim = env.start_managed_host_sim();
    let dpu_rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    let credentials_provider = Arc::new(TestCredentialProvider::new());
    BmcMetaDataUpdateRequest {
        machine_id: dpu_machine_id.clone(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0,
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),

        bmc_info: BmcInfo {
            ip: Some("127.0.0.3".to_string()),
            port: Some(1266),
            mac: Some("01:02:03:04:05:07".to_string()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    }
    .update_bmc_meta_data(&mut txn, credentials_provider.as_ref())
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataGetRequest {
            machine_id: dpu_machine_id.clone(),
            role: d.0,
        };

        let response = ipmi_req
            .get_bmc_meta_data(&mut txn, credentials_provider.as_ref())
            .await
            .unwrap();
        assert_eq!(response.ip, "127.0.0.3".to_string());
        assert_eq!(response.port, Some(1266));
        assert_eq!(response.user, d.1.to_string());
        assert_eq!(response.password, d.2.to_string());
        assert_eq!(response.mac, "01:02:03:04:05:07".to_string());
    }
}
