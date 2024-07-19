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

use carbide::db::bmc_metadata::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest};
use carbide::model::bmc_info::BmcInfo;
use carbide::model::machine::machine_id::try_parse_machine_id;
use sqlx::PgPool;
pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

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

    let bmc_ip = "127.0.0.2".to_string();
    let bmc_mac_str = "01:02:03:04:05:06".to_string();

    let mut txn = env.pool.begin().await.unwrap();
    BmcMetaDataUpdateRequest::new(
        dpu_machine_id.clone(),
        BmcInfo {
            ip: Some(bmc_ip.clone()),
            port: None,
            mac: Some(bmc_mac_str.clone()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    )
    .update_bmc_meta_data(&mut txn)
    .await
    .unwrap();
    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    let get_bmc_meta_data_req = BmcMetaDataGetRequest {
        machine_id: dpu_machine_id.clone(),
    };

    let response = get_bmc_meta_data_req
        .get_bmc_meta_data(&mut txn)
        .await
        .unwrap();
    assert_eq!(response.bmc_info.ip.unwrap(), bmc_ip.to_string());
    assert_eq!(response.bmc_info.port, None);
    assert_eq!(response.bmc_info.mac.unwrap(), bmc_mac_str.to_string());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn machine_bmc_credential_update_with_port(pool: PgPool) {
    let env = create_test_env(pool).await;
    // TODO: This probably should test with a host machine instead of a DPU,
    // since for DPUs we don't really store BMC credentials
    let host_sim = env.start_managed_host_sim();
    let dpu_rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let bmc_ip = "127.0.0.3".to_string();
    let bmc_mac_str = "01:02:03:04:05:07".to_string();

    let mut txn = env.pool.begin().await.unwrap();
    BmcMetaDataUpdateRequest::new(
        dpu_machine_id.clone(),
        BmcInfo {
            ip: Some(bmc_ip.clone()),
            port: Some(1266),
            mac: Some(bmc_mac_str.clone()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    )
    .update_bmc_meta_data(&mut txn)
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    let get_bmc_meta_data_req = BmcMetaDataGetRequest {
        machine_id: dpu_machine_id.clone(),
    };

    let response = get_bmc_meta_data_req
        .get_bmc_meta_data(&mut txn)
        .await
        .unwrap();
    assert_eq!(response.bmc_info.ip.unwrap(), bmc_ip.to_string());
    assert_eq!(response.bmc_info.port, Some(1266));
    assert_eq!(response.bmc_info.mac.unwrap(), bmc_mac_str.to_string());
}
