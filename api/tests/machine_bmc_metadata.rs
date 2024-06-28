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
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialProvider};
use mac_address::MacAddress;
use sqlx::PgPool;
pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

const SITE_BMC_ROOT_USERNAME: &str = "root";
const SITE_BMC_ROOT_PASSWORD: &str = "password";

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

// This work is done by the site explorer in the new flow
// TODO (spyda): see how we can integrate this into one of the test fixtures
async fn setup_credentials(bmc_mac_str: String, credential_provider: &dyn CredentialProvider) {
    let bmc_mac_address = bmc_mac_str.parse::<MacAddress>().unwrap();

    let bmc_site_credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };
    let credentials = forge_secrets::credentials::Credentials::UsernamePassword {
        username: SITE_BMC_ROOT_USERNAME.to_string(),
        password: SITE_BMC_ROOT_PASSWORD.to_string(),
    };

    credential_provider
        .set_credentials(bmc_site_credential_key, credentials)
        .await
        .unwrap();
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
    setup_credentials(bmc_mac_str.clone(), env.credential_provider.as_ref()).await;

    let mut txn = env.pool.begin().await.unwrap();
    BmcMetaDataUpdateRequest {
        machine_id: dpu_machine_id.clone(),
        bmc_info: BmcInfo {
            ip: Some(bmc_ip.clone()),
            port: None,
            mac: Some(bmc_mac_str.clone()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    }
    .update_bmc_meta_data(&mut txn)
    .await
    .unwrap();
    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    let get_bmc_meta_data_req = BmcMetaDataGetRequest {
        machine_id: dpu_machine_id.clone(),
    };

    let response = get_bmc_meta_data_req
        .get_bmc_meta_data(&mut txn, env.credential_provider.as_ref())
        .await
        .unwrap();
    assert_eq!(response.ip, bmc_ip.to_string());
    assert_eq!(response.port, None);
    assert_eq!(response.user, SITE_BMC_ROOT_USERNAME);
    assert_eq!(response.password, SITE_BMC_ROOT_PASSWORD);
    assert_eq!(response.mac, bmc_mac_str.to_string());
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
    setup_credentials(bmc_mac_str.clone(), env.credential_provider.as_ref()).await;

    let mut txn = env.pool.begin().await.unwrap();
    BmcMetaDataUpdateRequest {
        machine_id: dpu_machine_id.clone(),
        bmc_info: BmcInfo {
            ip: Some(bmc_ip.clone()),
            port: Some(1266),
            mac: Some(bmc_mac_str.clone()),
            version: Some("1".to_string()),
            firmware_version: Some("2".to_string()),
        },
    }
    .update_bmc_meta_data(&mut txn)
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = env.pool.begin().await.unwrap();

    let get_bmc_meta_data_req = BmcMetaDataGetRequest {
        machine_id: dpu_machine_id.clone(),
    };

    let response = get_bmc_meta_data_req
        .get_bmc_meta_data(&mut txn, env.credential_provider.as_ref())
        .await
        .unwrap();
    assert_eq!(response.ip, bmc_ip.to_string());
    assert_eq!(response.port, Some(1266));
    assert_eq!(response.user, SITE_BMC_ROOT_USERNAME);
    assert_eq!(response.password, SITE_BMC_ROOT_PASSWORD);
    assert_eq!(response.mac, bmc_mac_str.to_string());
}
