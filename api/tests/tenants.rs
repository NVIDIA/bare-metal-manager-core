/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub mod common;

use common::api_fixtures::{create_test_env, TestEnv};
use rpc::forge::{forge_server::Forge, CreateTenantKeysetResponse};

use crate::common::api_fixtures::{
    create_managed_host, instance::create_instance, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test]
async fn test_tenant(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let tenant_create = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "Org".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(tenant_create.tenant.unwrap().organization_id, "Org");

    let find_tenant = env
        .api
        .find_tenant(tonic::Request::new(rpc::forge::FindTenantRequest {
            tenant_organization_id: "Org".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(find_tenant.tenant.clone().unwrap().organization_id, "Org");

    let version = find_tenant.tenant.unwrap().version;

    let update_tenant = env
        .api
        .update_tenant(tonic::Request::new(rpc::forge::UpdateTenantRequest {
            organization_id: "Org".to_string(),
            tenant_content: None,
            if_version_match: Some(version.clone()),
        }))
        .await
        .unwrap()
        .into_inner();

    println!("{:?}", update_tenant);
    assert_ne!(version, update_tenant.tenant.unwrap().version);
}

async fn create_keyset(
    env: &TestEnv,
    organization_id: String,
    keyset_id: String,
    version: String,
    keyset_content: rpc::forge::TenantKeysetContent,
) -> CreateTenantKeysetResponse {
    env.api
        .create_tenant_keyset(tonic::Request::new(rpc::forge::CreateTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id,
                keyset_id,
            }),
            keyset_content: Some(keyset_content),
            version,
        }))
        .await
        .unwrap()
        .into_inner()
}

#[sqlx::test]
async fn test_tenant_create_keyset(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let keyset = create_keyset(
        &env,
        "Org1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![],
        },
    )
    .await
    .keyset
    .unwrap();

    assert_eq!(
        keyset.keyset_identifier.as_ref().unwrap().organization_id,
        "Org1"
    );

    assert_eq!(
        keyset.keyset_identifier.as_ref().unwrap().keyset_id,
        "keyset1"
    );

    assert!(keyset.keyset_content.unwrap().public_keys.is_empty());
}

#[sqlx::test]
async fn test_tenant_find_keyset(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let _ = create_keyset(
        &env,
        "Org1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![],
        },
    )
    .await;

    let _ = create_keyset(
        &env,
        "Org1".to_string(),
        "keyset2".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![
                rpc::forge::TenantPublicKey {
                    public_key: "mypublickey1".to_string(),
                    comment: Some("comment1".to_string()),
                },
                rpc::forge::TenantPublicKey {
                    public_key: "mypublickey2".to_string(),
                    comment: Some("comment2".to_string()),
                },
            ],
        },
    )
    .await;

    let _ = create_keyset(
        &env,
        "Org2".to_string(),
        "keyset3".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![],
        },
    )
    .await;

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org3".to_string()),
            keyset_id: None,
            include_key_data: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(find_result.keyset.is_empty());

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: None,
            include_key_data: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(find_result.keyset.len(), 2);

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: Some("keyset2".to_string()),
            include_key_data: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(find_result.keyset.len(), 1);
    assert_eq!(
        find_result.keyset[0]
            .keyset_identifier
            .as_ref()
            .unwrap()
            .organization_id,
        "Org1"
    );

    assert_eq!(
        find_result.keyset[0]
            .keyset_identifier
            .as_ref()
            .unwrap()
            .keyset_id,
        "keyset2"
    );

    assert!(find_result.keyset[0]
        .keyset_content
        .as_ref()
        .unwrap()
        .public_keys
        .is_empty());

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: Some("keyset2".to_string()),
            include_key_data: true,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(find_result.keyset.len(), 1);
    assert_eq!(
        find_result.keyset[0]
            .keyset_identifier
            .as_ref()
            .unwrap()
            .organization_id,
        "Org1"
    );

    assert_eq!(
        find_result.keyset[0]
            .keyset_identifier
            .as_ref()
            .unwrap()
            .keyset_id,
        "keyset2"
    );

    assert_eq!(
        find_result.keyset[0]
            .keyset_content
            .as_ref()
            .unwrap()
            .public_keys
            .len(),
        2
    );
}

#[sqlx::test]
async fn test_tenant_delete_keyset(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let _ = create_keyset(
        &env,
        "Org1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![],
        },
    )
    .await;

    assert!(env
        .api
        .delete_tenant_keyset(tonic::Request::new(rpc::forge::DeleteTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id: "Org1".to_string(),
                keyset_id: "keyset_id".to_string(),
            }),
        }))
        .await
        .is_err());

    env.api
        .delete_tenant_keyset(tonic::Request::new(rpc::forge::DeleteTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id: "Org1".to_string(),
                keyset_id: "keyset1".to_string(),
            }),
        }))
        .await
        .unwrap();

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: None,
            include_key_data: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(find_result.keyset.is_empty());
}

#[sqlx::test]
async fn test_tenant_update_keyset(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let _ = create_keyset(
        &env,
        "Org1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![],
        },
    )
    .await;

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: None,
            include_key_data: true,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(find_result.keyset[0]
        .keyset_content
        .as_ref()
        .unwrap()
        .public_keys
        .is_empty());

    assert!(env
        .api
        .update_tenant_keyset(tonic::Request::new(rpc::forge::UpdateTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id: "Org1".to_string(),
                keyset_id: "keyset1".to_string(),
            }),
            keyset_content: Some(rpc::forge::TenantKeysetContent {
                public_keys: vec![
                    rpc::forge::TenantPublicKey {
                        public_key: "mypublickey1".to_string(),
                        comment: Some("comment1".to_string()),
                    },
                    rpc::forge::TenantPublicKey {
                        public_key: "mypublickey2".to_string(),
                        comment: Some("comment2".to_string()),
                    },
                ],
            }),
            version: "V2-T1691517639501030".to_string(),
            if_version_match: Some("V1-T1691517639501900".to_string()),
        }))
        .await
        .is_err());

    env.api
        .update_tenant_keyset(tonic::Request::new(rpc::forge::UpdateTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id: "Org1".to_string(),
                keyset_id: "keyset1".to_string(),
            }),
            keyset_content: Some(rpc::forge::TenantKeysetContent {
                public_keys: vec![rpc::forge::TenantPublicKey {
                    public_key: "mypublickey1".to_string(),
                    comment: Some("comment1".to_string()),
                }],
            }),
            version: "V2-T1691517639501030".to_string(),
            if_version_match: Some("V1-T1691517639501025".to_string()),
        }))
        .await
        .unwrap();

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: None,
            include_key_data: true,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        find_result.keyset[0]
            .keyset_content
            .as_ref()
            .unwrap()
            .public_keys
            .len(),
        1
    );

    env.api
        .update_tenant_keyset(tonic::Request::new(rpc::forge::UpdateTenantKeysetRequest {
            keyset_identifier: Some(rpc::forge::TenantKeysetIdentifier {
                organization_id: "Org1".to_string(),
                keyset_id: "keyset1".to_string(),
            }),
            keyset_content: Some(rpc::forge::TenantKeysetContent {
                public_keys: vec![
                    rpc::forge::TenantPublicKey {
                        public_key: "mypublickey1".to_string(),
                        comment: Some("comment1".to_string()),
                    },
                    rpc::forge::TenantPublicKey {
                        public_key: "mypublickey2".to_string(),
                        comment: Some("comment2".to_string()),
                    },
                ],
            }),
            version: "V3-T1691517639501030".to_string(),
            if_version_match: None,
        }))
        .await
        .unwrap();

    let find_result = env
        .api
        .find_tenant_keyset(tonic::Request::new(rpc::forge::FindTenantKeysetRequest {
            organization_id: Some("Org1".to_string()),
            keyset_id: None,
            include_key_data: true,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        find_result.keyset[0]
            .keyset_content
            .as_ref()
            .unwrap()
            .public_keys
            .len(),
        2
    );

    assert_eq!(
        "V3-T1691517639501030".to_string(),
        find_result.keyset[0].version
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_tenant_validate_keyset(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let _keyset = create_keyset(
        &env,
        "Tenant1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![rpc::forge::TenantPublicKey {
                public_key: "ssh-rsa some_long_key_base64_encoded test@myname".to_string(),
                comment: Some("some random comment".to_string()),
            }],
        },
    )
    .await
    .keyset
    .unwrap();

    let _keyset = create_keyset(
        &env,
        "org1".to_string(),
        "keyset1".to_string(),
        "V1-T1691517639501025".to_string(),
        rpc::forge::TenantKeysetContent {
            public_keys: vec![rpc::forge::TenantPublicKey {
                public_key: "ssh-rsa some_long_key_base64_encoded_1 test@myname".to_string(),
                comment: Some("some random comment".to_string()),
            }],
        },
    )
    .await
    .keyset
    .unwrap();

    // Create instance
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });
    let (instance_id, _instance) =
        create_instance(&env, &dpu_machine_id, &host_machine_id, network, None).await;

    // Test that key set validation NOT ok with ssh keys passed with instance.
    assert!(env
        .api
        .validate_tenant_public_key(tonic::Request::new(
            rpc::forge::ValidateTenantPublicKeyRequest {
                instance_id: instance_id.to_string(),
                tenant_public_key: "mykey1".to_string()
            },
        ))
        .await
        .is_err());

    assert!(env
        .api
        .validate_tenant_public_key(tonic::Request::new(
            rpc::forge::ValidateTenantPublicKeyRequest {
                instance_id: instance_id.to_string(),
                tenant_public_key: "some_long_key_base64_encoded".to_string()
            },
        ))
        .await
        .is_ok());

    assert!(env
        .api
        .validate_tenant_public_key(tonic::Request::new(
            rpc::forge::ValidateTenantPublicKeyRequest {
                instance_id: instance_id.to_string(),
                tenant_public_key: "some_long_key_base64_encoded_1".to_string()
            },
        ))
        .await
        .is_err());

    assert!(env
        .api
        .validate_tenant_public_key(tonic::Request::new(
            rpc::forge::ValidateTenantPublicKeyRequest {
                instance_id: instance_id.to_string(),
                tenant_public_key: "unknown_key1".to_string()
            },
        ))
        .await
        .is_err());
}
