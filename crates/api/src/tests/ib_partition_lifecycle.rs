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

use std::collections::HashMap;

use carbide_uuid::infiniband::IBPartitionId;
use db::db_read::PgPoolReader;
use db::ib_partition::{IBPartition, IBPartitionConfig, IBPartitionStatus, NewIBPartition};
use db::{self, ObjectColumnFilter};
use model::ib::{IBMtu, IBNetwork, IBQosConf, IBRateLimit, IBServiceLevel};
use model::metadata::Metadata;
use rpc::forge::forge_server::Forge;
use rpc::forge::{Label, TenantState};
use tonic::Request;

use crate::api::Api;
use crate::api::rpc::IbPartitionConfig;
use crate::cfg::file::IBFabricConfig;
use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnvOverrides, create_test_env};

const FIXTURE_CREATED_IB_PARTITION_NAME: &str = "ib_partition_1";
const FIXTURE_TENANT_ORG_ID: &str = "tenant";

async fn create_ib_partition_with_api(
    api: &Api,
    name: String,
) -> Result<tonic::Response<rpc::IbPartition>, tonic::Status> {
    let request = rpc::forge::IbPartitionCreationRequest {
        id: None,
        config: Some(IbPartitionConfig {
            name: name.clone(),
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
            pkey: None,
        }),
        metadata: Some(rpc::Metadata {
            name,
            labels: vec![Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
            description: "example description".into(),
        }),
    };

    api.create_ib_partition(Request::new(request)).await
}

async fn get_partition_state(api: &Api, ib_partition_id: IBPartitionId) -> TenantState {
    let segment = api
        .find_ib_partitions_by_ids(Request::new(rpc::forge::IbPartitionsByIdsRequest {
            ib_partition_ids: vec![ib_partition_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);

    let status = segment.status.unwrap();

    TenantState::try_from(status.state).unwrap()
}

async fn test_ib_partition_lifecycle_impl(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let partition =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
            .await
            .unwrap()
            .into_inner();

    let partition_id: IBPartitionId = partition.id.unwrap();
    // The TenantState only switches after the state controller recognized the update
    assert_eq!(
        get_partition_state(&env.api, partition_id).await,
        TenantState::Provisioning
    );

    env.run_ib_partition_controller_iteration().await;

    // After 1 controller iterations, the partition should be ready
    assert_eq!(
        get_partition_state(&env.api, partition_id).await,
        TenantState::Ready
    );

    env.run_ib_partition_controller_iteration().await;
    // After another controller iterations, the partition should still be ready even the
    // controller can not find the partition.
    assert_eq!(
        get_partition_state(&env.api, partition_id).await,
        TenantState::Ready
    );

    env.api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id,
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the partition should show up as deleting
    assert_eq!(
        get_partition_state(&env.api, partition_id).await,
        TenantState::Terminating
    );

    // Deletion is idempotent
    env.api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id,
        }))
        .await
        .expect("expect deletion to succeed");

    // Make the controller aware about termination too
    env.run_ib_partition_controller_iteration().await;
    env.run_ib_partition_controller_iteration().await;

    let partitions = env
        .api
        .find_ib_partitions_by_ids(Request::new(rpc::forge::IbPartitionsByIdsRequest {
            ib_partition_ids: vec![partition.id.unwrap()],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions;

    assert!(partitions.is_empty());

    // After the partition is fully gone, deleting it again should return NotFound
    // Calling the API again in this state should be a noop
    let err = env
        .api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id,
        }))
        .await
        .expect_err("expect deletion to fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        err.message(),
        format!("ib_partition not found: {}", partition.id.unwrap())
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_ib_partition_lifecycle(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    test_ib_partition_lifecycle_impl(pool).await
}

#[crate::sqlx_test]
async fn test_find_ib_partition_for_tenant(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let created_ib_partition =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
            .await
            .unwrap()
            .into_inner();
    let created_ib_partition_id: IBPartitionId = created_ib_partition.id.unwrap();

    let find_ib_partition = env
        .api
        .ib_partitions_for_tenant(Request::new(rpc::forge::TenantSearchQuery {
            tenant_organization_id: Some(FIXTURE_TENANT_ORG_ID.to_string()),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);
    let find_ib_partition_id: IBPartitionId = find_ib_partition.id.unwrap();

    assert_eq!(created_ib_partition_id, find_ib_partition_id);
    Ok(())
}

#[crate::sqlx_test]
async fn test_create_ib_partition_over_max_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // create max number of ib partitions for the tenant
    for _i in 1..=IBFabricConfig::default_max_partition_per_tenant() {
        let _ =
            create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
                .await?;
    }

    // create one more ib partition for this tenant, should be fail with no rows retruned from DB.
    let response =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string()).await;

    let error = response
        .expect_err("expected create ibpartition to fail")
        .to_string();
    assert!(
        error.contains("Maximum Limit of Infiniband partitions had been reached"),
        "Error message should contain 'Maximum Limit of Infiniband partitions had been reached', but is {error}"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_create_with_invalid_metadata(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let request = rpc::forge::IbPartitionCreationRequest {
        id: None,
        config: Some(IbPartitionConfig {
            name: "partition1".into(),
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
            pkey: None,
        }),
        metadata: Some(rpc::Metadata {
            name: "".into(), // Invalid name
            labels: vec![Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
            description: "example description".into(),
        }),
    };

    let response = env.api.create_ib_partition(Request::new(request)).await;

    let error = response
        .expect_err("expected create ibpartition to fail")
        .to_string();
    assert!(
        error.contains("Invalid metadata for IBPartition"),
        "Error message should contain 'Invalid metadata for IBPartition', but is {error}"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn create_ib_partition_with_api_with_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Try an explicit pkey request with a bad format.
    // This should fail.
    let _ = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: Some(IBPartitionId::new()),
            config: Some(IbPartitionConfig {
                name: "partition1".into(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: Some("ABCDEFG".to_string()),
            }),
            metadata: Some(rpc::Metadata {
                name: "partition1".into(),
                labels: vec![Label {
                    key: "example_label".into(),
                    value: Some("example_value".into()),
                }],
                description: "description".into(),
            }),
        }))
        .await
        .unwrap_err();

    // Try an explicit pkey request with a good format but in the range
    // that isn't allowed to be explicitly requested.
    // This should fail.
    let _ = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: Some(IBPartitionId::new()),
            config: Some(IbPartitionConfig {
                name: "partition1".into(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: Some("0x05".to_string()),
            }),
            metadata: Some(rpc::Metadata {
                name: "partition1".into(),
                labels: vec![Label {
                    key: "example_label".into(),
                    value: Some("example_value".into()),
                }],
                description: "description".into(),
            }),
        }))
        .await
        .unwrap_err();

    // Now get a partition with a valid PKEY that can be
    // explicitly requested.
    // This should pass.
    let id = IBPartitionId::new();

    let partition = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: Some(id),
            config: Some(IbPartitionConfig {
                name: "partition1".into(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: Some("0x96".to_string()), // 150
            }),
            metadata: Some(rpc::Metadata {
                name: "partition1".into(),
                labels: vec![Label {
                    key: "example_label".into(),
                    value: Some("example_value".into()),
                }],
                description: "description".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(partition.id, Some(id));

    let id = IBPartitionId::new();
    let request = rpc::forge::IbPartitionCreationRequest {
        id: Some(id),
        config: Some(IbPartitionConfig {
            name: "partition1".into(),
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
            pkey: None,
        }),
        metadata: Some(rpc::Metadata {
            name: "partition1".into(),
            labels: vec![Label {
                key: "example_label".into(),
                value: Some("example_value".into()),
            }],
            description: "description".into(),
        }),
    };

    let partition = env
        .api
        .create_ib_partition(Request::new(request))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(partition.id, Some(id));
    Ok(())
}

#[crate::sqlx_test]
async fn test_update_ib_partition(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let id = IBPartitionId::new();
    let new_partition = NewIBPartition {
        id,
        config: IBPartitionConfig {
            name: "partition1".to_string(),
            pkey: None,
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string().try_into().unwrap(),
            mtu: Some(IBMtu::default()),
            rate_limit: Some(IBRateLimit::default()),
            service_level: Some(IBServiceLevel::default()),
        },
        metadata: Metadata {
            name: "partition1".to_string(),
            labels: HashMap::from([("example_label".into(), "example_value".into())]),
            description: "new description".to_string(),
        },
    };
    let mut txn = pool.begin().await?;
    let mut partition: IBPartition = db::ib_partition::create(
        new_partition,
        &mut txn,
        10,
        IBPartitionStatus {
            partition: None,
            mtu: None,
            rate_limit: None,
            service_level: None,
            pkey: Some(42.try_into().unwrap()),
        },
    )
    .await?;
    txn.commit().await?;

    let results = db::ib_partition::for_tenant(&pool, FIXTURE_TENANT_ORG_ID.to_string()).await?;

    assert_eq!(results.len(), 1);
    assert_eq!(partition.config, results[0].config);

    let ibnetwork = IBNetwork {
        pkey: 42,
        name: "x".to_string(),
        qos_conf: Some(IBQosConf {
            mtu: IBMtu(2),
            service_level: IBServiceLevel(15),
            rate_limit: IBRateLimit(112),
        }),
        ipoib: false,
        associated_guids: None,
        membership: None,
        // Not implemented yet
        // enable_sharp: false,
        // index0: false,
    };
    let qos_conf = ibnetwork.qos_conf.as_ref().unwrap();
    partition.status = Some(IBPartitionStatus {
        partition: Some(ibnetwork.name.clone()),
        mtu: Some(qos_conf.mtu.clone()),
        rate_limit: Some(qos_conf.rate_limit.clone()),
        service_level: Some(qos_conf.service_level.clone()),
        pkey: partition.status.as_ref().and_then(|s| s.pkey),
    });
    // What we're testing
    let mut txn = pool.begin().await?;
    db::ib_partition::update(&partition, &mut txn).await?;
    txn.commit().await?;

    let partition2 = db::ib_partition::find_by(
        &mut PgPoolReader::from(pool.clone()),
        ObjectColumnFilter::One(db::ib_partition::IdColumn, &partition.id),
    )
    .await?
    .remove(0);
    assert_eq!(IBNetwork::from(&partition), IBNetwork::from(&partition2));

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_update_with_invalid_metadata(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = IBPartitionId::new();
    let new_partition = NewIBPartition {
        id,
        config: IBPartitionConfig {
            name: "partition1".to_string(),
            pkey: None,
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string().try_into().unwrap(),
            mtu: Some(IBMtu::default()),
            rate_limit: Some(IBRateLimit::default()),
            service_level: Some(IBServiceLevel::default()),
        },
        metadata: Metadata {
            name: "partition1".to_string(),
            labels: HashMap::from([("example_label".into(), "example_value".into())]),
            description: "new description".to_string(),
        },
    };
    let mut txn = pool.begin().await?;
    let mut partition: IBPartition = db::ib_partition::create(
        new_partition,
        &mut txn,
        10,
        IBPartitionStatus {
            partition: None,
            mtu: None,
            rate_limit: None,
            service_level: None,
            pkey: Some(42.try_into().unwrap()),
        },
    )
    .await?;
    txn.commit().await?;

    partition.metadata.name = "".to_string(); // Invalid name

    let mut txn = pool.begin().await?;
    let result = db::ib_partition::update(&partition, &mut txn).await;
    txn.commit().await?;

    let error = result
        .expect_err("expected update ibpartition to fail")
        .to_string();
    assert!(
        error.contains("Invalid metadata for IBPartition"),
        "Error message should contain 'Invalid metadata for IBPartition', but is {error}"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_duplicate_ib_partition(pool: sqlx::PgPool) {
    // Create a partition.
    let env = create_test_env(pool.clone()).await;
    let p = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: None,
            config: Some(IbPartitionConfig {
                name: "p1".to_string(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "p1".to_string(),
                labels: vec![Label {
                    key: "example_key".into(),
                    value: Some("example_value".into()),
                }],
                description: "example description".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    // Status should have been created with the auto-allocated PKEY.
    assert!(p.status.as_ref().and_then(|s| s.pkey.as_ref()).is_some());

    // Try to create another partition but use the pkey we just got.
    // This should fail.
    let _ = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: None,
            config: Some(IbPartitionConfig {
                name: "p2".to_string(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: p.status.unwrap().pkey,
            }),
            metadata: Some(rpc::Metadata {
                name: "p2".to_string(),
                labels: vec![Label {
                    key: "example_key".into(),
                    value: Some("example_value".into()),
                }],
                description: "example description".into(),
            }),
        }))
        .await
        .unwrap_err();

    let pkey = "0x00A0";

    // Create another partition with a valid, explicit PKEY.
    let p = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: None,
            config: Some(IbPartitionConfig {
                name: "p3".to_string(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: Some(pkey.to_string()),
            }),
            metadata: Some(rpc::Metadata {
                name: "p3".to_string(),
                labels: vec![Label {
                    key: "example_key".into(),
                    value: Some("example_value".into()),
                }],
                description: "example description".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    // Status should have been created with the requested PKEY, and status and config should match.
    assert_eq!(
        p.status.unwrap().pkey.unwrap(),
        p.config.unwrap().pkey.unwrap()
    );

    // Create another partition.  PKEY doesn't matter because we are
    // going to change it anyway.
    let p2 = env
        .api
        .create_ib_partition(Request::new(rpc::forge::IbPartitionCreationRequest {
            id: None,
            config: Some(IbPartitionConfig {
                name: "p4".to_string(),
                tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                pkey: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "p4".to_string(),
                labels: vec![Label {
                    key: "example_key".into(),
                    value: Some("example_value".into()),
                }],
                description: "example description".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    // Try an update where the status.pkey is set to an existing PKEY.
    // Updates to the PKEY of the partition shouldn't be possible, but
    // we perform status updates, and pkey is part of status.

    let mut partition = db::ib_partition::find_by(
        &mut PgPoolReader::from(pool.clone()),
        ObjectColumnFilter::One(db::ib_partition::IdColumn, p2.id.as_ref().unwrap()),
    )
    .await
    .unwrap()
    .remove(0);
    let status = partition.status.as_mut().unwrap();
    status.pkey = Some(pkey.to_string().parse().unwrap());

    let mut txn = pool.begin().await.unwrap();
    db::ib_partition::update(&partition, &mut txn)
        .await
        .unwrap_err();
    txn.rollback().await.unwrap();
}
