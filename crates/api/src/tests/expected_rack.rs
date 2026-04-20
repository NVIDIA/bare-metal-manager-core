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

use carbide_uuid::rack::{RackId, RackProfileId};
use common::api_fixtures::{create_test_env, create_test_env_with_overrides, get_config};
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackProfile, RackProfileConfig,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpectedRackList, ExpectedRackRequest};

use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;

fn config_with_rack_profiles() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_profiles = RackProfileConfig {
        rack_profiles: [
            (
                "NVL72".to_string(),
                RackProfile {
                    rack_capabilities: RackCapabilitiesSet {
                        compute: RackCapabilityCompute {
                            name: Some("GB200".to_string()),
                            count: 18,
                            vendor: Some("NVIDIA".to_string()),
                            slot_ids: None,
                        },
                        switch: RackCapabilitySwitch {
                            name: None,
                            count: 9,
                            vendor: None,
                            slot_ids: None,
                        },
                        power_shelf: RackCapabilityPowerShelf {
                            name: None,
                            count: 4,
                            vendor: None,
                            slot_ids: None,
                        },
                    },
                    ..Default::default()
                },
            ),
            (
                "NVL36".to_string(),
                RackProfile {
                    rack_capabilities: RackCapabilitiesSet {
                        compute: RackCapabilityCompute {
                            name: None,
                            count: 9,
                            vendor: None,
                            slot_ids: None,
                        },
                        switch: RackCapabilitySwitch {
                            name: None,
                            count: 4,
                            vendor: None,
                            slot_ids: None,
                        },
                        power_shelf: RackCapabilityPowerShelf {
                            name: None,
                            count: 2,
                            vendor: None,
                            slot_ids: None,
                        },
                    },
                    ..Default::default()
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    config
}

fn new_rack_id() -> RackId {
    RackId::new(uuid::Uuid::new_v4().to_string())
}

/// Helper to seed expected racks directly via DB for tests that don't need the API.
async fn seed_expected_racks(txn: &mut sqlx::PgConnection) -> Vec<RackId> {
    let ids: Vec<RackId> = (0..3).map(|_| new_rack_id()).collect();

    db::expected_rack::create(
        txn,
        &model::expected_rack::ExpectedRack {
            rack_id: ids[0].clone(),
            rack_profile_id: RackProfileId::new("NVL72"),

            metadata: model::metadata::Metadata {
                name: "rack-1".to_string(),
                description: "Test rack 1".to_string(),
                labels: Default::default(),
            },
        },
    )
    .await
    .unwrap();

    db::expected_rack::create(
        txn,
        &model::expected_rack::ExpectedRack {
            rack_id: ids[1].clone(),
            rack_profile_id: RackProfileId::new("NVL72"),

            metadata: model::metadata::Metadata {
                name: "rack-2".to_string(),
                description: "Test rack 2".to_string(),
                labels: Default::default(),
            },
        },
    )
    .await
    .unwrap();

    db::expected_rack::create(
        txn,
        &model::expected_rack::ExpectedRack {
            rack_id: ids[2].clone(),
            rack_profile_id: RackProfileId::new("NVL36"),

            metadata: model::metadata::Metadata {
                name: "rack-3".to_string(),
                description: "Test rack 3".to_string(),
                labels: [("env".to_string(), "test".to_string())]
                    .into_iter()
                    .collect(),
            },
        },
    )
    .await
    .unwrap();

    ids
}

// ── DB tests ──

#[crate::sqlx_test]
async fn test_db_find_by_rack_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let ids = seed_expected_racks(&mut txn).await;

    let expected_rack = db::expected_rack::find_by_rack_id(&mut txn, &ids[0])
        .await?
        .expect("Expected rack not found");

    assert_eq!(expected_rack.rack_id, ids[0]);
    assert_eq!(expected_rack.rack_profile_id.as_str(), "NVL72");
    assert_eq!(expected_rack.metadata.name, "rack-1");
    assert_eq!(expected_rack.metadata.description, "Test rack 1");

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_find_all(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let _ids = seed_expected_racks(&mut txn).await;

    let all = db::expected_rack::find_all(&mut txn).await?;
    assert_eq!(all.len(), 3);
    Ok(())
}

#[crate::sqlx_test]
async fn test_db_find_nonexistent(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let rack_id = new_rack_id();
    let result = db::expected_rack::find_by_rack_id(&mut txn, &rack_id).await?;
    assert!(result.is_none());
    Ok(())
}

#[crate::sqlx_test]
async fn test_db_create_and_find(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let rack_id = new_rack_id();
    let metadata = model::metadata::Metadata {
        name: "test-rack".to_string(),
        description: "A test rack".to_string(),
        labels: [("env".to_string(), "test".to_string())]
            .into_iter()
            .collect(),
    };

    let created = db::expected_rack::create(
        &mut txn,
        &model::expected_rack::ExpectedRack {
            rack_id: rack_id.clone(),
            rack_profile_id: RackProfileId::new("NVL72"),

            metadata,
        },
    )
    .await?;

    assert_eq!(created.rack_id, rack_id);
    assert_eq!(created.rack_profile_id.as_str(), "NVL72");
    assert_eq!(created.metadata.name, "test-rack");
    assert_eq!(created.metadata.labels.get("env").unwrap(), "test");

    let found = db::expected_rack::find_by_rack_id(&mut txn, &rack_id)
        .await?
        .expect("Should find the rack we just created");

    assert_eq!(found.rack_id, rack_id);
    assert_eq!(found.rack_profile_id.as_str(), "NVL72");

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_duplicate_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let ids = seed_expected_racks(&mut txn).await;

    let result = db::expected_rack::create(
        &mut txn,
        &model::expected_rack::ExpectedRack {
            rack_id: ids[0].clone(),
            rack_profile_id: RackProfileId::new("NVL72"),

            metadata: model::metadata::Metadata::default(),
        },
    )
    .await;

    assert!(
        result.is_err(),
        "Creating a duplicate expected rack should fail"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_update(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let ids = seed_expected_racks(&mut txn).await;

    let expected_rack = db::expected_rack::find_by_rack_id(&mut txn, &ids[0])
        .await?
        .expect("Expected rack not found");

    assert_eq!(expected_rack.rack_profile_id.as_str(), "NVL72");

    let updated = model::expected_rack::ExpectedRack {
        rack_id: ids[0].clone(),
        rack_profile_id: RackProfileId::new("NVL36"),
        metadata: model::metadata::Metadata {
            name: "updated-rack".to_string(),
            description: "Updated description".to_string(),
            labels: Default::default(),
        },
    };

    db::expected_rack::update(&mut txn, &updated).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let found = db::expected_rack::find_by_rack_id(&mut txn, &ids[0])
        .await?
        .unwrap();
    assert_eq!(found.rack_profile_id.as_str(), "NVL36");
    assert_eq!(found.metadata.name, "updated-rack");

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_delete(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let ids = seed_expected_racks(&mut txn).await;

    db::expected_rack::delete(&mut txn, &ids[0]).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let result = db::expected_rack::find_by_rack_id(&mut txn, &ids[0]).await?;
    assert!(result.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_delete_nonexistent(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let rack_id = new_rack_id();

    let result = db::expected_rack::delete(&mut txn, &rack_id).await;
    assert!(result.is_err(), "Deleting nonexistent rack should fail");

    Ok(())
}

#[crate::sqlx_test]
async fn test_db_clear(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let _ids = seed_expected_racks(&mut txn).await;

    db::expected_rack::clear(&mut txn).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let all = db::expected_rack::find_all(&mut txn).await?;
    assert_eq!(all.len(), 0);

    Ok(())
}

// ── API handler tests ──

#[crate::sqlx_test]
async fn test_add_expected_rack(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: Some(rack_id.clone()),
        rack_profile_id: Some(RackProfileId::new("NVL72")),
        metadata: Some(rpc::forge::Metadata {
            name: "test-rack".to_string(),
            description: "A test NVL72 rack".to_string(),
            labels: vec![rpc::forge::Label {
                key: "env".to_string(),
                value: Some("test".to_string()),
            }],
        }),
    };

    env.api
        .add_expected_rack(tonic::Request::new(expected_rack.clone()))
        .await
        .expect("unable to add expected rack");

    let retrieved = env
        .api
        .get_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .expect("unable to retrieve expected rack")
        .into_inner();

    assert_eq!(retrieved.rack_id, Some(rack_id));
    assert_eq!(
        retrieved.rack_profile_id.as_ref().unwrap().as_str(),
        "NVL72"
    );
    assert_eq!(retrieved.metadata.as_ref().unwrap().name, "test-rack");
}

#[crate::sqlx_test]
async fn test_add_expected_rack_invalid_type(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: Some(rack_id.clone()),
        rack_profile_id: Some(RackProfileId::new("INVALID_TYPE")),
        metadata: None,
    };

    let err = env
        .api
        .add_expected_rack(tonic::Request::new(expected_rack))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("Unknown rack_profile_id"),
        "Expected error about unknown rack_profile_id, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_add_expected_rack_empty_type(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: Some(rack_id.clone()),
        rack_profile_id: Some(RackProfileId::new("")),
        metadata: None,
    };

    let err = env
        .api
        .add_expected_rack(tonic::Request::new(expected_rack))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("rack_profile_id is required"),
        "Expected error about empty rack_profile_id, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_add_expected_rack_missing_rack_id(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: None,
        rack_profile_id: Some(RackProfileId::new("NVL72")),
        metadata: None,
    };

    let err = env
        .api
        .add_expected_rack(tonic::Request::new(expected_rack))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("rack_id"),
        "Expected error about missing rack_id, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_get_expected_rack_not_found(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let rack_id = new_rack_id();
    let err = env
        .api
        .get_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("not found"),
        "Expected not found error, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_delete_expected_rack(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: Some(rack_id.clone()),
        rack_profile_id: Some(RackProfileId::new("NVL72")),
        metadata: None,
    };

    env.api
        .add_expected_rack(tonic::Request::new(expected_rack))
        .await
        .expect("unable to add expected rack");

    env.api
        .delete_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .expect("unable to delete expected rack");

    let err = env
        .api
        .get_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .unwrap_err();

    assert!(err.message().contains("not found"));
}

#[crate::sqlx_test]
async fn test_delete_expected_rack_not_found(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let rack_id = new_rack_id();
    let err = env
        .api
        .delete_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("not found"),
        "Expected not found error, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_update_expected_rack(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();

    // Add a rack first.
    env.api
        .add_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
            rack_id: Some(rack_id.clone()),
            rack_profile_id: Some(RackProfileId::new("NVL72")),
            metadata: Some(rpc::forge::Metadata {
                name: "original".to_string(),
                ..Default::default()
            }),
        }))
        .await
        .expect("unable to add expected rack");

    // Update it.
    env.api
        .update_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
            rack_id: Some(rack_id.clone()),
            rack_profile_id: Some(RackProfileId::new("NVL36")),
            metadata: Some(rpc::forge::Metadata {
                name: "updated".to_string(),
                description: "Updated rack".to_string(),
                ..Default::default()
            }),
        }))
        .await
        .expect("unable to update expected rack");

    let retrieved = env
        .api
        .get_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: rack_id.to_string(),
        }))
        .await
        .expect("unable to get expected rack")
        .into_inner();

    assert_eq!(
        retrieved.rack_profile_id.as_ref().unwrap().as_str(),
        "NVL36"
    );
    assert_eq!(retrieved.metadata.as_ref().unwrap().name, "updated");
    assert_eq!(
        retrieved.metadata.as_ref().unwrap().description,
        "Updated rack"
    );
}

#[crate::sqlx_test]
async fn test_update_expected_rack_not_found(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let err = env
        .api
        .update_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
            rack_id: Some(rack_id.clone()),
            rack_profile_id: Some(RackProfileId::new("NVL72")),
            metadata: None,
        }))
        .await
        .unwrap_err();

    assert!(
        err.message().contains("not found"),
        "Expected not found error, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_get_all_expected_racks(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // Start with none.
    let all = env
        .api
        .get_all_expected_racks(tonic::Request::new(()))
        .await
        .expect("unable to get all expected racks")
        .into_inner();
    assert_eq!(all.expected_racks.len(), 0);

    // Add two.
    for i in 0..2 {
        let rack_id = new_rack_id();
        env.api
            .add_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
                rack_id: Some(rack_id),
                rack_profile_id: Some(RackProfileId::new("NVL72")),
                metadata: Some(rpc::forge::Metadata {
                    name: format!("rack-{}", i),
                    ..Default::default()
                }),
            }))
            .await
            .expect("unable to add expected rack");
    }

    let all = env
        .api
        .get_all_expected_racks(tonic::Request::new(()))
        .await
        .expect("unable to get all expected racks")
        .into_inner();
    assert_eq!(all.expected_racks.len(), 2);
}

#[crate::sqlx_test]
async fn test_add_expected_rack_duplicate(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    let expected_rack = rpc::forge::ExpectedRack {
        rack_id: Some(rack_id.clone()),
        rack_profile_id: Some(RackProfileId::new("NVL72")),
        metadata: None,
    };

    env.api
        .add_expected_rack(tonic::Request::new(expected_rack.clone()))
        .await
        .expect("unable to add expected rack");

    // Adding the same rack again should fail.
    let err = env
        .api
        .add_expected_rack(tonic::Request::new(expected_rack))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    assert!(
        err.message().contains("already exists"),
        "Expected already exists error, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_replace_all_expected_racks(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // Add one initial rack.
    let initial_rack_id = new_rack_id();
    env.api
        .add_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
            rack_id: Some(initial_rack_id.clone()),
            rack_profile_id: Some(RackProfileId::new("NVL72")),
            metadata: None,
        }))
        .await
        .expect("unable to add expected rack");

    // Replace all with two new racks.
    let rack_id_1 = new_rack_id();
    let rack_id_2 = new_rack_id();
    let replacement = ExpectedRackList {
        expected_racks: vec![
            rpc::forge::ExpectedRack {
                rack_id: Some(rack_id_1),
                rack_profile_id: Some(RackProfileId::new("NVL72")),
                metadata: Some(rpc::forge::Metadata {
                    name: "replacement-1".to_string(),
                    ..Default::default()
                }),
            },
            rpc::forge::ExpectedRack {
                rack_id: Some(rack_id_2),
                rack_profile_id: Some(RackProfileId::new("NVL36")),
                metadata: Some(rpc::forge::Metadata {
                    name: "replacement-2".to_string(),
                    ..Default::default()
                }),
            },
        ],
    };

    env.api
        .replace_all_expected_racks(tonic::Request::new(replacement))
        .await
        .expect("unable to replace all expected racks");

    let all = env
        .api
        .get_all_expected_racks(tonic::Request::new(()))
        .await
        .expect("unable to get all expected racks")
        .into_inner();
    assert_eq!(all.expected_racks.len(), 2);

    // The initial rack should be gone.
    let err = env
        .api
        .get_expected_rack(tonic::Request::new(ExpectedRackRequest {
            rack_id: initial_rack_id.to_string(),
        }))
        .await
        .unwrap_err();
    assert!(err.message().contains("not found"));
}

#[crate::sqlx_test]
async fn test_delete_all_expected_racks(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // Add two racks.
    for _ in 0..2 {
        let rack_id = new_rack_id();
        env.api
            .add_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
                rack_id: Some(rack_id),
                rack_profile_id: Some(RackProfileId::new("NVL72")),
                metadata: None,
            }))
            .await
            .expect("unable to add expected rack");
    }

    let all = env
        .api
        .get_all_expected_racks(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(all.expected_racks.len(), 2);

    // Delete all.
    env.api
        .delete_all_expected_racks(tonic::Request::new(()))
        .await
        .expect("unable to delete all expected racks");

    let all = env
        .api
        .get_all_expected_racks(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(all.expected_racks.len(), 0);
}

#[crate::sqlx_test]
async fn test_add_expected_rack_creates_rack_entry(pool: sqlx::PgPool) {
    let config = config_with_rack_profiles();
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(config)).await;

    let rack_id = new_rack_id();
    env.api
        .add_expected_rack(tonic::Request::new(rpc::forge::ExpectedRack {
            rack_id: Some(rack_id.clone()),
            rack_profile_id: Some(RackProfileId::new("NVL72")),
            metadata: None,
        }))
        .await
        .expect("unable to add expected rack");

    // Verify the expected_rack entry was created (racks row is created lazily
    // by ensure_rack_exists when the first device is discovered).
    let mut txn = pool.acquire().await.unwrap();
    let expected = db::expected_rack::find_by_rack_id(&mut txn, &rack_id)
        .await
        .unwrap();
    assert!(expected.is_some(), "expected_rack entry should exist");
    assert_eq!(expected.unwrap().rack_profile_id.as_str(), "NVL72");
}
