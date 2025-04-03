/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use api::db::storage::OsImage;
use api::model::storage::{OsImageAttributes, OsImageStatus, StorageClusterAttributes, StoragePoolAttributes, StorageRaidLevels};
use api::model::tenant::TenantOrganizationId;
use chrono::Utc;
use sqlx::postgres::PgPool;
use uuid::Uuid;
use crate::tests::common::api_fixtures::{create_test_env, TestEnvOverrides};
use rpc::forge::forge_server::Forge;
use tonic::Request;


#[crate::sqlx_test]
async fn test_storage_cluster_crud() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // Test Create
    let cluster_attrs = rpc::forge::StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let cluster = env.api
        .import_storage_cluster(Request::new(cluster_attrs.clone()))
        .await?
        .into_inner();

    assert!(cluster.id.is_some());
    assert_eq!(cluster.name, "test-cluster");
    assert!(cluster.healthy);

    // Test Get
    let retrieved = env.api
        .get_storage_cluster(Request::new(cluster.id.clone().unwrap()))
        .await?
        .into_inner();

    assert_eq!(retrieved.id, cluster.id);
    assert_eq!(retrieved.name, cluster.name);

    // Test List
    let list_response = env.api
        .list_storage_cluster(Request::new(rpc::forge::ListStorageClusterRequest {}))
        .await?
        .into_inner();

    assert!(!list_response.clusters.is_empty());
    assert!(list_response.clusters.iter().any(|c| c.id == cluster.id));

    // Test Delete
    let delete_request = rpc::forge::DeleteStorageClusterRequest {
        id: cluster.id.clone(),
        name: cluster.name.clone(),
    };

    env.api
        .delete_storage_cluster(Request::new(delete_request))
        .await?;

    // Verify deletion
    let list_response = env.api
        .list_storage_cluster(Request::new(rpc::forge::ListStorageClusterRequest {}))
        .await?
        .into_inner();

    assert!(!list_response.clusters.iter().any(|c| c.id == cluster.id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_storage_pool_crud() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // First create a storage cluster
    let cluster_attrs = rpc::forge::StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let cluster = env.api
        .import_storage_cluster(Request::new(cluster_attrs))
        .await?
        .into_inner();

    // Test Create Pool
    let pool_attrs = rpc::forge::StoragePoolAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        cluster_id: cluster.id.clone(),
        raid_level: rpc::forge::StorageRaidLevels::Raid1 as i32,
        capacity: 1024 * 1024 * 1024, // 1GB
        tenant_organization_id: "test-org".to_string(),
        use_for_boot_volumes: true,
        name: Some("test-pool".to_string()),
        description: Some("Test Storage Pool".to_string()),
    };

    let pool = env.api
        .create_storage_pool(Request::new(pool_attrs.clone()))
        .await?
        .into_inner();

    assert!(pool.attributes.is_some());
    assert_eq!(pool.attributes.as_ref().unwrap().name, Some("test-pool".to_string()));

    // Test Get Pool
    let retrieved = env.api
        .get_storage_pool(Request::new(pool.attributes.as_ref().unwrap().id.clone().unwrap()))
        .await?
        .into_inner();

    assert_eq!(retrieved.attributes.as_ref().unwrap().id, pool.attributes.as_ref().unwrap().id);

    // Test List Pools
    let list_request = rpc::forge::ListStoragePoolRequest {
        cluster_id: cluster.id.clone(),
        tenant_organization_id: None,
    };

    let list_response = env.api
        .list_storage_pool(Request::new(list_request))
        .await?
        .into_inner();

    assert!(!list_response.pools.is_empty());
    assert!(list_response.pools.iter().any(|p| p.attributes.as_ref().unwrap().id == pool.attributes.as_ref().unwrap().id));

    // Test Delete Pool
    let delete_request = rpc::forge::DeleteStoragePoolRequest {
        cluster_id: cluster.id.clone(),
        pool_id: pool.attributes.as_ref().unwrap().id.clone(),
    };

    env.api
        .delete_storage_pool(Request::new(delete_request))
        .await?;

    // Verify deletion
    let list_request = rpc::forge::ListStoragePoolRequest {
        cluster_id: cluster.id,
        tenant_organization_id: None,
    };

    let list_response = env.api
        .list_storage_pool(Request::new(list_request))
        .await?
        .into_inner();

    assert!(!list_response.pools.iter().any(|p| p.attributes.as_ref().unwrap().id == pool.attributes.as_ref().unwrap().id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_os_image_crud() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // Test Create
    let image_attrs = rpc::forge::OsImageAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        source_url: "https://example.com/image.qcow2".to_string(),
        digest: "sha256:1234567890".to_string(),
        tenant_organization_id: "test-org".to_string(),
        create_volume: true,
        name: Some("test-image".to_string()),
        description: Some("Test OS Image".to_string()),
        auth_type: None,
        auth_token: None,
        rootfs_id: None,
        rootfs_label: None,
        boot_disk: None,
        capacity: Some(1024 * 1024 * 1024), // 1GB
        bootfs_id: None,
        efifs_id: None,
    };

    let image = env.api
        .create_os_image(Request::new(image_attrs.clone()))
        .await?
        .into_inner();

    assert!(image.attributes.is_some());
    assert_eq!(image.status, rpc::forge::OsImageStatus::ImageUninitialized as i32);

    // Test Get
    let retrieved = env.api
        .get_os_image(Request::new(image.attributes.as_ref().unwrap().id.clone().unwrap()))
        .await?
        .into_inner();

    assert_eq!(retrieved.attributes.as_ref().unwrap().id, image.attributes.as_ref().unwrap().id);

    // Test List
    let list_request = rpc::forge::ListOsImageRequest {
        tenant_organization_id: Some("test-org".to_string()),
    };

    let list_response = env.api
        .list_os_image(Request::new(list_request))
        .await?
        .into_inner();

    assert!(!list_response.images.is_empty());
    assert!(list_response.images.iter().any(|i| i.attributes.as_ref().unwrap().id == image.attributes.as_ref().unwrap().id));

    // Test Delete
    let delete_request = rpc::forge::DeleteOsImageRequest {
        id: image.attributes.as_ref().unwrap().id.clone(),
        tenant_organization_id: "test-org".to_string(),
    };

    env.api
        .delete_os_image(Request::new(delete_request))
        .await?;

    // Verify deletion
    let list_request = rpc::forge::ListOsImageRequest {
        tenant_organization_id: Some("test-org".to_string()),
    };

    let list_response = env.api
        .list_os_image(Request::new(list_request))
        .await?
        .into_inner();

    assert!(!list_response.images.iter().any(|i| i.attributes.as_ref().unwrap().id == image.attributes.as_ref().unwrap().id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_os_image_status_transitions() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // Create test image
    let image_attrs = rpc::forge::OsImageAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        source_url: "https://example.com/image.qcow2".to_string(),
        digest: "sha256:1234567890".to_string(),
        tenant_organization_id: "test-org".to_string(),
        create_volume: true,
        name: Some("test-image".to_string()),
        description: Some("Test OS Image".to_string()),
        auth_type: None,
        auth_token: None,
        rootfs_id: None,
        rootfs_label: None,
        boot_disk: None,
        capacity: Some(1024 * 1024 * 1024),
        bootfs_id: None,
        efifs_id: None,
    };

    let image = env.api
        .create_os_image(Request::new(image_attrs.clone()))
        .await?
        .into_inner();

    assert_eq!(image.status, rpc::forge::OsImageStatus::ImageUninitialized as i32);

    // Test status transitions
    let mut updated_attrs = image_attrs.clone();
    updated_attrs.name = Some("in-progress-image".to_string());
    
    let mut updated = env.api
        .update_os_image(Request::new(updated_attrs))
        .await?
        .into_inner();

    assert_eq!(updated.status, rpc::forge::OsImageStatus::ImageInProgress as i32);

    Ok(())
}

#[crate::sqlx_test]
async fn test_storage_cluster_validation() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // Test with invalid host
    let invalid_cluster_attrs = rpc::forge::StorageClusterAttributes {
        host: vec![],  // Empty host list
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let result = env.api
        .import_storage_cluster(Request::new(invalid_cluster_attrs))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

    Ok(())
}

#[crate::sqlx_test]
async fn test_storage_pool_capacity_validation() -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // First create a storage cluster
    let cluster_attrs = rpc::forge::StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let cluster = env.api
        .import_storage_cluster(Request::new(cluster_attrs))
        .await?
        .into_inner();

    // Test with invalid capacity (0)
    let invalid_pool_attrs = rpc::forge::StoragePoolAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        cluster_id: cluster.id.clone(),
        raid_level: rpc::forge::StorageRaidLevels::Raid1 as i32,
        capacity: 0,  // Invalid capacity
        tenant_organization_id: "test-org".to_string(),
        use_for_boot_volumes: true,
        name: Some("test-pool".to_string()),
        description: Some("Test Storage Pool".to_string()),
    };

    let result = env.api
        .create_storage_pool(Request::new(invalid_pool_attrs))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

    Ok(())
} 