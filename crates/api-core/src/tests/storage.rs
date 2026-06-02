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

use rpc::forge::forge_server::Forge;
use rpc::forge::{
    // StorageClusterAttributes,
    // StoragePoolAttributes,
    OsImageAttributes,
    OsImageStatus,
};
use tonic::Request;
use uuid::Uuid;

use crate::tests::common::api_fixtures::{TestEnvOverrides, create_test_env_with_overrides};

// TODO: Fix tests for storage pool
/*
#[crate::sqlx_test]
async fn test_create_and_delete_storage_cluster(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    let cluster_attrs = StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let request = Request::new(cluster_attrs.clone());
    let response = env.api.import_storage_cluster(request).await;
    let cluster = response.expect("Could not create storage cluster").into_inner();

    assert!(cluster.id.is_some(), "Cluster ID should be set");
    assert_eq!(cluster.name, "test-cluster", "Cluster name should match");
    assert!(cluster.healthy, "Cluster should be healthy");

    let id = cluster.id.expect("Cluster ID should be present");
    let delete_request = rpc::forge::DeleteStorageClusterRequest {
        id: Some(id),
        name: cluster.name.clone(),
    };

    let request = Request::new(delete_request);
    let response = env.api.delete_storage_cluster(request).await;
    let _deletion_result = response.expect("Could not delete storage cluster").into_inner();

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_and_delete_storage_pool(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // First create a storage cluster
    let cluster_attrs = StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let request = Request::new(cluster_attrs.clone());
    let response = env.api.import_storage_cluster(request).await;
    let cluster = response.expect("Could not create storage cluster").into_inner();

    // Create storage pool
    let pool_attrs = StoragePoolAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        cluster_id: cluster.id.clone(),
        raid_level: rpc::forge::StorageRaidLevels::Raid1 as i32,
        capacity: 1024 * 1024 * 1024, // 1GB
        tenant_organization_id: "test-org".to_string(),
        use_for_boot_volumes: true,
        name: Some("test-pool".to_string()),
        description: Some("Test Storage Pool".to_string()),
    };

    let request = Request::new(pool_attrs.clone());
    let response = env.api.create_storage_pool(request).await;
    let pool = response.expect("Could not create storage pool").into_inner();

    assert!(pool.attributes.is_some(), "Pool attributes should be set");
    assert_eq!(
        pool.attributes.as_ref().unwrap().name,
        Some("test-pool".to_string()),
        "Pool name should match"
    );

    let pool_id = pool.attributes.as_ref().unwrap().id.clone().unwrap();
    let delete_request = rpc::forge::DeleteStoragePoolRequest {
        cluster_id: cluster.id.clone(),
        pool_id: Some(pool_id),
    };

    let request = Request::new(delete_request);
    let response = env.api.delete_storage_pool(request).await;
    let _deletion_result = response.expect("Could not delete storage pool").into_inner();

    Ok(())
}

    #[crate::sqlx_test]
async fn test_invalid_storage_cluster_attributes(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    let invalid_cluster_attrs = StorageClusterAttributes {
        host: vec![],  // Empty host list
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let request = Request::new(invalid_cluster_attrs);
    let response = env.api.import_storage_cluster(request).await;

    assert!(
        response.is_err(),
        "Creating a storage cluster with empty host list should fail"
    );
    assert_eq!(
        response.unwrap_err().code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_invalid_storage_pool_capacity(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    // First create a storage cluster
    let cluster_attrs = StorageClusterAttributes {
        host: vec!["192.168.1.100".to_string()],
        port: 4000,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
        description: Some("Test Storage Cluster".to_string()),
    };

    let request = Request::new(cluster_attrs.clone());
    let response = env.api.import_storage_cluster(request).await;
    let cluster = response.expect("Could not create storage cluster").into_inner();

    // Test with invalid capacity (0)
    let invalid_pool_attrs = StoragePoolAttributes {
        id: Some(rpc::Uuid { value: Uuid::new_v4().to_string() }),
        cluster_id: cluster.id.clone(),
        raid_level: rpc::forge::StorageRaidLevels::Raid1 as i32,
        capacity: 0,  // Invalid capacity
        tenant_organization_id: "test-org".to_string(),
        use_for_boot_volumes: true,
        name: Some("test-pool".to_string()),
        description: Some("Test Storage Pool".to_string()),
    };

    let request = Request::new(invalid_pool_attrs);
    let response = env.api.create_storage_pool(request).await;

    assert!(
        response.is_err(),
        "Creating a storage pool with zero capacity should fail"
    );
    assert_eq!(
        response.unwrap_err().code(),
        tonic::Code::InvalidArgument,
        "Error code should be InvalidArgument"
    );

    Ok(())
}
 */

#[crate::sqlx_test]
async fn test_create_and_delete_os_image(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    let image_attrs = OsImageAttributes {
        id: Some(rpc::Uuid {
            value: Uuid::new_v4().to_string(),
        }),
        source_url: "https://example.com/image.qcow2".to_string(),
        digest: "sha256:1234567890".to_string(),
        tenant_organization_id: "test-org".to_string(),
        create_volume: false,
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

    let request = Request::new(image_attrs.clone());
    let response = env.api.create_os_image(request).await;
    let image = response.expect("Could not create OS image").into_inner();

    assert!(image.attributes.is_some(), "Image attributes should be set");
    assert_eq!(
        image.status,
        OsImageStatus::ImageReady as i32,
        "Initial status should be Ready"
    );

    let image_id = image.attributes.as_ref().unwrap().id.clone().unwrap();
    let delete_request = rpc::forge::DeleteOsImageRequest {
        id: Some(image_id),
        tenant_organization_id: "test-org".to_string(),
    };

    let request = Request::new(delete_request);
    let response = env.api.delete_os_image(request).await;
    let _deletion_result = response.expect("Could not delete OS image").into_inner();

    Ok(())
}

#[crate::sqlx_test]
async fn test_os_image_status_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::default()).await;

    let image_attrs = OsImageAttributes {
        id: Some(rpc::Uuid {
            value: Uuid::new_v4().to_string(),
        }),
        source_url: "https://example.com/image.qcow2".to_string(),
        digest: "sha256:1234567890".to_string(),
        tenant_organization_id: "test-org".to_string(),
        create_volume: false,
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

    let request = Request::new(image_attrs.clone());
    let response = env.api.create_os_image(request).await;
    let image = response.expect("Could not create OS image").into_inner();

    assert_eq!(
        image.status,
        OsImageStatus::ImageReady as i32,
        "Initial status should be Ready"
    );

    // Test status transition to InProgress
    let mut updated_attrs = image_attrs.clone();
    updated_attrs.name = Some("in-progress-image".to_string());

    let request = Request::new(updated_attrs);
    let response = env.api.update_os_image(request).await;
    let updated = response.expect("Could not update OS image").into_inner();

    // The status should not change unless the volume is created
    assert_eq!(
        updated.status,
        OsImageStatus::ImageReady as i32,
        "Status should transition to ImageReady"
    );

    Ok(())
}
