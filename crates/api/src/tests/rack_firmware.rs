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

use common::api_fixtures::create_test_env;
use db::rack_firmware::RackFirmware as DbRackFirmware;
use rpc::forge::{
    RackFirmwareCreateRequest, RackFirmwareDeleteRequest, RackFirmwareGetRequest,
    RackFirmwareListRequest,
};
use rpc::protos::forge::forge_server::Forge;

use crate::tests::common;

/// Helper function to create a valid rack firmware JSON config
fn create_valid_rack_firmware_json(id: &str) -> String {
    serde_json::json!({
        "Id": id,
        "Name": "Test Rack Firmware Config",
        "Description": "A test configuration for rack firmware",
        "BoardSKUs": [
            {
                "SKUID": "sku-001",
                "Name": "Compute Tray",
                "Type": "ComputeTray",
                "Components": {
                    "Firmware": [
                        {
                            "Component": "BIOS",
                            "Bundle": "bios-bundle-v1.0",
                            "Version": "1.0.0",
                            "Locations": [
                                {
                                    "Location": "artifactory.example.com/bios/v1.0.0",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        },
                        {
                            "Component": "BMC",
                            "Bundle": "bmc-bundle-v2.0",
                            "Version": "2.0.0",
                            "Locations": [
                                {
                                    "Location": "artifactory.example.com/bmc/v2.0.0",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        }
                    ]
                }
            },
            {
                "SKUID": "sku-002",
                "Name": "Power Shelf",
                "Type": "PowerShelf",
                "Components": {
                    "Firmware": [
                        {
                            "Component": "PSU",
                            "Bundle": "psu-bundle-v1.5",
                            "Version": "1.5.0",
                            "Locations": [
                                {
                                    "Location": "artifactory.example.com/psu/v1.5.0",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    })
    .to_string()
}

// ============================================================================
// CREATE TESTS
// ============================================================================

#[crate::sqlx_test()]
async fn test_create_rack_firmware(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "test-firmware-001";
    let config_json = create_valid_rack_firmware_json(firmware_id);

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        config_json: config_json.clone(),
        artifactory_token: "test-token-123".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    // Verify response
    assert_eq!(firmware.id, firmware_id);
    assert!(!firmware.config_json.is_empty());
    assert!(!firmware.available); // Should default to false
    assert!(!firmware.created.is_empty());
    assert!(!firmware.updated.is_empty());

    // Verify database state
    let mut txn = env.pool.begin().await?;
    let db_firmware = DbRackFirmware::find_by_id(&mut txn, firmware_id).await?;
    assert_eq!(db_firmware.id, firmware_id);
    assert!(!db_firmware.available);
    assert!(db_firmware.parsed_components.is_some());

    // Verify parsed components contain expected data
    let parsed = db_firmware.parsed_components.unwrap();
    let board_skus = parsed["board_skus"].as_array().unwrap();
    assert_eq!(board_skus.len(), 2);
    assert_eq!(board_skus[0]["sku_id"], "sku-001");
    assert_eq!(board_skus[1]["sku_id"], "sku-002");

    Ok(())
}

// ============================================================================
// GET TESTS
// ============================================================================

#[crate::sqlx_test()]
async fn test_get_rack_firmware(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "get-test-firmware-001";
    let config_json = create_valid_rack_firmware_json(firmware_id);

    // Create firmware first
    let create_request = tonic::Request::new(RackFirmwareCreateRequest {
        config_json: config_json.clone(),
        artifactory_token: "test-token".to_string(),
    });
    env.api.create_rack_firmware(create_request).await?;

    // Now get it
    let get_request = tonic::Request::new(RackFirmwareGetRequest {
        id: firmware_id.to_string(),
    });

    let response = env.api.get_rack_firmware(get_request).await?;
    let firmware = response.into_inner();

    assert_eq!(firmware.id, firmware_id);
    assert!(!firmware.config_json.is_empty());
    assert!(!firmware.available);
    assert!(!firmware.created.is_empty());
    assert!(!firmware.updated.is_empty());

    Ok(())
}

// ============================================================================
// LIST TESTS
// ============================================================================

#[crate::sqlx_test()]
async fn test_list_rack_firmware_empty(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let request = tonic::Request::new(RackFirmwareListRequest {
        only_available: false,
    });

    let response = env.api.list_rack_firmware(request).await?;
    let list = response.into_inner();

    assert_eq!(list.configs.len(), 0);

    Ok(())
}

#[crate::sqlx_test()]
async fn test_list_rack_firmware_multiple(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create multiple firmware configs
    for i in 1..=3 {
        let firmware_id = format!("list-test-firmware-{:03}", i);
        let config_json = create_valid_rack_firmware_json(&firmware_id);

        let request = tonic::Request::new(RackFirmwareCreateRequest {
            config_json,
            artifactory_token: format!("test-token-{}", i),
        });
        env.api.create_rack_firmware(request).await?;
    }

    // List all
    let request = tonic::Request::new(RackFirmwareListRequest {
        only_available: false,
    });

    let response = env.api.list_rack_firmware(request).await?;
    let list = response.into_inner();

    assert_eq!(list.configs.len(), 3);

    // Verify they're sorted by created DESC (newest first)
    assert_eq!(list.configs[0].id, "list-test-firmware-003");
    assert_eq!(list.configs[1].id, "list-test-firmware-002");
    assert_eq!(list.configs[2].id, "list-test-firmware-001");

    Ok(())
}

// ============================================================================
// DELETE TESTS
// ============================================================================

#[crate::sqlx_test()]
async fn test_delete_rack_firmware(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "delete-test-firmware-001";
    let config_json = create_valid_rack_firmware_json(firmware_id);

    // Create firmware
    let create_request = tonic::Request::new(RackFirmwareCreateRequest {
        config_json,
        artifactory_token: "test-token".to_string(),
    });
    env.api.create_rack_firmware(create_request).await?;

    // Verify it exists
    let mut txn = env.pool.begin().await?;
    let firmware = DbRackFirmware::find_by_id(&mut txn, firmware_id).await;
    assert!(firmware.is_ok());
    txn.commit().await?;

    // Delete it
    let delete_request = tonic::Request::new(RackFirmwareDeleteRequest {
        id: firmware_id.to_string(),
    });
    env.api.delete_rack_firmware(delete_request).await?;

    // Verify it's gone
    let mut txn = env.pool.begin().await?;
    let firmware = DbRackFirmware::find_by_id(&mut txn, firmware_id).await;
    assert!(firmware.is_err());

    Ok(())
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[crate::sqlx_test()]
async fn test_rack_firmware_full_lifecycle(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "lifecycle-test-001";
    let config_json = create_valid_rack_firmware_json(firmware_id);

    // 1. Create
    let create_request = tonic::Request::new(RackFirmwareCreateRequest {
        config_json: config_json.clone(),
        artifactory_token: "test-token".to_string(),
    });
    let create_response = env.api.create_rack_firmware(create_request).await?;
    let created_firmware = create_response.into_inner();
    assert_eq!(created_firmware.id, firmware_id);
    assert!(!created_firmware.available);

    // 2. Get
    let get_request = tonic::Request::new(RackFirmwareGetRequest {
        id: firmware_id.to_string(),
    });
    let get_response = env.api.get_rack_firmware(get_request).await?;
    let retrieved_firmware = get_response.into_inner();
    assert_eq!(retrieved_firmware.id, firmware_id);

    // 3. List (should contain our firmware)
    let list_request = tonic::Request::new(RackFirmwareListRequest {
        only_available: false,
    });
    let list_response = env.api.list_rack_firmware(list_request).await?;
    let list = list_response.into_inner();
    assert_eq!(list.configs.len(), 1);
    assert_eq!(list.configs[0].id, firmware_id);

    // 4. Update availability in database
    let mut txn = env.pool.begin().await?;
    DbRackFirmware::set_available(&mut txn, firmware_id, true).await?;
    txn.commit().await?;

    // 5. Verify availability changed
    let get_request = tonic::Request::new(RackFirmwareGetRequest {
        id: firmware_id.to_string(),
    });
    let get_response = env.api.get_rack_firmware(get_request).await?;
    let updated_firmware = get_response.into_inner();
    assert!(updated_firmware.available);

    // 6. Delete
    let delete_request = tonic::Request::new(RackFirmwareDeleteRequest {
        id: firmware_id.to_string(),
    });
    env.api.delete_rack_firmware(delete_request).await?;

    // 7. Verify deleted
    let get_request = tonic::Request::new(RackFirmwareGetRequest {
        id: firmware_id.to_string(),
    });
    let err = env
        .api
        .get_rack_firmware(get_request)
        .await
        .expect_err("Should not find deleted firmware");
    assert_eq!(err.code(), tonic::Code::NotFound);

    Ok(())
}

#[crate::sqlx_test()]
async fn test_rack_firmware_with_multiple_components(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "multi-component-001";
    let config_json = serde_json::json!({
        "Id": firmware_id,
        "Name": "Multi-Component Configuration",
        "Version": "2.5.0",
        "Description": "A firmware configuration with multiple board SKUs and components",
        "BoardSKUs": [
            {
                "SKUID": "sku-compute-001",
                "Name": "GB200 Compute Tray",
                "Type": "ComputeTray",
                "Components": {
                    "Firmware": [
                        {
                            "Component": "BIOS",
                            "Bundle": "bios-gb200-v3.0",
                            "Version": "3.0.5",
                            "Locations": [
                                {
                                    "Location": "artifactory.nvidia.com/firmware/bios/gb200/v3.0.5",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        },
                        {
                            "Component": "BMC",
                            "Bundle": "bmc-gb200-v2.1",
                            "Version": "2.1.3",
                            "Locations": [
                                {
                                    "Location": "artifactory.nvidia.com/firmware/bmc/gb200/v2.1.3",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        },
                        {
                            "Component": "NIC",
                            "Bundle": "nic-cx7-v1.8",
                            "Version": "1.8.2",
                            "Locations": [
                                {
                                    "Location": "artifactory.nvidia.com/firmware/nic/cx7/v1.8.2",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        }
                    ]
                }
            },
            {
                "SKUID": "sku-power-001",
                "Name": "Power Shelf",
                "Type": "PowerShelf",
                "Components": {
                    "Firmware": [
                        {
                            "Component": "PSU",
                            "Bundle": "psu-v2.0",
                            "Version": "2.0.1",
                            "Locations": [
                                {
                                    "Location": "artifactory.nvidia.com/firmware/psu/v2.0.1",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        }
                    ]
                }
            },
            {
                "SKUID": "sku-switch-001",
                "Name": "NVLink Switch",
                "Type": "NVLinkSwitch",
                "Components": {
                    "Firmware": [
                        {
                            "Component": "SwitchOS",
                            "Bundle": "nvlink-switch-v4.0",
                            "Version": "4.0.0",
                            "Locations": [
                                {
                                    "Location": "artifactory.nvidia.com/firmware/nvlink/v4.0.0",
                                    "LocationType": "Artifactory",
                                    "Type": "Firmware"
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    })
    .to_string();

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        config_json,
        artifactory_token: "test-token".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    assert_eq!(firmware.id, firmware_id);

    // Verify parsed components
    let mut txn = env.pool.begin().await?;
    let db_firmware = DbRackFirmware::find_by_id(&mut txn, firmware_id).await?;
    assert!(db_firmware.parsed_components.is_some());

    let parsed = db_firmware.parsed_components.unwrap();
    let board_skus = parsed["board_skus"].as_array().unwrap();
    assert_eq!(board_skus.len(), 3);

    // Verify SKU details
    assert_eq!(board_skus[0]["sku_id"], "sku-compute-001");
    assert_eq!(board_skus[0]["name"], "GB200 Compute Tray");
    assert_eq!(board_skus[0]["sku_type"], "ComputeTray");

    let firmware_components = board_skus[0]["firmware_components"].as_array().unwrap();
    assert_eq!(firmware_components.len(), 3); // BIOS, BMC, NIC

    assert_eq!(board_skus[1]["sku_id"], "sku-power-001");
    assert_eq!(board_skus[2]["sku_id"], "sku-switch-001");

    Ok(())
}
