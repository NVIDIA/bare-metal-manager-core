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
use rpc::forge::{
    RackFirmwareCreateRequest, RackFirmwareDeleteRequest, RackFirmwareGetRequest,
    RackFirmwareSearchFilter,
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

fn create_valid_rack_firmware_json_with_switch_system_image(id: &str) -> String {
    serde_json::json!({
        "Id": id,
        "Name": "Test Rack Firmware Config With NVOS",
        "Description": "A test configuration for rack firmware with switch system image",
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
                        }
                    ]
                }
            }
        ],
        "SwitchSystemImages": [
            {
                "DeviceType": "Switch Tray",
                "Component": "NVOS",
                "Version": "25.02.2553",
                "Type": "Prod",
                "PackageName": "GB200NVL72_NVOS",
                "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/amd64/prod/nvos-amd64-25.02.2553.bin",
                "LocationType": "HTTPS",
                "Required": true
            }
        ]
    })
    .to_string()
}

fn create_valid_rack_firmware_json_with_nvos_software(id: &str) -> String {
    serde_json::json!({
        "Id": id,
        "Name": "Test Rack Firmware Config With NVOS Software",
        "Description": "A test configuration for rack firmware with NVOS under Switch Tray software",
        "BoardSKUs": [
            {
                "SKUID": "switch-sku-001",
                "Name": "P4978-Juliet_Switch",
                "Type": "Switch Tray",
                "Components": {
                    "Software": [
                        {
                            "Component": "NVOS",
                            "Version": "25.02.2553",
                            "Type": "Prod",
                            "Locations": [
                                {
                                    "Name": "NVOS_Prod_AMD64",
                                    "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/amd64/prod/nvos-amd64-25.02.2553.bin",
                                    "LocationType": "HTTPS",
                                    "PackageName": "GB300_NVOS",
                                    "Required": true
                                },
                                {
                                    "Name": "NVOS_OpenAPI_Spec",
                                    "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/openapi.json",
                                    "LocationType": "HTTPS",
                                    "PackageName": "GB300_NVOS",
                                    "Required": true
                                }
                            ]
                        },
                        {
                            "Component": "NVOS",
                            "Version": "25.02.2553",
                            "Type": "Dev",
                            "Locations": [
                                {
                                    "Name": "NVOS_Dev_AMD64",
                                    "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/amd64/dev/nvos-amd64-25.02.2553.bin",
                                    "LocationType": "HTTPS",
                                    "PackageName": "",
                                    "Required": true
                                }
                            ]
                        }
                    ],
                    "Firmware": []
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
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json: config_json.clone(),
        artifactory_token: "test-token-123".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    // Verify response
    assert_eq!(firmware.id, firmware_id);
    assert!(!firmware.config_json.is_empty());
    assert!(!firmware.available); // Should default to false
    assert!(firmware.is_default); // First firmware for a hardware type becomes default
    assert!(!firmware.created.is_empty());
    assert!(!firmware.updated.is_empty());

    // Verify database state
    let db_firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await?;
    assert_eq!(db_firmware.id, firmware_id);
    assert!(!db_firmware.available);
    assert!(db_firmware.is_default);
    assert!(db_firmware.parsed_components.is_some());

    // Verify parsed components contain expected data
    let parsed = db_firmware.parsed_components.unwrap();
    let board_skus = parsed["board_skus"].as_array().unwrap();
    assert_eq!(board_skus.len(), 2);
    assert_eq!(board_skus[0]["sku_id"], "sku-001");
    assert_eq!(board_skus[1]["sku_id"], "sku-002");

    Ok(())
}

#[crate::sqlx_test()]
async fn test_create_rack_firmware_with_switch_system_image(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "test-firmware-nvos-001";
    let config_json = create_valid_rack_firmware_json_with_switch_system_image(firmware_id);

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token-123".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    assert_eq!(firmware.id, firmware_id);

    let db_firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await?;
    let parsed = db_firmware.parsed_components.unwrap();
    let switch_system_images = parsed["switch_system_images"].as_array().unwrap();
    assert_eq!(switch_system_images.len(), 1);
    assert_eq!(switch_system_images[0]["device_type"], "Switch Tray");
    assert_eq!(switch_system_images[0]["component"], "NVOS");
    assert_eq!(switch_system_images[0]["version"], "25.02.2553");
    assert_eq!(switch_system_images[0]["firmware_type"], "prod");
    assert_eq!(switch_system_images[0]["package_name"], "GB200NVL72_NVOS");
    assert_eq!(
        switch_system_images[0]["image_filename"],
        "nvos-amd64-25.02.2553.bin"
    );

    Ok(())
}

#[crate::sqlx_test()]
async fn test_create_rack_firmware_derives_nvos_from_switch_tray_software(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "test-firmware-nvos-software-001";
    let config_json = create_valid_rack_firmware_json_with_nvos_software(firmware_id);

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token-123".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    assert_eq!(firmware.id, firmware_id);

    let db_firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await?;
    let parsed = db_firmware.parsed_components.unwrap();
    let switch_system_images = parsed["switch_system_images"].as_array().unwrap();
    assert_eq!(switch_system_images.len(), 2);

    let prod = switch_system_images
        .iter()
        .find(|image| image["firmware_type"] == "prod")
        .expect("expected prod NVOS image");
    assert_eq!(prod["device_type"], "Switch Tray");
    assert_eq!(prod["component"], "NVOS");
    assert_eq!(prod["version"], "25.02.2553");
    assert_eq!(prod["package_name"], "GB300_NVOS");
    assert_eq!(prod["image_filename"], "nvos-amd64-25.02.2553.bin");

    let dev = switch_system_images
        .iter()
        .find(|image| image["firmware_type"] == "dev")
        .expect("expected dev NVOS image");
    assert_eq!(dev["package_name"], "GB300_NVOS");
    assert_eq!(dev["image_filename"], "nvos-amd64-25.02.2553.bin");

    Ok(())
}

#[crate::sqlx_test()]
async fn test_create_rack_firmware_rejects_switch_system_image_without_location(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "invalid-firmware-nvos-missing-location";
    let config_json = serde_json::json!({
        "Id": firmware_id,
        "BoardSKUs": [],
        "SwitchSystemImages": [
            {
                "DeviceType": "Switch Tray",
                "Component": "NVOS",
                "Version": "25.02.2553",
                "Type": "Prod",
                "PackageName": "GB200NVL72_NVOS",
                "LocationType": "HTTPS",
                "Required": true
            }
        ]
    })
    .to_string();

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token-123".to_string(),
    });

    let err = env.api.create_rack_firmware(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("Location is required"));

    Ok(())
}

#[crate::sqlx_test()]
async fn test_create_rack_firmware_rejects_switch_system_image_with_wrong_device_type(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "invalid-firmware-nvos-device-type";
    let config_json = serde_json::json!({
        "Id": firmware_id,
        "BoardSKUs": [],
        "SwitchSystemImages": [
            {
                "DeviceType": "Compute Node",
                "Component": "NVOS",
                "Version": "25.02.2553",
                "Type": "Prod",
                "PackageName": "GB200NVL72_NVOS",
                "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/amd64/prod/nvos-amd64-25.02.2553.bin",
                "LocationType": "HTTPS",
                "Required": true
            }
        ]
    })
    .to_string();

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token-123".to_string(),
    });

    let err = env.api.create_rack_firmware(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("DeviceType must be 'Switch Tray'"));

    Ok(())
}

#[crate::sqlx_test()]
async fn test_create_rack_firmware_rejects_switch_system_image_with_wrong_component(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let firmware_id = "invalid-firmware-nvos-component";
    let config_json = serde_json::json!({
        "Id": firmware_id,
        "BoardSKUs": [],
        "SwitchSystemImages": [
            {
                "DeviceType": "Switch Tray",
                "Component": "SDK",
                "Version": "25.02.2553",
                "Type": "Prod",
                "PackageName": "GB200NVL72_NVOS",
                "Location": "https://urm.nvidia.com/artifactory/sw-nbu-sws-nvos-generic-local/release/25.02.2553/amd64/prod/nvos-amd64-25.02.2553.bin",
                "LocationType": "HTTPS",
                "Required": true
            }
        ]
    })
    .to_string();

    let request = tonic::Request::new(RackFirmwareCreateRequest {
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token-123".to_string(),
    });

    let err = env.api.create_rack_firmware(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("Component must be 'NVOS'"));

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
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
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

    let request = tonic::Request::new(RackFirmwareSearchFilter {
        only_available: false,
        rack_hardware_type: None,
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
            rack_hardware_type: Some(rpc::common::RackHardwareType {
                value: "any".to_string(),
            }),
            config_json,
            artifactory_token: format!("test-token-{}", i),
        });
        env.api.create_rack_firmware(request).await?;
    }

    // List all
    let request = tonic::Request::new(RackFirmwareSearchFilter {
        only_available: false,
        rack_hardware_type: None,
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
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token".to_string(),
    });
    env.api.create_rack_firmware(create_request).await?;

    // Verify it exists
    let firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await;
    assert!(firmware.is_ok());

    // Delete it
    let delete_request = tonic::Request::new(RackFirmwareDeleteRequest {
        id: firmware_id.to_string(),
    });
    env.api.delete_rack_firmware(delete_request).await?;

    // Verify it's gone
    let firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await;
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
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
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
    let list_request = tonic::Request::new(RackFirmwareSearchFilter {
        only_available: false,
        rack_hardware_type: None,
    });
    let list_response = env.api.list_rack_firmware(list_request).await?;
    let list = list_response.into_inner();
    assert_eq!(list.configs.len(), 1);
    assert_eq!(list.configs[0].id, firmware_id);

    // 4. Update availability in database
    let mut txn = env.pool.begin().await?;
    db::rack_firmware::set_available(&mut txn, firmware_id, true).await?;
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
        rack_hardware_type: Some(rpc::common::RackHardwareType {
            value: "any".to_string(),
        }),
        config_json,
        artifactory_token: "test-token".to_string(),
    });

    let response = env.api.create_rack_firmware(request).await?;
    let firmware = response.into_inner();

    assert_eq!(firmware.id, firmware_id);

    // Verify parsed components
    let db_firmware = db::rack_firmware::find_by_id(&env.pool, firmware_id).await?;
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
