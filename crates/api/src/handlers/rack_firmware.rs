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

use std::path::PathBuf;
use std::sync::Arc;

use db::DatabaseError;
use db::rack_firmware::RackFirmware as DbRackFirmware;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use rpc::forge::{
    DeviceUpdateResult, NodeJobInfo, RackFirmware, RackFirmwareApplyRequest,
    RackFirmwareApplyResponse, RackFirmwareCreateRequest, RackFirmwareDeleteRequest,
    RackFirmwareGetRequest, RackFirmwareJobStatusRequest, RackFirmwareJobStatusResponse,
    RackFirmwareList, RackFirmwareListRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;
use tonic::{Request, Response, Status};

use crate::api::Api;
use crate::errors::CarbideError;
// Structs for parsing rack firmware JSON

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParsedFirmwareComponents {
    board_skus: Vec<BoardSkuFirmware>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BoardSkuFirmware {
    sku_id: String,
    name: String,
    sku_type: String,
    firmware_components: Vec<FirmwareComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareComponent {
    component: String,
    bundle: Option<String>,
    version: Option<String>,
    /// Firmware type: "Prod" or "Dev"
    component_type: Option<String>,
    locations: Vec<FirmwareLocation>,
    /// Subcomponents with individual versions (from FWPKG)
    subcomponents: Vec<FirmwareSubComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareSubComponent {
    component: String,
    version: String,
    skuid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareLocation {
    location: String,
    location_type: String,
    firmware_type: Option<String>,
}

// Structs for firmware lookup table

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareLookupTable {
    /// Map of device_type -> component_name -> FirmwareLookupEntry
    devices:
        std::collections::HashMap<String, std::collections::HashMap<String, FirmwareLookupEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareLookupEntry {
    /// Path to the downloaded firmware file (relative to firmware_id directory)
    filename: String,
    /// Target identifier for RMS update command
    target: String,
    /// Component name (e.g., "HMC", "BMC")
    component: String,
    /// Bundle identifier (e.g., "P4975", "P4972")
    bundle: String,
    /// Firmware type: "prod" or "dev"
    firmware_type: String,
    /// Version of the firmware bundle
    version: Option<String>,
    /// Subcomponents with individual versions
    subcomponents: Vec<FirmwareSubComponent>,
}

/// Parse rack firmware JSON to extract firmware components
fn parse_rack_firmware_json(config: &Value) -> Result<ParsedFirmwareComponents, String> {
    let board_skus = config
        .get("BoardSKUs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "JSON must contain 'BoardSKUs' array".to_string())?;

    let mut parsed_board_skus = Vec::new();

    for board_sku in board_skus {
        let sku_id = board_sku
            .get("SKUID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let name = board_sku
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let sku_type = board_sku
            .get("Type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Get firmware components (ignore software)
        let firmware_array = board_sku
            .get("Components")
            .and_then(|c| c.get("Firmware"))
            .and_then(|f| f.as_array());

        let mut firmware_components = Vec::new();

        if let Some(firmware_list) = firmware_array {
            for firmware in firmware_list {
                let component = firmware
                    .get("Component")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let bundle = firmware
                    .get("Bundle")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let version = firmware
                    .get("Version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Get firmware type (Prod or Dev)
                let component_type = firmware
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Parse locations
                let empty_vec = vec![];
                let locations_array = firmware
                    .get("Locations")
                    .and_then(|l| l.as_array())
                    .unwrap_or(&empty_vec);

                let mut locations = Vec::new();

                for location in locations_array {
                    let firmware_type = location
                        .get("Type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // Only include locations with Type: "Firmware" (skip Certificate, Misc, etc.)
                    if firmware_type.as_deref() != Some("Firmware") {
                        continue;
                    }

                    let loc = FirmwareLocation {
                        location: location
                            .get("Location")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        location_type: location
                            .get("LocationType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        firmware_type,
                    };
                    locations.push(loc);
                }

                // Parse subcomponents
                let empty_vec = vec![];
                let subcomponents_array = firmware
                    .get("SubComponents")
                    .and_then(|s| s.as_array())
                    .unwrap_or(&empty_vec);

                let mut subcomponents = Vec::new();
                for subcomp in subcomponents_array {
                    let sub_component = subcomp
                        .get("Component")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let sub_version = subcomp
                        .get("Version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let sub_skuid = subcomp
                        .get("SKUID")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if !sub_component.is_empty() && !sub_version.is_empty() {
                        subcomponents.push(FirmwareSubComponent {
                            component: sub_component,
                            version: sub_version,
                            skuid: sub_skuid,
                        });
                    }
                }

                firmware_components.push(FirmwareComponent {
                    component,
                    bundle,
                    version,
                    component_type,
                    locations,
                    subcomponents,
                });
            }
        }

        parsed_board_skus.push(BoardSkuFirmware {
            sku_id,
            name,
            sku_type,
            firmware_components,
        });
    }

    Ok(ParsedFirmwareComponents {
        board_skus: parsed_board_skus,
    })
}

/// Create a new Rack firmware configuration
pub async fn create(
    api: &Api,
    request: Request<RackFirmwareCreateRequest>,
) -> Result<Response<RackFirmware>, Status> {
    let req = request.into_inner();

    // Validate that config_json is valid JSON
    let config: serde_json::Value = serde_json::from_str(&req.config_json)
        .map_err(|e| Status::invalid_argument(format!("Invalid JSON: {}", e)))?;

    // Extract ID from JSON - use "Id" field (UUID)
    let id = config
        .get("Id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Status::invalid_argument("JSON must contain 'Id' field to use as identifier")
        })?
        .to_string();

    // Validate token is provided
    if req.artifactory_token.is_empty() {
        return Err(Status::invalid_argument("Artifactory token is required"));
    }

    // Parse firmware components from the JSON
    let parsed_components = match parse_rack_firmware_json(&config) {
        Ok(parsed) => {
            tracing::info!(
                "Parsed {} board SKUs from rack firmware config {}",
                parsed.board_skus.len(),
                id
            );
            Some(serde_json::to_value(parsed).map_err(|e| {
                Status::internal(format!("Failed to serialize parsed components: {}", e))
            })?)
        }
        Err(e) => {
            tracing::warn!(
                "Failed to parse firmware components from config {}: {}",
                id,
                e
            );
            None
        }
    };

    // Store token in Vault
    tracing::info!("Storing Rack firmware config {} with token in Vault", id);

    api.credential_provider
        .set_credentials(
            &CredentialKey::RackFirmware {
                firmware_id: id.clone(),
            },
            &Credentials::UsernamePassword {
                username: id.clone(),
                password: req.artifactory_token.clone(),
            },
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to store token in Vault: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("begin create", e)))?;

    let db_config = DbRackFirmware::create(&mut txn, &id, config, parsed_components).await?;

    txn.commit()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("commit create", e)))?;

    // Spawn background task to download firmware files
    if let Some(parsed_value) = &db_config.parsed_components {
        // Deserialize back to struct for download task
        if let Ok(parsed_struct) =
            serde_json::from_value::<ParsedFirmwareComponents>(parsed_value.0.clone())
        {
            spawn_firmware_download_task(
                id.clone(),
                parsed_struct,
                api.credential_provider.clone(),
                api.database_connection.clone(),
            );
            tracing::info!(
                firmware_id = %id,
                "Spawned background task to download firmware files"
            );
        }
    }

    Ok(Response::new((&db_config).into()))
}

/// Get a Rack firmware configuration by ID
pub async fn get(
    api: &Api,
    request: Request<RackFirmwareGetRequest>,
) -> Result<Response<RackFirmware>, Status> {
    let req = request.into_inner();

    let db_config = DbRackFirmware::find_by_id(&api.database_connection, &req.id)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new((&db_config).into()))
}

/// List all Rack firmware configurations
pub async fn list(
    api: &Api,
    request: Request<RackFirmwareListRequest>,
) -> Result<Response<RackFirmwareList>, Status> {
    let req = request.into_inner();

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("begin list", e)))?;

    let db_configs = DbRackFirmware::list_all(&mut txn, req.only_available).await?;

    txn.commit()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("commit list", e)))?;

    let configs = db_configs
        .into_iter()
        .map(|db_config| (&db_config).into())
        .collect();

    Ok(Response::new(RackFirmwareList { configs }))
}

/// Delete a Rack firmware configuration
pub async fn delete(
    api: &Api,
    request: Request<RackFirmwareDeleteRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("begin delete", e)))?;

    DbRackFirmware::delete(&mut txn, &req.id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new("commit delete", e)))?;

    Ok(Response::new(()))
}

/// Spawn a background task to download firmware files and mark as available when complete
fn spawn_firmware_download_task(
    firmware_id: String,
    parsed_components: ParsedFirmwareComponents,
    credential_provider: Arc<dyn CredentialProvider>,
    database_connection: sqlx::PgPool,
) {
    tokio::spawn(async move {
        if let Err(e) = download_firmware_files(
            &firmware_id,
            &parsed_components,
            credential_provider,
            &database_connection,
        )
        .await
        {
            tracing::error!(
                firmware_id = %firmware_id,
                error = %e,
                "Failed to download firmware files"
            );
        }
    });
}

/// Download all firmware files for a rack firmware configuration
async fn download_firmware_files(
    firmware_id: &str,
    parsed_components: &ParsedFirmwareComponents,
    credential_provider: Arc<dyn CredentialProvider>,
    database_connection: &sqlx::PgPool,
) -> Result<(), String> {
    // Retrieve token from Vault
    let credentials = credential_provider
        .get_credentials(&CredentialKey::RackFirmware {
            firmware_id: firmware_id.to_string(),
        })
        .await
        .map_err(|e| format!("Failed to get token from Vault: {}", e))?;

    let artifactory_token = match credentials {
        Some(Credentials::UsernamePassword { password, .. }) => password,
        None => "".to_string(), // no credentials for this download
    };

    tracing::info!(
        firmware_id = %firmware_id,
        "Starting firmware download for {} board SKUs",
        parsed_components.board_skus.len()
    );

    // Create firmware cache directory if it doesn't exist
    let firmware_cache_dir = PathBuf::from("/forge-boot-artifacts/blobs/internal/fw")
        .join("rack_firmware")
        .join(firmware_id);
    tokio::fs::create_dir_all(&firmware_cache_dir)
        .await
        .map_err(|e| format!("Failed to create cache directory: {}", e))?;

    // Collect all download tasks
    let mut task_set = JoinSet::new();
    let mut total_locations = 0;

    for board_sku in &parsed_components.board_skus {
        for firmware_component in &board_sku.firmware_components {
            for location in &firmware_component.locations {
                total_locations += 1;

                let url = location.location.clone();
                let location_type = location.location_type.clone();
                let component = firmware_component.component.clone();
                let bundle = firmware_component.bundle.clone();
                let token = artifactory_token.clone();
                let dest_dir = firmware_cache_dir.clone();

                task_set.spawn(async move {
                    download_single_file(url, location_type, component, bundle, token, dest_dir)
                        .await
                });
            }
        }
    }

    tracing::info!(
        firmware_id = %firmware_id,
        total_locations = total_locations,
        "Spawned download tasks for all firmware locations"
    );

    // Wait for all downloads to complete
    let mut successful_downloads = 0;
    let mut failed_downloads = 0;

    while let Some(result) = task_set.join_next().await {
        match result {
            Ok(Ok(_)) => successful_downloads += 1,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Firmware download failed");
                failed_downloads += 1;
            }
            Err(join_error) => {
                tracing::error!(error = %join_error, "Download task panicked");
                failed_downloads += 1;
            }
        }
    }

    tracing::info!(
        firmware_id = %firmware_id,
        successful = successful_downloads,
        failed = failed_downloads,
        total = total_locations,
        "Firmware download completed"
    );

    // Mark firmware as available if all downloads succeeded
    if failed_downloads == 0 {
        // Build firmware lookup table
        let lookup_table = build_firmware_lookup_table(parsed_components);
        let lookup_json = serde_json::to_value(&lookup_table)
            .map_err(|e| format!("Failed to serialize lookup table: {}", e))?;

        tracing::info!(
            firmware_id = %firmware_id,
            device_types = lookup_table.devices.len(),
            "Built firmware lookup table"
        );

        let mut txn = database_connection
            .begin()
            .await
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        // Update parsed_components with the lookup table
        let query = "UPDATE rack_firmware SET parsed_components = $2::jsonb, available = true, updated = NOW() WHERE id = $1";
        sqlx::query(query)
            .bind(firmware_id)
            .bind(sqlx::types::Json(lookup_json))
            .execute(&mut *txn)
            .await
            .map_err(|e| format!("Failed to update firmware lookup table: {}", e))?;

        txn.commit()
            .await
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        tracing::info!(
            firmware_id = %firmware_id,
            "Marked rack firmware as available with lookup table"
        );
    } else {
        tracing::warn!(
            firmware_id = %firmware_id,
            failed = failed_downloads,
            "Firmware not marked as available due to download failures"
        );
    }

    Ok(())
}

/// Known device types based on BoardSKU SKUID patterns
#[derive(Debug, Clone, PartialEq)]
enum DeviceType {
    /// GB200 Compute Tray (P4975 Bianca) - needs HMC and BMC firmware
    /// Also contains Power Shelf firmware that gets extracted separately
    GB200ComputeTray,
    /// Juliet Switch (P4978) - needs switch firmware
    JulietSwitch,
    /// Power Shelf - firmware is included in GB200ComputeTray BoardSKU
    PowerShelf,
    /// Unknown device type
    Unknown,
}

/// Map BoardSKU SKUID to a known device type
fn get_device_type_from_skuid(sku_id: &str) -> DeviceType {
    // GB200 Compute Tray SKUIDs (P4975 Bianca)
    const GB200_COMPUTE_TRAY_SKUIDS: &[&str] = &["699-24764-0001-TS3", "699-24764-0001-TS1"];

    // Juliet Switch SKUIDs (P4978)
    const JULIET_SWITCH_SKUIDS: &[&str] = &[
        "920-9K36F-00MV-QS1",
        "692-9K36F-00MV-JQS",
        "920-9K36F-B4MV-QS1",
        "692-9K36F-B4MV-JD0",
        "920-9K36F-A5MV-QS1",
        "692-9K36F-A5MV-JQS",
        "920-9K36N-00MV-QS1",
        "692-9K36N-00MV-JQS",
        "920-9K36N-09MV-QS1",
        "692-9K36N-09MV-JSO",
    ];

    // The sku_id field may contain multiple comma-separated SKUIDs
    let skuids: Vec<&str> = sku_id.split(',').map(|s| s.trim()).collect();

    for skuid in &skuids {
        if GB200_COMPUTE_TRAY_SKUIDS.contains(skuid) {
            return DeviceType::GB200ComputeTray;
        }
        if JULIET_SWITCH_SKUIDS.contains(skuid) {
            return DeviceType::JulietSwitch;
        }
    }

    DeviceType::Unknown
}

/// Get the firmware components to extract for a given device type
/// Returns: Vec of (component_name_to_match, lookup_key, target)
fn get_firmware_components_for_device_type(
    device_type: &DeviceType,
) -> Vec<(&'static str, &'static str, &'static str)> {
    match device_type {
        DeviceType::GB200ComputeTray => vec![
            // (Component name in JSON, Key in lookup table, Redfish target)
            ("HMC", "HMC", "/redfish/v1/Chassis/HGX_Chassis_0"),
            ("BMC", "BMC", "FW_BMC_0"),
        ],
        DeviceType::JulietSwitch => vec![
            ("BMC+FPGA+EROT", "BMC", "bmc"),
            ("BMC+FPGA+EROT", "FPGA", "fpga"),
            ("BMC+FPGA+EROT", "EROT", "erot"),
            // CPLD — disabled: RMS does not support CPLD updates yet
            // ("CPLD", "CPLD", "cpld"),
            ("SBIOS+EROT", "BIOS", "bios"),
        ],
        DeviceType::PowerShelf => vec![
            // Power Shelf firmware - found in GB200ComputeTray BoardSKU
            // TODO: Confirm correct targets for Power Shelf components
            ("Power Shelf FW", "PowerShelfFW", "TODO_POWERSHELF_TARGET"),
        ],
        DeviceType::Unknown => vec![],
    }
}

/// Build a lookup table mapping device types and components to downloaded firmware files
fn build_firmware_lookup_table(
    parsed_components: &ParsedFirmwareComponents,
) -> FirmwareLookupTable {
    let mut lookup = FirmwareLookupTable {
        devices: std::collections::HashMap::new(),
    };

    for board_sku in &parsed_components.board_skus {
        // Determine device type from SKUID
        let device_type = get_device_type_from_skuid(&board_sku.sku_id);

        if device_type == DeviceType::Unknown {
            tracing::debug!(
                sku_id = %board_sku.sku_id,
                sku_name = %board_sku.name,
                "Unknown device type for BoardSKU, skipping"
            );
            continue;
        }

        // Get the firmware components we need to extract for this device type
        let components_to_extract = get_firmware_components_for_device_type(&device_type);

        // For GB200ComputeTray, also extract Power Shelf firmware
        let power_shelf_components = if device_type == DeviceType::GB200ComputeTray {
            get_firmware_components_for_device_type(&DeviceType::PowerShelf)
        } else {
            vec![]
        };

        let mut device_components = std::collections::HashMap::new();
        let mut power_shelf_device_components = std::collections::HashMap::new();

        for firmware_component in &board_sku.firmware_components {
            let component_name = &firmware_component.component;
            let bundle = firmware_component.bundle.clone().unwrap_or_default();

            // Get firmware type (Prod/Dev), normalize to lowercase
            let fw_type = firmware_component
                .component_type
                .as_ref()
                .map(|t| t.to_lowercase())
                .unwrap_or_else(|| "prod".to_string()); // Default to prod if not specified

            // Check if this component is one we need to extract for the main device type
            for (match_name, lookup_key, target) in &components_to_extract {
                if component_name == *match_name {
                    // Find the firmware location and extract filename
                    for location in &firmware_component.locations {
                        if location.firmware_type.as_deref() == Some("Firmware")
                            && let Some(filename) = location.location.split('/').next_back()
                        {
                            // Use key format: "HMC_prod" or "HMC_dev"
                            let typed_key = format!("{}_{}", lookup_key, fw_type);
                            device_components.insert(
                                typed_key.clone(),
                                FirmwareLookupEntry {
                                    filename: filename.to_string(),
                                    target: target.to_string(),
                                    component: component_name.clone(),
                                    bundle: bundle.clone(),
                                    firmware_type: fw_type.clone(),
                                    version: firmware_component.version.clone(),
                                    subcomponents: firmware_component.subcomponents.clone(),
                                },
                            );
                            tracing::debug!(
                                device_type = ?device_type,
                                component = %component_name,
                                firmware_type = %fw_type,
                                filename = %filename,
                                target = %target,
                                "Added firmware component to lookup table"
                            );
                            break; // Found the file, move to next component
                        }
                    }
                    break; // Found matching component definition
                }
            }

            // Check if this component is Power Shelf firmware (embedded in GB200ComputeTray)
            for (match_name, lookup_key, target) in &power_shelf_components {
                if component_name == *match_name {
                    // Power Shelf FW has subcomponents with firmware locations
                    // For now, just record that we have Power Shelf firmware
                    // TODO: Extract individual subcomponent firmware files
                    let typed_key = format!("{}_{}", lookup_key, fw_type);
                    power_shelf_device_components.insert(
                        typed_key,
                        FirmwareLookupEntry {
                            filename: "".to_string(), // Subcomponents have individual files
                            target: target.to_string(),
                            component: component_name.clone(),
                            bundle: bundle.clone(),
                            firmware_type: fw_type.clone(),
                            version: firmware_component.version.clone(),
                            subcomponents: firmware_component.subcomponents.clone(),
                        },
                    );
                    tracing::debug!(
                        component = %component_name,
                        target = %target,
                        "Added Power Shelf firmware component to lookup table"
                    );
                    break;
                }
            }
        }

        if !device_components.is_empty() {
            // Use a consistent device type key for the lookup table
            let device_key = match device_type {
                DeviceType::GB200ComputeTray => "Compute Node",
                DeviceType::JulietSwitch => "Switch Tray",
                DeviceType::PowerShelf => "Power Shelf",
                DeviceType::Unknown => continue,
            };
            lookup
                .devices
                .insert(device_key.to_string(), device_components);
        }

        // Insert Power Shelf components if found
        if !power_shelf_device_components.is_empty() {
            lookup
                .devices
                .insert("Power Shelf".to_string(), power_shelf_device_components);
        }
    }

    lookup
}

/// Download a single firmware file
async fn download_single_file(
    url: String,
    location_type: String,
    component: String,
    bundle: Option<String>,
    token: String,
    dest_dir: PathBuf,
) -> Result<(), String> {
    // Extract filename from URL
    let filename = url
        .split('/')
        .next_back()
        .ok_or_else(|| format!("Invalid URL: {}", url))?;

    let dest_path = dest_dir.join(filename);

    // Skip if file already exists
    if dest_path.exists() {
        tracing::debug!(
            component = %component,
            filename = %filename,
            "File already cached, skipping download"
        );
        return Ok(());
    }

    tracing::info!(
        component = %component,
        bundle = ?bundle,
        url = %url,
        location_type = %location_type,
        "Downloading firmware file"
    );

    // Build HTTP client
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(600)) // 10 minutes for large files
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Try downloading without token first
    let response = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
            tracing::debug!(
                url = %url,
                "Authentication required, retrying with token"
            );

            // Retry with token
            client
                .get(&url)
                .header("X-JFrog-Art-Api", &token)
                .send()
                .await
                .map_err(|e| format!("Failed to download with token: {}", e))?
        }
        Ok(resp) => {
            return Err(format!(
                "Download failed with status {}: {}",
                resp.status(),
                url
            ));
        }
        Err(e) => {
            tracing::debug!(
                url = %url,
                error = %e,
                "Download without token failed, retrying with token"
            );

            // Try with token on any error
            client
                .get(&url)
                .header("X-JFrog-Art-Api", &token)
                .send()
                .await
                .map_err(|e| format!("Failed to download with token: {}", e))?
        }
    };

    // Check if response is successful
    if !response.status().is_success() {
        return Err(format!(
            "Download failed with status {}: {}",
            response.status(),
            url
        ));
    }

    // Download file content
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Write to file
    tokio::fs::write(&dest_path, bytes)
        .await
        .map_err(|e| format!("Failed to write file {}: {}", dest_path.display(), e))?;

    tracing::info!(
        component = %component,
        filename = %filename,
        path = %dest_path.display(),
        "Successfully downloaded firmware file"
    );

    Ok(())
}

/// Apply firmware to all devices in a rack
pub async fn apply(
    api: &Api,
    request: Request<RackFirmwareApplyRequest>,
) -> Result<Response<RackFirmwareApplyResponse>, Status> {
    let req = request.into_inner();
    let rack_id = req
        .rack_id
        .ok_or_else(|| Status::invalid_argument("rack_id is required"))?;

    tracing::info!(
        rack_id = %rack_id,
        firmware_id = %req.firmware_id,
        firmware_type = %req.firmware_type,
        "Starting firmware apply operation"
    );

    // Get the RackFirmware configuration from the database
    let fw_config = DbRackFirmware::find_by_id(&api.database_connection, &req.firmware_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get firmware configuration: {}", e)))?;

    if !fw_config.available {
        return Err(Status::failed_precondition(format!(
            "Firmware configuration '{}' is not marked as available",
            req.firmware_id
        )));
    }

    let parsed_components: serde_json::Value = fw_config
        .parsed_components
        .as_ref()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| {
            tracing::warn!("No parsed_components in firmware config, using empty object");
            serde_json::json!({})
        });

    let rack = db::rack::get(&api.database_connection, rack_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get rack: {}", e)))?;

    // Convert rack to proto to get device IDs
    let rack_proto: rpc::forge::Rack = rack.into();

    let has_compute_trays = !rack_proto.compute_trays.is_empty();
    let has_power_shelves = !rack_proto.power_shelves.is_empty();
    let has_switches = !rack_proto.expected_nvlink_switches.is_empty();

    if !has_compute_trays && !has_power_shelves && !has_switches {
        return Err(Status::failed_precondition(format!(
            "Rack '{}' contains no devices",
            rack_id
        )));
    }

    tracing::info!(
        rack_id = %rack_id,
        compute_trays = rack_proto.compute_trays.len(),
        power_shelves = rack_proto.power_shelves.len(),
        switches = rack_proto.expected_nvlink_switches.len(),
        "Found devices in rack"
    );

    // Each device type is updated via a single update_firmware_by_node_type_async
    // call — RMS handles distributing to all nodes of that type in the rack.
    let mut device_results = Vec::new();
    let mut successful_updates = 0;
    let mut failed_updates = 0;

    // Device types to update: (lookup_table_key, RMS NodeType, display_name, has_devices, activate)
    // activate=true for compute trays (Redfish activation after flash).
    // activate=false for switches (activation is handled internally via power cycle).
    let device_types: &[(&str, i32, &str, bool, bool)] = &[
        (
            "Compute Node",
            librms::protos::rack_manager::NodeType::Compute as i32,
            "Compute Node",
            has_compute_trays,
            true,
        ),
        (
            "Power Shelf",
            librms::protos::rack_manager::NodeType::Powershelf as i32,
            "Power Shelf",
            has_power_shelves,
            false,
        ),
        (
            "Switch Tray",
            librms::protos::rack_manager::NodeType::Switch as i32,
            "Switch",
            has_switches,
            false,
        ),
    ];

    for &(lookup_key, node_type, display_name, has_devices, activate) in device_types {
        if !has_devices {
            continue;
        }

        let mut firmware_components =
            find_firmware_components_for_device(&parsed_components, lookup_key, &req.firmware_type);

        // Sort components into the required flashing order for this device type
        let flash_order = get_firmware_flash_order(lookup_key);
        firmware_components.sort_by_key(|(_, _, target)| {
            flash_order
                .iter()
                .position(|&t| t == target.as_str())
                .unwrap_or(usize::MAX)
        });

        if firmware_components.is_empty() {
            tracing::warn!(
                rack_id = %rack_id,
                device_type = %display_name,
                "No matching firmware found in config"
            );
            device_results.push(DeviceUpdateResult {
                device_id: rack_id.to_string(),
                device_type: display_name.to_string(),
                success: false,
                message: format!("No matching firmware found in config for {}", display_name),
                job_id: String::new(),
                node_jobs: vec![],
            });
            failed_updates += 1;
            continue;
        }

        let Some(rms_client) = &api.rms_client else {
            tracing::warn!(
                rack_id = %rack_id,
                device_type = %display_name,
                "RMS client not configured, cannot update firmware"
            );
            device_results.push(DeviceUpdateResult {
                device_id: rack_id.to_string(),
                device_type: display_name.to_string(),
                success: false,
                message: "RMS client not configured".to_string(),
                job_id: String::new(),
                node_jobs: vec![],
            });
            failed_updates += 1;
            continue;
        };

        // Build FirmwareTarget entries from the lookup table
        let firmware_targets: Vec<librms::protos::rack_manager::FirmwareTarget> =
            firmware_components
                .iter()
                .map(|(_component_name, filename, target)| {
                    let full_firmware_path = format!(
                        "/forge-boot-artifacts/blobs/internal/fw/rack_firmware/{}/{}",
                        req.firmware_id, filename
                    );
                    librms::protos::rack_manager::FirmwareTarget {
                        target: target.clone(),
                        filename: full_firmware_path,
                    }
                })
                .collect();

        tracing::info!(
            rack_id = %rack_id,
            device_type = %display_name,
            firmware_target_count = firmware_targets.len(),
            targets = ?firmware_targets.iter().map(|t| &t.target).collect::<Vec<_>>(),
            "Applying firmware via async batch API"
        );

        let rms_request = librms::protos::rack_manager::UpdateFirmwareByNodeTypeRequest {
            metadata: None,
            node_type,
            filename: String::new(),
            target: String::new(),
            rack_id: rack_id.to_string(),
            firmware_targets,
            activate,
        };

        match rms_client
            .update_firmware_by_node_type_async(rms_request)
            .await
        {
            Ok(response) => {
                let success =
                    response.status == librms::protos::rack_manager::ReturnCode::Success as i32;

                if success {
                    successful_updates += 1;
                } else {
                    failed_updates += 1;
                }

                let node_jobs: Vec<NodeJobInfo> = response
                    .node_jobs
                    .iter()
                    .map(|j| NodeJobInfo {
                        node_id: j.node_id.clone(),
                        job_id: j.job_id.clone(),
                    })
                    .collect();

                for node_job in &response.node_jobs {
                    tracing::info!(
                        device_type = %display_name,
                        node_id = %node_job.node_id,
                        job_id = %node_job.job_id,
                        "Firmware update job created"
                    );
                }

                device_results.push(DeviceUpdateResult {
                    device_id: rack_id.to_string(),
                    device_type: display_name.to_string(),
                    success,
                    message: format!(
                        "Async firmware update initiated for {} nodes: {}",
                        response.total_nodes, response.message
                    ),
                    job_id: response.job_id,
                    node_jobs,
                });
            }
            Err(e) => {
                tracing::warn!(
                    rack_id = %rack_id,
                    device_type = %display_name,
                    error = %e,
                    "Failed to initiate async firmware update"
                );
                device_results.push(DeviceUpdateResult {
                    device_id: rack_id.to_string(),
                    device_type: display_name.to_string(),
                    success: false,
                    message: format!("RMS API Error: {}", e),
                    job_id: String::new(),
                    node_jobs: vec![],
                });
                failed_updates += 1;
            }
        }
    }

    tracing::info!(
        rack_id = %rack_id,
        firmware_id = %req.firmware_id,
        successful = successful_updates,
        failed = failed_updates,
        total = device_results.len(),
        "Firmware apply operation completed"
    );

    Ok(Response::new(RackFirmwareApplyResponse {
        total_updates: device_results.len() as i32,
        successful_updates,
        failed_updates,
        device_results,
    }))
}

fn get_firmware_flash_order(device_type_key: &str) -> &'static [&'static str] {
    match device_type_key {
        "Switch Tray" => &["bmc", "fpga", "erot", "bios"],
        "Compute Node" => &["/redfish/v1/Chassis/HGX_Chassis_0", "FW_BMC_0"],
        _ => &[],
    }
}

/// Helper function to find all firmware components for a specific device type using the lookup table
/// Returns a vector of (component_name, filename, target) tuples
/// Only returns components matching the requested firmware_type (prod or dev)
fn find_firmware_components_for_device(
    parsed_components: &serde_json::Value,
    hardware_type: &str,
    firmware_type: &str, // "prod" or "dev"
) -> Vec<(String, String, String)> {
    let mut results = Vec::new();

    // Try to parse as FirmwareLookupTable
    let lookup_table: FirmwareLookupTable =
        match serde_json::from_value::<FirmwareLookupTable>(parsed_components.clone()) {
            Ok(table) => {
                tracing::debug!(
                    device_count = table.devices.len(),
                    "Successfully parsed firmware lookup table"
                );
                table
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    raw_json = %parsed_components,
                    "Failed to parse firmware lookup table, no firmware will be applied"
                );
                return results;
            }
        };

    // Normalize firmware type to lowercase
    let fw_type = firmware_type.to_lowercase();

    let available_device_types: Vec<&String> = lookup_table.devices.keys().collect();
    tracing::debug!(
        available_device_types = ?available_device_types,
        requested_hardware_type = %hardware_type,
        requested_firmware_type = %fw_type,
        "Looking up firmware components in lookup table"
    );

    // Look up the device type in the lookup table
    if let Some(device_components) = lookup_table.devices.get(hardware_type) {
        for (component_key, entry) in device_components {
            // Only include components matching the requested firmware type
            // Keys are formatted as "HMC_prod" or "HMC_dev"
            if entry.firmware_type.to_lowercase() != fw_type {
                tracing::debug!(
                    hardware_type = %hardware_type,
                    component = %component_key,
                    entry_type = %entry.firmware_type,
                    requested_type = %fw_type,
                    "Skipping firmware component - type mismatch"
                );
                continue;
            }

            tracing::debug!(
                hardware_type = %hardware_type,
                component = %component_key,
                firmware_type = %entry.firmware_type,
                filename = %entry.filename,
                target = %entry.target,
                "Found matching firmware component in lookup table"
            );

            results.push((
                component_key.clone(),
                entry.filename.clone(),
                entry.target.clone(),
            ));
        }
    } else {
        tracing::debug!(
            hardware_type = %hardware_type,
            "No firmware components found for device type in lookup table"
        );
    }

    results
}

/// Get the status of an async firmware update job by proxying to RMS GetFirmwareJobStatus
pub async fn get_job_status(
    api: &Api,
    request: Request<RackFirmwareJobStatusRequest>,
) -> Result<Response<RackFirmwareJobStatusResponse>, Status> {
    let req = request.into_inner();

    if req.job_id.is_empty() {
        return Err(Status::invalid_argument("job_id is required"));
    }

    let rms_client = api
        .rms_client
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("RMS client not configured"))?;

    let rms_request = librms::protos::rack_manager::GetFirmwareJobStatusRequest {
        metadata: None,
        job_id: req.job_id.clone(),
    };

    let rms_response = rms_client
        .get_firmware_job_status(rms_request)
        .await
        .map_err(|e| Status::internal(format!("RMS API error: {}", e)))?;

    // Map FirmwareJobState enum to human-readable string
    let state = match rms_response.job_state {
        0 => "QUEUED",
        1 => "RUNNING",
        2 => "COMPLETED",
        3 => "FAILED",
        _ => "UNKNOWN",
    };

    Ok(Response::new(RackFirmwareJobStatusResponse {
        job_id: rms_response.job_id,
        state: state.to_string(),
        state_description: rms_response.state_description,
        rack_id: rms_response.rack_id,
        node_id: rms_response.node_id,
        error_message: rms_response.error_message,
        result_json: rms_response.result_json,
    }))
}
