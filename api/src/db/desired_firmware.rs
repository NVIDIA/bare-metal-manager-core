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

use super::DatabaseError;
use crate::cfg::{Firmware, FirmwareConfig};
use sqlx::{Postgres, Transaction};
use std::{collections::BTreeMap, ops::DerefMut};

/// snapshot_desired_firmware will replace the desired_firmware table with one matching the given FirmwareConfig
pub async fn snapshot_desired_firmware(
    txn: &mut Transaction<'_, Postgres>,
    cfg: &FirmwareConfig,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM desired_firmware;";
    sqlx::query(query)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    for (_, model) in cfg.map() {
        snapshot_desired_firmware_for_model(txn, &model).await?;
    }

    Ok(())
}

async fn snapshot_desired_firmware_for_model(
    txn: &mut Transaction<'_, Postgres>,
    model: &Firmware,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO desired_firmware (vendor, model, versions) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;";

    let Ok(versions) = build_versions(model) else {
        tracing::error!("Bad serialize {:?}", model.components);
        return Ok(());
    };

    sqlx::query(query)
        .bind(model.vendor.to_pascalcase())
        .bind(model.model.clone())
        .bind(versions)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

fn build_versions(model: &Firmware) -> Result<String, serde_json::Error> {
    // Using a BTreeMap instead of a hash means that this will be sorted by the key
    let mut versions = BTreeMap::new();
    for (component_type, component) in &model.components {
        for firmware in &component.known_firmware {
            if firmware.default {
                versions.insert(component_type, firmware.version.clone());
                break;
            }
        }
    }
    serde_json::to_string(&versions)
}

#[cfg(test)]
mod test {
    use crate::{
        cfg::{Firmware, FirmwareComponent, FirmwareComponentType, FirmwareEntry},
        db::desired_firmware::build_versions,
    };
    use std::collections::HashMap;

    #[test]
    fn test_build_versions() -> Result<(), serde_json::Error> {
        let mut fw = Firmware {
            vendor: bmc_vendor::BMCVendor::Unknown,
            model: "T".to_string(),
            ordering: vec![],
            components: HashMap::default(),
        };
        let known = FirmwareEntry {
            version: "1.0".to_string(),
            mandatory_upgrade_from_priority: None,
            default: true,
            filename: None,
            url: None,
            checksum: None,
        };
        let component = FirmwareComponent {
            current_version_reported_as: None,
            preingest_upgrade_when_below: None,
            known_firmware: vec![known],
        };
        fw.components
            .insert(FirmwareComponentType::Cec, component.clone());
        fw.components
            .insert(FirmwareComponentType::Uefi, component.clone());
        fw.components
            .insert(FirmwareComponentType::Bmc, component.clone());
        let expected = r#"{"bmc":"1.0","cec":"1.0","uefi":"1.0"}"#;
        assert_eq!(build_versions(&fw)?, expected);
        Ok(())
    }
}
