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
use crate::cfg::file::{Firmware, FirmwareComponentType, FirmwareConfig};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::{collections::HashMap, default::Default, ops::DerefMut};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct DbDesiredFirmwareVersions {
    /// Parsed versions, serializtion override means it will always be sorted
    #[serde(default, serialize_with = "utils::ordered_map")]
    pub versions: HashMap<FirmwareComponentType, String>,
}

/// snapshot_desired_firmware will replace the desired_firmware table with one matching the given FirmwareConfig
pub async fn snapshot_desired_firmware(
    txn: &mut Transaction<'_, Postgres>,
    cfg: &FirmwareConfig,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM desired_firmware";
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
    let query = "INSERT INTO desired_firmware (vendor, model, versions) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";

    sqlx::query(query)
        .bind(model.vendor.to_pascalcase())
        .bind(model.model.clone())
        .bind(sqlx::types::Json(&build_versions(model)))
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

fn build_versions(model: &Firmware) -> DbDesiredFirmwareVersions {
    // Using a BTreeMap instead of a hash means that this will be sorted by the key
    let mut versions: DbDesiredFirmwareVersions = Default::default();
    for (component_type, component) in &model.components {
        for firmware in &component.known_firmware {
            if firmware.default {
                versions
                    .versions
                    .insert(*component_type, firmware.version.clone());
                break;
            }
        }
    }
    versions
}

#[cfg(test)]
use sqlx::FromRow;

#[cfg(test)]
#[derive(FromRow)]
struct AsStrings {
    pub versions: String,
}

#[cfg(test)]
#[crate::sqlx_test]
pub async fn test_build_versions(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
    // Source config is hacky, but we just need to have 3 different components in unsorted order
    let src_cfg_str = r#"
    model = "PowerEdge R750"
    vendor = "Dell"

    [components.uefi]
    current_version_reported_as = "^Installed-.*__BIOS.Setup."
    preingest_upgrade_when_below = "1.13.3"

    [[components.uefi.known_firmware]]
    version = "1.13.3"
    url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/BIOS_T3H20_WN64_1.13.2.EXE"
    default = true

    [components.bmc]
    current_version_reported_as = "^Installed-.*__iDRAC."

    [[components.bmc.known_firmware]]
    version = "7.10.30.00"
    url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A00.EXE"
    default = true


    [components.cec]
    current_version_reported_as = "^Installed-.*__iDRAC."

    [[components.cec.known_firmware]]
    version = "8.10.30.00"
    url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A00.EXE"
    default = true
        "#;
    let mut config: FirmwareConfig = Default::default();
    config.add_test_override(src_cfg_str.to_string());

    println!("{config:?}");
    let mut txn = pool.begin().await?;
    snapshot_desired_firmware(&mut txn, &config).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let query = r#"SELECT versions->>'Versions' AS versions FROM desired_firmware;"#;

    let versions_all: Vec<AsStrings> = sqlx::query_as(query).fetch_all(txn.deref_mut()).await?;
    let versions = versions_all.first().unwrap().versions.clone();

    let expected = r#"{"bmc": "7.10.30.00", "cec": "8.10.30.00", "uefi": "1.13.3"}"#;

    assert_eq!(expected, versions);
    Ok(())
}
