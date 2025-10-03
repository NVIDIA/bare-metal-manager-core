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
use crate::cfg::file::{Firmware, FirmwareConfig};
use crate::model::desired_firmware::DesiredFirmwareVersions;
use sqlx::PgConnection;

/// snapshot_desired_firmware will replace the desired_firmware table with one matching the given FirmwareConfig
pub async fn snapshot_desired_firmware(
    txn: &mut PgConnection,
    cfg: &FirmwareConfig,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM desired_firmware";
    sqlx::query(query)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    for (_, model) in cfg.map() {
        snapshot_desired_firmware_for_model(&mut *txn, &model).await?;
    }

    Ok(())
}

async fn snapshot_desired_firmware_for_model(
    txn: &mut PgConnection,
    model: &Firmware,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO desired_firmware (vendor, model, versions, explicit_update_start_needed) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING";

    let mut model = model.clone();
    model.components = model
        .components
        .iter()
        .filter_map(|(k, v)| {
            if v.known_firmware.is_empty() {
                None
            } else {
                Some((*k, v.clone()))
            }
        })
        .collect();
    if model.components.is_empty() {
        // Nothing is defined - do not add to the table.
        return Ok(());
    }

    sqlx::query(query)
        .bind(model.vendor.to_pascalcase())
        .bind(model.model.clone())
        .bind(sqlx::types::Json(DesiredFirmwareVersions::from(
            model.clone(),
        )))
        .bind(model.explicit_start_needed)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
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
    use std::ops::DerefMut;
    let mut config: FirmwareConfig = Default::default();

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
    config.add_test_override(src_cfg_str.to_string());

    // And empty ones to test that we don't add these to desired firmware
    let src_cfg_str = r#"
vendor = "Hpe"
model = "ProLiant DL385 Gen10 Plus v2"
[components.bmc]
current_version_reported_as = "^1$"
[components.uefi]
current_version_reported_as = "^2$"
"#;
    config.add_test_override(src_cfg_str.to_string());
    let src_cfg_str = r#"
vendor = "Hpe"
model = "ProLiant DL380a Gen11"
[components.bmc]
current_version_reported_as = "^1$"
[components.uefi]
current_version_reported_as = "^2$"
"#;
    config.add_test_override(src_cfg_str.to_string());

    println!("{config:?}");
    let mut txn = pool.begin().await?;
    snapshot_desired_firmware(&mut txn, &config).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let query =
        r#"SELECT versions->>'Versions' AS versions FROM desired_firmware WHERE vendor = 'Dell';"#;

    let versions_all: Vec<AsStrings> = sqlx::query_as(query).fetch_all(txn.deref_mut()).await?;
    let versions = versions_all.first().unwrap().versions.clone();

    let expected = r#"{"bmc": "7.10.30.00", "cec": "8.10.30.00", "uefi": "1.13.3"}"#;

    assert_eq!(expected, versions);

    let query = r#"SELECT COUNT(1) FROM desired_firmware;"#;
    let count: (i64,) = sqlx::query_as(query).fetch_one(txn.deref_mut()).await?;
    assert_eq!(count, (1,));

    Ok(())
}
