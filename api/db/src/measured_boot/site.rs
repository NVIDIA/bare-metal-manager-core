/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/*!
 *  Code for working the measurement_trusted_machines and measurement_trusted_profiles
 *  tables in the database, leveraging the site-specific record types.
 *
 * This also provides code for importing/exporting (and working with) SiteModels.
*/

use measured_boot::site::SiteModel;
use sqlx::PgConnection;

use crate::DatabaseResult;
use crate::measured_boot::interface::bundle::{
    get_measurement_bundle_records, get_measurement_bundles_values, import_measurement_bundles,
    import_measurement_bundles_values,
};
use crate::measured_boot::interface::profile::{
    export_measurement_profile_records, export_measurement_system_profiles_attrs,
    import_measurement_system_profiles, import_measurement_system_profiles_attrs,
};

/// import takes a populated SiteModel and imports it by
/// populating the corresponding profile and bundle records
/// in the database.
pub async fn import(txn: &mut PgConnection, model: &SiteModel) -> DatabaseResult<()> {
    import_measurement_system_profiles(txn, &model.measurement_system_profiles).await?;
    import_measurement_system_profiles_attrs(txn, &model.measurement_system_profiles_attrs).await?;
    import_measurement_bundles(txn, &model.measurement_bundles).await?;
    import_measurement_bundles_values(txn, &model.measurement_bundles_values).await?;
    Ok(())
}

/// export builds a SiteModel from the records in the database.
pub async fn export(txn: &mut PgConnection) -> DatabaseResult<SiteModel> {
    let measurement_system_profiles = export_measurement_profile_records(txn).await?;
    let measurement_system_profiles_attrs = export_measurement_system_profiles_attrs(txn).await?;
    let measurement_bundles = get_measurement_bundle_records(txn).await?;
    let measurement_bundles_values = get_measurement_bundles_values(txn).await?;

    Ok(SiteModel {
        measurement_system_profiles,
        measurement_system_profiles_attrs,
        measurement_bundles,
        measurement_bundles_values,
    })
}
