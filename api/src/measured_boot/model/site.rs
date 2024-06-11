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

use crate::measured_boot::dto::records::{
    MeasurementBundleRecord, MeasurementBundleValueRecord, MeasurementSystemProfileAttrRecord,
    MeasurementSystemProfileRecord,
};
use crate::measured_boot::interface::bundle::{
    get_measurement_bundle_records, get_measurement_bundles_values,
};
use crate::measured_boot::interface::bundle::{
    import_measurement_bundles, import_measurement_bundles_values,
};
use crate::measured_boot::interface::common::ToTable;
use crate::measured_boot::interface::profile::{
    export_measurement_profile_records, export_measurement_system_profiles_attrs,
};
use crate::measured_boot::interface::profile::{
    import_measurement_system_profiles, import_measurement_system_profiles_attrs,
};
use rpc::protos::measured_boot::{ImportSiteMeasurementsResponse, SiteModelPb};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};

#[derive(Serialize)]
pub struct ImportResult {
    pub status: String,
}

impl From<&ImportSiteMeasurementsResponse> for ImportResult {
    fn from(msg: &ImportSiteMeasurementsResponse) -> Self {
        Self {
            status: msg.result().as_str_name().to_string(),
        }
    }
}

impl ToTable for ImportResult {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["status", self.status]);
        Ok(table.to_string())
    }
}

/// SiteModel represents everything that is imported/exported
/// for an entire site.
#[derive(Serialize, Deserialize)]
pub struct SiteModel {
    pub measurement_system_profiles: Vec<MeasurementSystemProfileRecord>,
    pub measurement_system_profiles_attrs: Vec<MeasurementSystemProfileAttrRecord>,
    pub measurement_bundles: Vec<MeasurementBundleRecord>,
    pub measurement_bundles_values: Vec<MeasurementBundleValueRecord>,
}

impl ToTable for SiteModel {
    fn to_table(&self) -> eyre::Result<String> {
        Ok("lol, not implemented for SiteModel. try -o json or -o yaml.".to_string())
    }
}

impl SiteModel {
    /// import takes a populated SiteModel and imports it by
    /// populating the corresponding profile and bundle records
    /// in the database.
    pub async fn import(
        txn: &mut Transaction<'_, Postgres>,
        model: &SiteModel,
    ) -> eyre::Result<()> {
        import_measurement_system_profiles(txn, &model.measurement_system_profiles).await?;
        import_measurement_system_profiles_attrs(txn, &model.measurement_system_profiles_attrs)
            .await?;
        import_measurement_bundles(txn, &model.measurement_bundles).await?;
        import_measurement_bundles_values(txn, &model.measurement_bundles_values).await?;
        Ok(())
    }

    /// export builds a SiteModel from the records in the database.
    pub async fn export(txn: &mut Transaction<'_, Postgres>) -> eyre::Result<Self> {
        let measurement_system_profiles = export_measurement_profile_records(txn).await?;
        let measurement_system_profiles_attrs =
            export_measurement_system_profiles_attrs(txn).await?;
        let measurement_bundles = get_measurement_bundle_records(txn).await?;
        let measurement_bundles_values = get_measurement_bundles_values(txn).await?;

        Ok(Self {
            measurement_system_profiles,
            measurement_system_profiles_attrs,
            measurement_bundles,
            measurement_bundles_values,
        })
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&SiteModelPb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("model is unexpectedly empty"))
            .and_then(|pb| {
                Self::from_pb(pb)
                    .map_err(|e| eyre::eyre!("site failed pb->model conversion: {}", e))
            })
    }

    /// from_pb takes a SiteModelPb and converts it to a SiteModel,
    /// generally for the purpose of importing it into the database.
    pub fn from_pb(model: &SiteModelPb) -> eyre::Result<Self> {
        Ok(Self {
            measurement_system_profiles: MeasurementSystemProfileRecord::from_pb_vec(
                &model.measurement_system_profiles,
            )?,
            measurement_system_profiles_attrs: MeasurementSystemProfileAttrRecord::from_pb_vec(
                &model.measurement_system_profiles_attrs,
            )?,
            measurement_bundles: MeasurementBundleRecord::from_pb_vec(&model.measurement_bundles)?,
            measurement_bundles_values: MeasurementBundleValueRecord::from_pb_vec(
                &model.measurement_bundles_values,
            )?,
        })
    }

    /// to_pb takes a SiteModel and converts it to a SiteModelPb,
    /// generally for the purpose of handling a gRPC response.
    pub fn to_pb(model: &SiteModel) -> eyre::Result<SiteModelPb> {
        let measurement_system_profiles = model
            .measurement_system_profiles
            .iter()
            .map(|record| record.clone().into())
            .collect();

        let measurement_system_profiles_attrs = model
            .measurement_system_profiles_attrs
            .iter()
            .map(|record| record.clone().into())
            .collect();

        let measurement_bundles = model
            .measurement_bundles
            .iter()
            .map(|record| record.clone().into())
            .collect();

        let measurement_bundles_values = model
            .measurement_bundles_values
            .iter()
            .map(|record| record.clone().into())
            .collect();

        Ok(SiteModelPb {
            measurement_system_profiles,
            measurement_system_profiles_attrs,
            measurement_bundles,
            measurement_bundles_values,
        })
    }
}
