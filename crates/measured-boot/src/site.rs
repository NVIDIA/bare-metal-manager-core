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

use std::convert::{From, Into};
use std::str::FromStr;
use std::vec::Vec;

use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementBundleId;
use chrono::Utc;
#[cfg(feature = "cli")]
use rpc::admin_cli::ToTable;
use rpc::protos::measured_boot::{
    ImportSiteMeasurementsResponse, ListAttestationSummaryResponse, MachineAttestationSummaryPb,
    SiteModelPb,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;

use super::records::{
    MeasurementBundleRecord, MeasurementBundleValueRecord, MeasurementSystemProfileAttrRecord,
    MeasurementSystemProfileRecord,
};

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

#[cfg(feature = "cli")]
impl ToTable for ImportResult {
    fn into_table(self) -> eyre::Result<String> {
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

#[cfg(feature = "cli")]
impl ToTable for SiteModel {
    fn into_table(self) -> eyre::Result<String> {
        Ok("lol, not implemented for SiteModel. try -o json or -o yaml.".to_string())
    }
}

impl SiteModel {
    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&SiteModelPb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(
                "model is unexpectedly empty".to_string(),
            ))
            .and_then(|pb| {
                Self::from_pb(pb).map_err(|e| {
                    super::Error::RpcConversion(format!("site failed pb->model conversion: {e}"))
                })
            })
    }

    /// from_pb takes a SiteModelPb and converts it to a SiteModel,
    /// generally for the purpose of importing it into the database.
    pub fn from_pb(model: &SiteModelPb) -> super::Result<Self> {
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
    pub fn to_pb(model: &SiteModel) -> super::Result<SiteModelPb> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MachineAttestationSummary {
    pub machine_id: MachineId,
    pub bundle_id: Option<MeasurementBundleId>,
    #[cfg_attr(feature = "sqlx", sqlx(rename = "name"))]
    pub profile_name: String,
    pub ts: chrono::DateTime<Utc>,
}

pub struct MachineAttestationSummaryList(pub Vec<MachineAttestationSummary>);

// we need methods to convert this to gRPC messages and back
impl From<MachineAttestationSummaryList> for ListAttestationSummaryResponse {
    fn from(val: MachineAttestationSummaryList) -> Self {
        MachineAttestationSummaryList::to_grpc(&val.0)
    }
}

impl MachineAttestationSummaryList {
    pub fn to_grpc(val: &[MachineAttestationSummary]) -> ListAttestationSummaryResponse {
        ListAttestationSummaryResponse {
            attestation_outcomes: val
                .iter()
                .map(|e| MachineAttestationSummaryPb {
                    machine_id: e.machine_id.to_string(),
                    bundle_id: if e.bundle_id.is_none() {
                        None
                    } else {
                        Some(e.bundle_id.unwrap())
                    },
                    profile_name: e.profile_name.clone(),
                    ts: Some(e.ts.into()),
                })
                .collect(),
        }
    }

    pub fn from_grpc(val: &ListAttestationSummaryResponse) -> super::Result<Self> {
        let mut attestation_summary_list = Vec::<MachineAttestationSummary>::new();

        for pb in &val.attestation_outcomes {
            attestation_summary_list.push(MachineAttestationSummary {
                machine_id: MachineId::from_str(&pb.machine_id).map_err(|err| {
                    super::Error::RpcConversion(format!(
                        "Could not deserialize ListAttestationSummaryResponse(machine_id): {err}"
                    ))
                })?,
                bundle_id: pb.bundle_id,
                profile_name: pb.profile_name.clone(),
                ts: if pb.ts.is_none() {
                    chrono::DateTime::<Utc>::default()
                } else {
                    chrono::DateTime::<Utc>::try_from(pb.ts.unwrap()).map_err(|err| {
                        super::Error::RpcConversion(format!(
                            "Could not deserialize ListAttestationSummaryResponse(timestamp): {err}"
                        ))
                    })?
                },
            });
        }

        Ok(Self(attestation_summary_list))
    }
}
