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
 *  Code for working the measurement_system_profiles and measurement_system_profiles_attrs
 *  tables in the database, leveraging the profile-specific record types.
*/

use std::convert::{Into, TryFrom};

use carbide_uuid::measured_boot::MeasurementSystemProfileId;
use chrono::{DateTime, Utc};
#[cfg(feature = "cli")]
use rpc::admin_cli::ToTable;
use rpc::protos::measured_boot::MeasurementSystemProfilePb;
use serde::Serialize;

use super::records::MeasurementSystemProfileAttrRecord;

/// MeasurementSystemProfile is a composition of a MeasurementSystemProfileRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementSystemProfileAttrRecord, along with its UUID and timestamp).
///
/// Included are ToTable implementations, which are used by the CLI for
/// doing prettytable-formatted output.
#[derive(Debug, Serialize)]
pub struct MeasurementSystemProfile {
    pub profile_id: MeasurementSystemProfileId,
    pub name: String,
    pub ts: chrono::DateTime<Utc>,
    pub attrs: Vec<MeasurementSystemProfileAttrRecord>,
}

impl MeasurementSystemProfile {
    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&MeasurementSystemProfilePb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(
                "profile is unexpectedly empty".to_string(),
            ))
            .and_then(|pb| {
                Self::try_from(pb.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!("profile failed pb->model conversion: {e}"))
                })
            })
    }
}

impl From<MeasurementSystemProfile> for MeasurementSystemProfilePb {
    fn from(val: MeasurementSystemProfile) -> Self {
        Self {
            profile_id: Some(val.profile_id),
            name: val.name,
            ts: Some(val.ts.into()),
            attrs: val.attrs.iter().map(|attr| attr.clone().into()).collect(),
        }
    }
}

impl TryFrom<MeasurementSystemProfilePb> for MeasurementSystemProfile {
    type Error = super::Error;

    fn try_from(msg: MeasurementSystemProfilePb) -> super::Result<Self> {
        let attrs: super::Result<Vec<MeasurementSystemProfileAttrRecord>> = msg
            .attrs
            .iter()
            .map(
                |attr| match MeasurementSystemProfileAttrRecord::try_from(attr.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(super::Error::RpcConversion(format!(
                        "attr conversion failed: {failed}"
                    ))),
                },
            )
            .collect();

        Ok(Self {
            profile_id: msg.profile_id.ok_or(super::Error::RpcConversion(
                "missing profile_id".to_string(),
            ))?,
            name: msg.name.clone(),
            attrs: attrs?,
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())
                .map_err(|e| super::Error::RpcConversion(e.to_string()))?,
        })
    }
}

// When `profile show <profile-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
#[cfg(feature = "cli")]
impl ToTable for MeasurementSystemProfile {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let mut attrs_table = prettytable::Table::new();
        attrs_table.add_row(prettytable::row!["name", "value"]);
        for attr_record in self.attrs.iter() {
            attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
        }
        table.add_row(prettytable::row!["profile_id", self.profile_id]);
        table.add_row(prettytable::row!["name", self.name]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["attrs", attrs_table]);
        Ok(table.to_string())
    }
}
