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

/*!
 *  Code for working the measurement_bundles and measurement_bundles_values
 *  tables in the database, leveraging the bundle-specific record types.
*/

use carbide_uuid::measured_boot::{MeasurementBundleId, MeasurementSystemProfileId};
#[cfg(feature = "cli")]
use rpc::admin_cli::ToTable;
use rpc::errors::RpcDataConversionError;
use rpc::protos::measured_boot::{MeasurementBundlePb, MeasurementBundleStatePb};
use serde::Serialize;

use super::pcr::PcrRegisterValue;
use super::records::{MeasurementBundleState, MeasurementBundleValueRecord};

/// MeasurementBundle is a composition of a MeasurementBundleRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementBundleValueRecord, along with its UUID and timestamp).
#[derive(Debug, Serialize, Clone)]
pub struct MeasurementBundle {
    // bundle_id is the auto-generated UUID for a measurement bundle,
    // and is used as a reference ID for all measurement_bundle_value
    // records.
    pub bundle_id: MeasurementBundleId,

    // profile_id is the system profile this bundle is associated
    // with, allowing us to track bundles per profile.
    pub profile_id: MeasurementSystemProfileId,

    // name is the [db-enforced] unique, human-friendly name for the
    // bundle. for manually-created bundles, it is expected that
    // a name is provided. for auto-created bundles, some sort of
    // derived name is generated.
    pub name: String,

    // state is the state of this bundle.
    // See the MeasurementBundleState enum for more info,
    // including all states, and what they mean.
    pub state: MeasurementBundleState,

    // values are all of the bundle measurement values,
    // which includes all of the PCR registers and their
    // values.
    pub values: Vec<MeasurementBundleValueRecord>,

    // ts is the timestamp this bundle was created.
    pub ts: chrono::DateTime<chrono::Utc>,
}

impl From<MeasurementBundle> for MeasurementBundlePb {
    fn from(val: MeasurementBundle) -> Self {
        let pb_state: MeasurementBundleStatePb = val.state.into();
        Self {
            bundle_id: Some(val.bundle_id),
            profile_id: Some(val.profile_id),
            name: val.name,
            state: pb_state.into(),
            values: val
                .values
                .iter()
                .map(|value| value.clone().into())
                .collect(),
            ts: Some(val.ts.into()),
        }
    }
}

impl MeasurementBundle {
    pub fn pcr_values(&self) -> Vec<PcrRegisterValue> {
        let borrowed = &self.values;
        borrowed.iter().map(|rec| rec.clone().into()).collect()
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&MeasurementBundlePb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(String::from(
                "bundle is unexpectedly empty",
            )))
            .and_then(|pb| {
                Self::try_from(pb.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!("bundle failed pb->model conversion: {e}"))
                })
            })
    }
}

impl TryFrom<MeasurementBundlePb> for MeasurementBundle {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementBundlePb) -> Result<Self, Box<dyn std::error::Error>> {
        let state = msg.state();
        let values: super::Result<Vec<MeasurementBundleValueRecord>> = msg
            .values
            .iter()
            .map(
                |attr| match MeasurementBundleValueRecord::try_from(attr.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(super::Error::RpcConversion(format!(
                        "attr conversion failed: {failed}"
                    ))),
                },
            )
            .collect();

        Ok(Self {
            bundle_id: msg
                .bundle_id
                .ok_or(RpcDataConversionError::MissingArgument("bundle_id"))?,
            profile_id: msg
                .profile_id
                .ok_or(RpcDataConversionError::MissingArgument("profile_id"))?,
            name: msg.name.clone(),
            state: MeasurementBundleState::from(state),
            values: values?,
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

// When `bundle show <bundle-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
#[cfg(feature = "cli")]
impl ToTable for MeasurementBundle {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let mut values_table = prettytable::Table::new();
        values_table.add_row(prettytable::row!["pcr_register", "value"]);
        for value_record in self.values.iter() {
            values_table.add_row(prettytable::row![
                value_record.pcr_register,
                value_record.sha_any
            ]);
        }
        table.add_row(prettytable::row!["bundle_id", self.bundle_id]);
        table.add_row(prettytable::row!["profile_id", self.profile_id]);
        table.add_row(prettytable::row!["name", self.name]);
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["values", values_table]);
        Ok(table.to_string())
    }
}
