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
 *  Code for working the measuremment_reports and measurement_reports_values
 *  tables in the database, leveraging the report-specific record types.
*/

use std::str::FromStr;

use carbide_uuid::UuidEmptyStringError;
use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementReportId;
use chrono::Utc;
#[cfg(feature = "cli")]
use rpc::admin_cli::ToTable;
use rpc::errors::RpcDataConversionError;
use rpc::protos::measured_boot::MeasurementReportPb;
use serde::Serialize;

use super::pcr::PcrRegisterValue;
use super::records::MeasurementReportValueRecord;

/// MeasurementReport is a composition of a MeasurementReportRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementReportValueRecord, along with its UUID and timestamp).
#[derive(Debug, Serialize, Clone)]
pub struct MeasurementReport {
    pub report_id: MeasurementReportId,
    pub machine_id: MachineId,
    pub ts: chrono::DateTime<Utc>,
    pub values: Vec<MeasurementReportValueRecord>,
}

impl MeasurementReport {
    pub fn pcr_values(&self) -> Vec<PcrRegisterValue> {
        let borrowed = &self.values;
        borrowed.iter().map(|rec| rec.clone().into()).collect()
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&MeasurementReportPb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(
                "report is unexpectedly empty".to_string(),
            ))
            .and_then(|pb| {
                Self::try_from(pb.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!("report failed pb->model conversion: {e}"))
                })
            })
    }
}

impl From<MeasurementReport> for MeasurementReportPb {
    fn from(val: MeasurementReport) -> Self {
        Self {
            report_id: Some(val.report_id),
            machine_id: val.machine_id.to_string(),
            values: val
                .values
                .iter()
                .map(|value| value.clone().into())
                .collect(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementReportPb> for MeasurementReport {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementReportPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let values: super::Result<Vec<MeasurementReportValueRecord>> = msg
            .values
            .iter()
            .map(
                |value| match MeasurementReportValueRecord::try_from(value.clone()) {
                    Ok(worked) => Ok(worked),
                    Err(failed) => Err(super::Error::RpcConversion(format!(
                        "attr conversion failed: {failed}"
                    ))),
                },
            )
            .collect();

        Ok(Self {
            report_id: msg
                .report_id
                .ok_or(RpcDataConversionError::MissingArgument("report_id"))?,
            machine_id: MachineId::from_str(&msg.machine_id)?,
            values: values?,
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

// When `report show <report-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
#[cfg(feature = "cli")]
impl ToTable for MeasurementReport {
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
        table.add_row(prettytable::row!["report_id", self.report_id]);
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["values", values_table]);
        Ok(table.to_string())
    }
}
