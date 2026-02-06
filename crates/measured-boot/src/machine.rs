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
 *  Code for working the machine_topologies table in the
 *  database to match candidate machines to profiles and bundles.
*/

use std::collections::HashMap;
use std::str::FromStr;

use carbide_uuid::UuidEmptyStringError;
use carbide_uuid::machine::MachineId;
use chrono::Utc;
#[cfg(feature = "cli")]
use rpc::admin_cli::ToTable;
use rpc::protos::measured_boot::{CandidateMachinePb, MeasurementMachineStatePb};
use serde::Serialize;

use super::journal::MeasurementJournal;
use super::records::MeasurementMachineState;

/// CandidateMachine describes a machine that is a candidate for attestation,
/// and is derived from machine information in the machine_toplogies table.
#[derive(Debug, Serialize, Clone)]
pub struct CandidateMachine {
    pub machine_id: MachineId,
    pub state: MeasurementMachineState,
    pub journal: Option<MeasurementJournal>,
    pub attrs: HashMap<String, String>,
    pub created_ts: chrono::DateTime<Utc>,
    pub updated_ts: chrono::DateTime<Utc>,
}

impl CandidateMachine {
    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&CandidateMachinePb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(
                "machine is unexpectedly empty".to_string(),
            ))
            .and_then(|pb| {
                Self::try_from(pb.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!("machine failed pb->model conversion: {e}"))
                })
            })
    }
}

impl From<CandidateMachine> for CandidateMachinePb {
    fn from(val: CandidateMachine) -> Self {
        let pb_state: MeasurementMachineStatePb = val.state.into();
        Self {
            machine_id: val.machine_id.to_string(),
            state: pb_state.into(),
            journal: val.journal.map(|journal| journal.into()),
            attrs: val.attrs,
            created_ts: Some(val.created_ts.into()),
            updated_ts: Some(val.updated_ts.into()),
        }
    }
}

impl TryFrom<CandidateMachinePb> for CandidateMachine {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: CandidateMachinePb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let state = msg.state();

        Ok(Self {
            machine_id: MachineId::from_str(&msg.machine_id)?,
            state: MeasurementMachineState::from(state),
            journal: match msg.journal {
                Some(journal_pb) => Some(MeasurementJournal::try_from(journal_pb)?),
                None => None,
            },
            attrs: msg.attrs,
            created_ts: chrono::DateTime::<chrono::Utc>::try_from(msg.created_ts.unwrap())?,
            updated_ts: chrono::DateTime::<chrono::Utc>::try_from(msg.updated_ts.unwrap())?,
        })
    }
}

#[cfg(feature = "cli")]
impl ToTable for CandidateMachine {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let journal_table = match &self.journal {
            Some(journal) => journal.to_nested_prettytable(),
            None => {
                let mut not_found = prettytable::Table::new();
                not_found.add_row(prettytable::row!["<no journal found>"]);
                not_found
            }
        };
        let mut attrs_table = prettytable::Table::new();
        attrs_table.add_row(prettytable::row!["name", "value"]);
        for (key, value) in self.attrs.iter() {
            attrs_table.add_row(prettytable::row![key, value]);
        }
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.created_ts]);
        table.add_row(prettytable::row!["updated_ts", self.updated_ts]);
        table.add_row(prettytable::row!["journal", journal_table]);
        table.add_row(prettytable::row!["attrs", attrs_table]);
        Ok(table.to_string())
    }
}
