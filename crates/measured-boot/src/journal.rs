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
 *  Code for working the measuremment_journal and measurement_journal_values
 *  tables in the database, leveraging the journal-specific record types.
*/

use std::str::FromStr;

use carbide_uuid::UuidEmptyStringError;
use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::{
    MeasurementBundleId, MeasurementJournalId, MeasurementReportId, MeasurementSystemProfileId,
};
use chrono::Utc;
use rpc::errors::RpcDataConversionError;
use rpc::protos::measured_boot::{MeasurementJournalPb, MeasurementMachineStatePb};
use serde::Serialize;
#[cfg(feature = "cli")]
use {
    rpc::admin_cli::ToTable,
    rpc::admin_cli::{just_print_summary, serde_just_print_summary},
};

use super::records::MeasurementMachineState;

/// MeasurementJournal is a composition of a MeasurementJournalRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementReportValueRecord, along with its UUID and timestamp).
#[derive(Debug, Serialize, Clone)]
pub struct MeasurementJournal {
    pub journal_id: MeasurementJournalId,
    pub machine_id: MachineId,
    pub report_id: MeasurementReportId,
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub profile_id: Option<MeasurementSystemProfileId>,
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub bundle_id: Option<MeasurementBundleId>,
    pub state: MeasurementMachineState,
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementJournal {
    #[cfg(feature = "cli")]
    /// to_nested_prettytable converts a MeasurementJournal into a small
    /// prettytable::Table for the purpose of displaying as a nested
    /// table for a CandidateMachine (showing just the basics).
    pub fn to_nested_prettytable(&self) -> prettytable::Table {
        let mut journal_table = prettytable::Table::new();
        journal_table.add_row(prettytable::row!["report_id", self.report_id]);
        journal_table.add_row(prettytable::row![
            "profile_id",
            match self.profile_id {
                Some(profile_id) => profile_id.to_string(),
                None => "<none>".to_string(),
            }
        ]);
        journal_table.add_row(prettytable::row![
            "bundle_id",
            match self.bundle_id {
                Some(bundle_id) => bundle_id.to_string(),
                None => "<none>".to_string(),
            }
        ]);
        journal_table
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////
    pub fn from_grpc(some_pb: Option<&MeasurementJournalPb>) -> super::Result<Self> {
        some_pb
            .ok_or(super::Error::RpcConversion(
                "journal is unexpectedly empty".to_string(),
            ))
            .and_then(|pb| {
                Self::try_from(pb.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!("journal failed pb->model conversion: {e}"))
                })
            })
    }
}

impl From<MeasurementJournal> for MeasurementJournalPb {
    fn from(val: MeasurementJournal) -> Self {
        let pb_state: MeasurementMachineStatePb = val.state.into();
        Self {
            journal_id: Some(val.journal_id),
            machine_id: val.machine_id.to_string(),
            report_id: Some(val.report_id),
            profile_id: val.profile_id,
            bundle_id: val.bundle_id,
            state: pb_state.into(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementJournalPb> for MeasurementJournal {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementJournalPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let state = msg.state();

        Ok(Self {
            journal_id: msg
                .journal_id
                .ok_or(RpcDataConversionError::MissingArgument("journal_id"))?,
            machine_id: MachineId::from_str(&msg.machine_id)?,
            report_id: msg
                .report_id
                .ok_or(RpcDataConversionError::MissingArgument("report_id"))?,
            profile_id: msg.profile_id,
            bundle_id: msg.bundle_id,
            state: MeasurementMachineState::from(state),
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

// When `journal show <journal-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
#[cfg(feature = "cli")]
impl ToTable for MeasurementJournal {
    fn into_table(self) -> eyre::Result<String> {
        let profile_id: String = match self.profile_id {
            Some(profile_id) => profile_id.to_string(),
            None => "<none>".to_string(),
        };
        let bundle_id: String = match self.bundle_id {
            Some(bundle_id) => bundle_id.to_string(),
            None => "<none>".to_string(),
        };
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["journal_id", self.journal_id]);
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        if !just_print_summary() {
            table.add_row(prettytable::row!["report_id", self.report_id]);
            table.add_row(prettytable::row!["profile_id", profile_id]);
            table.add_row(prettytable::row!["bundle_id", bundle_id]);
        }
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        Ok(table.to_string())
    }
}
