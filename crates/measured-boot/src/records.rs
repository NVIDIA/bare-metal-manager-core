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
 *  Contains structs that map directly to tables, with the intent of binding
 *  for doing selects.
 *
 *  And, once https://github.com/launchbadge/sqlx/issues/3071 is taken care of,
 *  these models can be re-leveraged for doing inserts as well (well, more than
 *  likely there will be insert-specific models, but they'd go in here).
 *
 *  There are type-specific primary/foreign key IDs to make it more explicit
 *  what type of key is being passed around. A bunch of uuid::Uuid is meh.
*/

use std::convert::Into;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::{
    MeasurementApprovedMachineId, MeasurementApprovedProfileId, MeasurementBundleId,
    MeasurementBundleValueId, MeasurementJournalId, MeasurementReportId, MeasurementReportValueId,
    MeasurementSystemProfileAttrId, MeasurementSystemProfileId, TrustedMachineId,
};
use carbide_uuid::{DbTable, UuidEmptyStringError};
use chrono::{DateTime, Utc};
#[cfg(feature = "cli")]
use rpc::admin_cli::{ToTable, serde_just_print_summary};
use rpc::errors::RpcDataConversionError;
use rpc::protos::measured_boot::{
    CandidateMachineSummaryPb, MeasurementApprovedMachineRecordPb,
    MeasurementApprovedProfileRecordPb, MeasurementApprovedTypePb, MeasurementBundleRecordPb,
    MeasurementBundleStatePb, MeasurementBundleValueRecordPb, MeasurementJournalRecordPb,
    MeasurementMachineStatePb, MeasurementReportRecordPb, MeasurementReportValueRecordPb,
    MeasurementSystemProfileAttrRecordPb, MeasurementSystemProfileRecordPb,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::PgRow,
    {FromRow, Row},
};
use tonic::Status;

use super::pcr::PcrRegisterValue;

/// ProtoParseError is an error used for reporting back failures
/// to parse a protobuf message back into its record or model.
#[derive(Debug)]
pub struct ProtoParseError {
    // from is the input type
    pub from: String,
    // to is the output type
    pub to: String,
    // msg is the msg
    pub msg: String,
}

impl fmt::Display for ProtoParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to convert {} to {}: {}",
            self.from, self.to, self.msg,
        )
    }
}

impl Error for ProtoParseError {}

/// StringToEnumError is used for taking an input string and converting
/// it to an enum of a given type. It is leveraged by MeasurementBundleState,
/// MeasurementApprovedType, and anything else that might need
/// to leverage it further.
#[derive(Debug)]
pub struct StringToEnumError;

impl fmt::Display for StringToEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to convert measurement bundle state to enum")
    }
}

impl Error for StringToEnumError {}

/// MeasurementSystemProfileRecord defines a single row from the
/// measurement_system_profiles table in the database.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementSystemProfileRecord {
    // profile_id is the auto-generated UUID assigned to the profile,
    // and internally typed as a MeasurementSystemProfileId.
    pub profile_id: MeasurementSystemProfileId,

    // name is the [db-enforced] unique, human-friendly name for the
    // profile. for manually-created profiles, it is expected that
    // a name is provided. for auto-created profiles, some sort of
    // derived name is generated.
    pub name: String,

    // ts is the timestamp the profile was created.
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementSystemProfileRecord {
    pub fn from_grpc(msg: MeasurementSystemProfileRecordPb) -> super::Result<Self> {
        Self::try_from(msg).map_err(|e| {
            super::Error::RpcConversion(format!("bad input system profile record: {e}"))
        })
    }

    pub fn from_pb_vec(pbs: &[MeasurementSystemProfileRecordPb]) -> super::Result<Vec<Self>> {
        pbs.iter()
            .map(|record| {
                Self::try_from(record.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!(
                        "failed system profile record conversion: {e}"
                    ))
                })
            })
            .collect()
    }
}

impl DbTable for MeasurementSystemProfileRecord {
    fn db_table_name() -> &'static str {
        "measurement_system_profiles"
    }
}

impl From<MeasurementSystemProfileRecord> for MeasurementSystemProfileRecordPb {
    fn from(val: MeasurementSystemProfileRecord) -> Self {
        Self {
            profile_id: Some(val.profile_id),
            name: val.name,
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementSystemProfileRecordPb> for MeasurementSystemProfileRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementSystemProfileRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            profile_id: msg
                .profile_id
                .ok_or(RpcDataConversionError::MissingArgument("profile_id"))?,
            name: msg.name.clone(),
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementSystemProfileAttrRecord defines a single row from
/// the measurement_system_profiles_attrs table in the database.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementSystemProfileAttrRecord {
    // attribute_id is the auto-generated UUID assigned to this
    // specific attribute record for its profile attributes.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub attribute_id: MeasurementSystemProfileAttrId,

    // profile_id is the system profile ID that this specific
    // attribute is a part of.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub profile_id: MeasurementSystemProfileId,

    // key is the attribute key (e.g. vendor, product, etc), and
    // is generally derived from some sort of value that comes
    // from DiscoveryInfo.
    pub key: String,

    // value is the value for the attribute, again being generally
    // derived from sort of value coming from DiscoveryInfo.
    pub value: String,

    // ts is the timestamp this record was created.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementSystemProfileAttrRecord {
    pub fn from_grpc(msg: MeasurementSystemProfileAttrRecordPb) -> super::Result<Self> {
        Self::try_from(msg).map_err(|e| {
            super::Error::RpcConversion(format!("bad input system profile attr record: {e}"))
        })
    }

    pub fn from_pb_vec(pbs: &[MeasurementSystemProfileAttrRecordPb]) -> super::Result<Vec<Self>> {
        pbs.iter()
            .map(|record| {
                Self::try_from(record.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!(
                        "failed system profile record attr conversion: {e}"
                    ))
                })
            })
            .collect()
    }
}

impl DbTable for MeasurementSystemProfileAttrRecord {
    fn db_table_name() -> &'static str {
        "measurement_system_profiles_attrs"
    }
}

impl From<MeasurementSystemProfileAttrRecord> for MeasurementSystemProfileAttrRecordPb {
    fn from(val: MeasurementSystemProfileAttrRecord) -> Self {
        Self {
            attribute_id: Some(val.attribute_id),
            profile_id: Some(val.profile_id),
            key: val.key,
            value: val.value,
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementSystemProfileAttrRecordPb> for MeasurementSystemProfileAttrRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(
        msg: MeasurementSystemProfileAttrRecordPb,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            attribute_id: msg
                .attribute_id
                .ok_or(RpcDataConversionError::MissingArgument("attribute_id"))?,
            profile_id: msg
                .profile_id
                .ok_or(RpcDataConversionError::MissingArgument("profile_id"))?,
            key: msg.key.clone(),
            value: msg.value.clone(),
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementBundleState is an enum in the database, and
/// is used for tracking the state of a measurement bundle.
///
/// Impls FromStr trait.
#[derive(Copy, Debug, Eq, Hash, PartialEq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "measurement_bundle_state", rename_all = "lowercase")
)]
pub enum MeasurementBundleState {
    // Pending exists such that, when a bundle is created, it has the
    // option of needing approval to become Active before machines can
    // start passing measurements against it. In that case, the bundle
    // is marked as Pending.
    Pending,

    // Active is used to notate a an active bundle to which machines
    // will be considered Measured when matching against this bundle.
    Active,

    // Obsolete is used to note a deprecated bundle. It's still allowed
    // to match for attestation, but those machines will be reported
    // as being on obsolete measurements (and need to upgrade, for example).
    Obsolete,

    // Retired is used to notate, well, a retired bundle. Machines matching
    // a Retied bundle will be considered MeasuringFailed, and not pass
    // measurements.
    //
    // Retired bundles CAN have their state changed (i.e. back to Pending,
    // Active, Obsolete, etc).
    Retired,

    // Revoked is similar to Retired, in that machines matching a Revoked
    // bundle will be considered MeasuringFailed, and not pass measurements.
    //
    // The purpose of Revoked is generally to mark a very well-known BAD
    // bundle (as in, we discovered an issue with a class of machines with
    // certain measurements), and we NEVER want to pass attestation for
    // those machines.
    //
    // Revoked bundles CANNOT have their state changed.
    Revoked,
}

impl FromStr for MeasurementBundleState {
    type Err = StringToEnumError;

    fn from_str(input: &str) -> Result<MeasurementBundleState, Self::Err> {
        match input {
            "Pending" => Ok(MeasurementBundleState::Pending),
            "Active" => Ok(MeasurementBundleState::Active),
            "Obsolete" => Ok(MeasurementBundleState::Obsolete),
            "Retired" => Ok(MeasurementBundleState::Retired),
            "Revoked" => Ok(MeasurementBundleState::Revoked),
            _ => Err(StringToEnumError),
        }
    }
}

impl fmt::Display for MeasurementBundleState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<MeasurementBundleState> for MeasurementBundleStatePb {
    fn from(val: MeasurementBundleState) -> Self {
        match val {
            MeasurementBundleState::Pending => Self::Pending,
            MeasurementBundleState::Active => Self::Active,
            MeasurementBundleState::Obsolete => Self::Obsolete,
            MeasurementBundleState::Retired => Self::Retired,
            MeasurementBundleState::Revoked => Self::Revoked,
        }
    }
}

impl From<MeasurementBundleStatePb> for MeasurementBundleState {
    fn from(msg: MeasurementBundleStatePb) -> Self {
        match msg {
            MeasurementBundleStatePb::Pending => Self::Pending,
            MeasurementBundleStatePb::Active => Self::Active,
            MeasurementBundleStatePb::Obsolete => Self::Obsolete,
            MeasurementBundleStatePb::Retired => Self::Retired,
            MeasurementBundleStatePb::Revoked => Self::Revoked,
        }
    }
}

/// MeasurementBundleStateRecord exists so we can do an sqlx::query_as and
/// *just* select the state (and bind it to a struct). It doesn't really need
/// to be much other than this for now.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementBundleStateRecord {
    // Read the comment above, but state is the actual state.
    pub state: MeasurementBundleState,
}

/// MeasurementBundleRecord defines a single row from
/// the measurement_bundles table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementBundleRecord {
    // bundle_id is the auto-generated UUID for a measurement bundle,
    // and is used as a reference ID for all measurement_bundle_value
    // records.
    pub bundle_id: MeasurementBundleId,

    // name is the [db-enforced] unique, human-friendly name for the
    // bundle. for manually-created bundles, it is expected that
    // a name is provided. for auto-created bundles, some sort of
    // derived name is generated.
    pub name: String,

    // profile_id is the system profile this bundle is associated
    // with, allowing us to track bundles per profile.
    pub profile_id: MeasurementSystemProfileId,

    // state is the state of this bundle.
    // See the MeasurementBundleState enum for more info,
    // including all states, and what they mean.
    pub state: MeasurementBundleState,

    // ts is the timestamp this record was created.
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementBundleRecord {
    pub fn from_grpc(msg: MeasurementBundleRecordPb) -> super::Result<Self> {
        Self::try_from(msg)
            .map_err(|e| super::Error::RpcConversion(format!("bad input bundle record: {e}")))
    }

    pub fn from_pb_vec(pbs: &[MeasurementBundleRecordPb]) -> super::Result<Vec<Self>> {
        pbs.iter()
            .map(|record| {
                Self::try_from(record.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!(
                        "failed bundle record attr conversion: {e}"
                    ))
                })
            })
            .collect()
    }
}

impl DbTable for MeasurementBundleRecord {
    fn db_table_name() -> &'static str {
        "measurement_bundles"
    }
}

impl From<MeasurementBundleRecord> for MeasurementBundleRecordPb {
    fn from(val: MeasurementBundleRecord) -> Self {
        let pb_state: MeasurementBundleStatePb = val.state.into();
        Self {
            bundle_id: Some(val.bundle_id),
            name: val.name,
            profile_id: Some(val.profile_id),
            state: pb_state.into(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementBundleRecordPb> for MeasurementBundleRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementBundleRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
        let state = msg.state();

        Ok(Self {
            bundle_id: msg
                .bundle_id
                .ok_or(RpcDataConversionError::MissingArgument("bundle_id"))?,
            profile_id: msg
                .profile_id
                .ok_or(RpcDataConversionError::MissingArgument("profile_id"))?,
            name: msg.name.clone(),
            state: MeasurementBundleState::from(state),
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementBundleValueRecord defines a single row
/// from the measurement_bundles_values table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementBundleValueRecord {
    // value_id is the auto-generated UUID for this record.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub value_id: MeasurementBundleValueId,

    // bundle_id is the ID of the measurement bundle this
    // value is associated with.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub bundle_id: MeasurementBundleId,

    // pcr_register is the specific PCR register index (starting
    // at 0) that the corresponding sha256 is from.
    pub pcr_register: i16,

    // sha_any is any shaXXX from the PCR register.
    pub sha_any: String,

    // ts is the timestamp the record was created.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementBundleValueRecord {
    pub fn from_grpc(msg: MeasurementBundleValueRecordPb) -> super::Result<Self> {
        Self::try_from(msg)
            .map_err(|e| super::Error::RpcConversion(format!("bad input bundle value record: {e}")))
    }

    pub fn from_pb_vec(pbs: &[MeasurementBundleValueRecordPb]) -> super::Result<Vec<Self>> {
        pbs.iter()
            .map(|record| {
                Self::try_from(record.clone()).map_err(|e| {
                    super::Error::RpcConversion(format!(
                        "failed bundle value record attr conversion: {e}"
                    ))
                })
            })
            .collect()
    }
}

impl DbTable for MeasurementBundleValueRecord {
    fn db_table_name() -> &'static str {
        "measurement_bundles_values"
    }
}

impl From<MeasurementBundleValueRecord> for PcrRegisterValue {
    fn from(val: MeasurementBundleValueRecord) -> Self {
        PcrRegisterValue {
            pcr_register: val.pcr_register,
            sha_any: val.sha_any,
        }
    }
}

impl From<MeasurementBundleValueRecord> for MeasurementBundleValueRecordPb {
    fn from(val: MeasurementBundleValueRecord) -> Self {
        Self {
            value_id: Some(val.value_id),
            bundle_id: Some(val.bundle_id),
            pcr_register: val.pcr_register as i32,
            sha_any: val.sha_any,
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementBundleValueRecordPb> for MeasurementBundleValueRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementBundleValueRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            value_id: msg
                .value_id
                .ok_or(RpcDataConversionError::MissingArgument("value_id"))?,
            bundle_id: msg
                .bundle_id
                .ok_or(RpcDataConversionError::MissingArgument("bundle_id"))?,
            pcr_register: msg.pcr_register as i16,
            sha_any: msg.sha_any.clone(),
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementReportRecord defines a single row from
/// the measurement_reports table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementReportRecord {
    // report_id is the auto-generated UUID specific to this report.
    pub report_id: MeasurementReportId,

    // machine_id is the "mock" machine ID that this report is for.
    pub machine_id: MachineId,

    // ts is the timestamp the report record was created.
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementReportRecord {
    pub fn from_grpc(msg: MeasurementReportRecordPb) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input report record: {e}")))
    }
}

impl DbTable for MeasurementReportRecord {
    fn db_table_name() -> &'static str {
        "measurement_reports"
    }
}

impl From<MeasurementReportRecord> for MeasurementReportRecordPb {
    fn from(val: MeasurementReportRecord) -> Self {
        Self {
            report_id: Some(val.report_id),
            machine_id: val.machine_id.to_string(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementReportRecordPb> for MeasurementReportRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementReportRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        };

        Ok(Self {
            report_id: msg
                .report_id
                .ok_or(RpcDataConversionError::MissingArgument("report_id"))?,
            machine_id: MachineId::from_str(&msg.machine_id)?,
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementReportValueRecord defines a single row from
/// the measurement_reports_values table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as a self-implementation for converting into a PcrRegisterValue.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementReportValueRecord {
    // value_id is the auto-generated UUID for this value record.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub value_id: MeasurementReportValueId,

    // report_id is the measurement report record this value is
    // associated with.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub report_id: MeasurementReportId,

    // pcr_register is the specific PCR register index (starting
    // at 0) that the corresponding sha_any is from.
    pub pcr_register: i16,

    // sha_any is the sha_any value reported for the given
    // PCR register from the machine.
    pub sha_any: String,

    // ts is the timestamp this record was created.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementReportValueRecord {
    pub fn from_grpc(msg: MeasurementReportValueRecordPb) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input report value record: {e}")))
    }
}

impl DbTable for MeasurementReportValueRecord {
    fn db_table_name() -> &'static str {
        "measurement_reports_values"
    }
}

impl From<MeasurementReportValueRecord> for PcrRegisterValue {
    fn from(val: MeasurementReportValueRecord) -> Self {
        Self {
            pcr_register: val.pcr_register,
            sha_any: val.sha_any,
        }
    }
}

impl From<MeasurementReportValueRecord> for MeasurementReportValueRecordPb {
    fn from(val: MeasurementReportValueRecord) -> Self {
        Self {
            value_id: Some(val.value_id),
            report_id: Some(val.report_id),
            pcr_register: val.pcr_register as i32,
            sha_any: val.sha_any,
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementReportValueRecordPb> for MeasurementReportValueRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementReportValueRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            value_id: msg
                .value_id
                .ok_or(RpcDataConversionError::MissingArgument("value_id"))?,
            report_id: msg
                .report_id
                .ok_or(RpcDataConversionError::MissingArgument("report_id"))?,
            pcr_register: msg.pcr_register as i16,
            sha_any: msg.sha_any.clone(),
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementJournalRecord defines a single row from
/// the measurement_journal table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementJournalRecord {
    // journal is the auto-generated UUID specific to this
    // journal entry.
    pub journal_id: MeasurementJournalId,

    // machine_id is the ID of the machine for this journal
    // entry. Technically this can be derived from report_id,
    // but it makes things easier just having it right here
    // versus needing to join against the reports table.
    pub machine_id: MachineId,

    // report_id is the report record that this journal entry is for.
    pub report_id: MeasurementReportId,

    // profile_id is the matched system profile for the machine
    // that generated the report referenced in this journal.
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub profile_id: Option<MeasurementSystemProfileId>,

    // bundle_id is the matched measurement bundle for this
    // journal entry. If no matching bundle exists, this will
    // be None, and the machine will be "Pending".
    #[cfg_attr(
        feature = "cli",
        serde(skip_serializing_if = "serde_just_print_summary")
    )]
    pub bundle_id: Option<MeasurementBundleId>,

    // state is the resulting state of the machine based on
    // this journal entry. For example, if the machine matches
    // an active bundle, the machine state will be Measured,
    // whereas if a retired (or revoked) bundle is matched,
    // the machine state will be MeasuringFailed. If no bundle
    // is matched, this state will show Pending.
    pub state: MeasurementMachineState,

    // ts is the timestamp the journal record was created.
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementJournalRecord {
    pub fn from_grpc(msg: MeasurementJournalRecordPb) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input journal record: {e}")))
    }
}

impl DbTable for MeasurementJournalRecord {
    fn db_table_name() -> &'static str {
        "measurement_journal"
    }
}

impl From<MeasurementJournalRecord> for MeasurementJournalRecordPb {
    fn from(val: MeasurementJournalRecord) -> Self {
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

impl TryFrom<MeasurementJournalRecordPb> for MeasurementJournalRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementJournalRecordPb) -> Result<Self, Box<dyn std::error::Error>> {
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
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

/// MeasurementMachineState is an enum in the database, and
/// is used for tracking the state of a machine.
///
/// Impls FromStr trait.
#[derive(Copy, Debug, Eq, Hash, PartialEq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "measurement_machine_state", rename_all = "lowercase")
)]
pub enum MeasurementMachineState {
    Discovered,
    PendingBundle,
    Measured,
    MeasuringFailed,
}

impl FromStr for MeasurementMachineState {
    type Err = StringToEnumError;

    fn from_str(input: &str) -> Result<MeasurementMachineState, Self::Err> {
        match input {
            "Discovered" => Ok(MeasurementMachineState::Discovered),
            "PendingBundle" => Ok(MeasurementMachineState::PendingBundle),
            "Measured" => Ok(MeasurementMachineState::Measured),
            "MeasuringFailed" => Ok(MeasurementMachineState::MeasuringFailed),
            _ => Err(StringToEnumError),
        }
    }
}

impl fmt::Display for MeasurementMachineState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<MeasurementMachineState> for MeasurementMachineStatePb {
    fn from(val: MeasurementMachineState) -> Self {
        match val {
            MeasurementMachineState::Discovered => Self::Discovered,
            MeasurementMachineState::PendingBundle => Self::PendingBundle,
            MeasurementMachineState::Measured => Self::Measured,
            MeasurementMachineState::MeasuringFailed => Self::MeasuringFailed,
        }
    }
}

impl From<MeasurementMachineStatePb> for MeasurementMachineState {
    fn from(msg: MeasurementMachineStatePb) -> Self {
        match msg {
            MeasurementMachineStatePb::Discovered => Self::Discovered,
            MeasurementMachineStatePb::PendingBundle => Self::PendingBundle,
            MeasurementMachineStatePb::Measured => Self::Measured,
            MeasurementMachineStatePb::MeasuringFailed => Self::MeasuringFailed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateMachineSummary {
    // machine_id is the ID of the machine, e.g. fm100hxxxxx.
    pub machine_id: MachineId,

    // ts is the timestamp this record was created.
    pub ts: chrono::DateTime<Utc>,
}

impl CandidateMachineSummary {
    pub fn from_grpc(msg: CandidateMachineSummaryPb) -> Result<Self, Status> {
        Self::try_from(msg).map_err(|e| {
            Status::invalid_argument(format!("bad input candidate machine record: {e}"))
        })
    }
}

impl From<CandidateMachineSummary> for CandidateMachineSummaryPb {
    fn from(val: CandidateMachineSummary) -> Self {
        Self {
            machine_id: val.machine_id.to_string(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<CandidateMachineSummaryPb> for CandidateMachineSummary {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: CandidateMachineSummaryPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }

        Ok(Self {
            machine_id: MachineId::from_str(&msg.machine_id)?,
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

#[cfg(feature = "cli")]
impl ToTable for CandidateMachineSummary {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        Ok(table.to_string())
    }
}

/// MeasurementApprovedType is an enum in the database, and
/// is used for tracking the state of a site-approved machine that
/// measurements will be auto-approved as a bundle.
///
/// Impls FromStr trait.
#[derive(Copy, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "measurement_approved_type", rename_all = "lowercase")
)]
pub enum MeasurementApprovedType {
    Oneshot,
    Persist,
}

impl FromStr for MeasurementApprovedType {
    type Err = StringToEnumError;

    fn from_str(input: &str) -> Result<MeasurementApprovedType, Self::Err> {
        match input {
            "Oneshot" => Ok(MeasurementApprovedType::Oneshot),
            "Persist" => Ok(MeasurementApprovedType::Persist),
            _ => Err(StringToEnumError),
        }
    }
}

impl fmt::Display for MeasurementApprovedType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<MeasurementApprovedType> for MeasurementApprovedTypePb {
    fn from(val: MeasurementApprovedType) -> Self {
        match val {
            MeasurementApprovedType::Oneshot => Self::Oneshot,
            MeasurementApprovedType::Persist => Self::Persist,
        }
    }
}

impl From<MeasurementApprovedTypePb> for MeasurementApprovedType {
    fn from(val: MeasurementApprovedTypePb) -> Self {
        match val {
            MeasurementApprovedTypePb::Oneshot => Self::Oneshot,
            MeasurementApprovedTypePb::Persist => Self::Persist,
        }
    }
}

/// MeasurementApprovedMachineRecord defines a single row from
/// the measurement_approved_machines table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementApprovedMachineRecord {
    // approval_id is the auto-generated UUID for this approval record.
    pub approval_id: MeasurementApprovedMachineId,

    // machine_id is the ID of the machine this approval is for.
    pub machine_id: TrustedMachineId,

    // state is the type of approval (oneshot or persist).
    pub approval_type: MeasurementApprovedType,

    // pcr_registers are which PCR registers should be promoted
    // into a bundle from the corresponding report record
    // that we are auto-promoting. This takes the same format
    // as the --pcr-registers CLI flag, which is ultimately
    // parsed by parse_pcr_index_input.
    pub pcr_registers: Option<String>,

    // comments is an optional comment that can be provided with
    // the auto-approval record.
    pub comments: Option<String>,

    // ts is the timestamp the approval record was created.
    pub ts: chrono::DateTime<Utc>,
}

#[cfg(feature = "sqlx")]
impl<'r> FromRow<'r, PgRow> for MeasurementApprovedMachineRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id_str: &str = row.try_get("machine_id")?;
        let machine_id =
            TrustedMachineId::from_str(id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Self {
            approval_id: row.try_get("approval_id")?,
            machine_id,
            approval_type: row.try_get("approval_type")?,
            pcr_registers: row.try_get("pcr_registers")?,
            comments: row.try_get("comments")?,
            ts: row.try_get("ts")?,
        })
    }
}

impl MeasurementApprovedMachineRecord {
    pub fn from_grpc(msg: Option<&MeasurementApprovedMachineRecordPb>) -> Result<Self, Status> {
        match msg {
            Some(pb) => Self::try_from(pb.clone()).map_err(|e| {
                Status::invalid_argument(format!("bad input trusted machine approval record: {e}"))
            }),
            None => Err(Status::invalid_argument("record unexpectedly empty")),
        }
    }
}

impl DbTable for MeasurementApprovedMachineRecord {
    fn db_table_name() -> &'static str {
        "measurement_approved_machines"
    }
}

impl From<MeasurementApprovedMachineRecord> for MeasurementApprovedMachineRecordPb {
    fn from(val: MeasurementApprovedMachineRecord) -> Self {
        let approval_type: MeasurementApprovedTypePb = val.approval_type.into();

        Self {
            approval_id: Some(val.approval_id),
            machine_id: val.machine_id.to_string(),
            approval_type: approval_type.into(),
            pcr_registers: val.pcr_registers.unwrap_or("".to_string()),
            comments: val.comments.unwrap_or("".to_string()),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementApprovedMachineRecordPb> for MeasurementApprovedMachineRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(
        msg: MeasurementApprovedMachineRecordPb,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let approval_type = msg.approval_type();

        Ok(Self {
            approval_id: msg
                .approval_id
                .ok_or(RpcDataConversionError::MissingArgument("approval_id"))?,
            machine_id: TrustedMachineId::from_str(&msg.machine_id)?,
            approval_type: MeasurementApprovedType::from(approval_type),
            pcr_registers: match !msg.pcr_registers.is_empty() {
                true => Some(msg.pcr_registers.clone()),
                false => None,
            },
            comments: match !msg.comments.is_empty() {
                true => Some(msg.comments.clone()),
                false => None,
            },
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

#[cfg(feature = "cli")]
impl ToTable for MeasurementApprovedMachineRecord {
    fn into_table(self) -> eyre::Result<String> {
        let pcr_registers: String = match self.pcr_registers.clone() {
            Some(pcr_registers) => pcr_registers,
            None => "".to_string(),
        };
        let comments: String = match self.comments.clone() {
            Some(comments) => comments,
            None => "".to_string(),
        };
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["approval_id", self.approval_id]);
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["approval_type", self.approval_type]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["pcr_registers", pcr_registers]);
        table.add_row(prettytable::row!["comments", comments]);
        Ok(table.to_string())
    }
}
/// MeasurementApprovedProfileRecord defines a single row from
/// the measurement_approved_profiles table.
///
/// Impls DbTable trait for generic selects defined in db/interface/common.rs,
/// as well as ToTable for printing out details via prettytable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(FromRow))]
pub struct MeasurementApprovedProfileRecord {
    // approval_id is the auto-generated UUID for this approval record.
    pub approval_id: MeasurementApprovedProfileId,

    // profile_id is the profile this approval is for.
    pub profile_id: MeasurementSystemProfileId,

    // state is the type of approval (oneshot or persist).
    pub approval_type: MeasurementApprovedType,

    // pcr_registers are which PCR registers should be promoted
    // into a bundle from the corresponding report record
    // that we are auto-promoting. This takes the same format
    // as the --pcr-registers CLI flag, which is ultimately
    // parsed by parse_pcr_index_input.
    pub pcr_registers: Option<String>,

    // comments is an optional comment that can be provided with
    // the auto-approval record.
    pub comments: Option<String>,

    // ts is the timestamp the approval record was created.
    pub ts: chrono::DateTime<Utc>,
}

impl MeasurementApprovedProfileRecord {
    pub fn from_grpc(msg: Option<&MeasurementApprovedProfileRecordPb>) -> Result<Self, Status> {
        match msg {
            Some(pb) => Self::try_from(pb.clone()).map_err(|e| {
                Status::invalid_argument(format!("bad input trusted profile approval record: {e}"))
            }),
            None => Err(Status::invalid_argument("record unexpectedly empty")),
        }
    }
}

impl DbTable for MeasurementApprovedProfileRecord {
    fn db_table_name() -> &'static str {
        "measurement_approved_profiles"
    }
}

impl From<MeasurementApprovedProfileRecord> for MeasurementApprovedProfileRecordPb {
    fn from(val: MeasurementApprovedProfileRecord) -> Self {
        let approval_type: MeasurementApprovedTypePb = val.approval_type.into();

        Self {
            approval_id: Some(val.approval_id),
            profile_id: Some(val.profile_id),
            approval_type: approval_type.into(),
            pcr_registers: val.pcr_registers.unwrap_or("".to_string()),
            comments: val.comments.unwrap_or("".to_string()),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementApprovedProfileRecordPb> for MeasurementApprovedProfileRecord {
    type Error = Box<dyn std::error::Error>;

    fn try_from(
        msg: MeasurementApprovedProfileRecordPb,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let approval_type = msg.approval_type();
        Ok(Self {
            approval_id: msg
                .approval_id
                .ok_or(RpcDataConversionError::MissingArgument("approval_id"))?,
            profile_id: msg
                .profile_id
                .ok_or(RpcDataConversionError::MissingArgument("profile_id"))?,
            approval_type: MeasurementApprovedType::from(approval_type),
            pcr_registers: match !msg.pcr_registers.is_empty() {
                true => Some(msg.pcr_registers.clone()),
                false => None,
            },
            comments: match !msg.comments.is_empty() {
                true => Some(msg.comments.clone()),
                false => None,
            },
            ts: DateTime::<Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

#[cfg(feature = "cli")]
impl ToTable for MeasurementApprovedProfileRecord {
    fn into_table(self) -> eyre::Result<String> {
        let pcr_registers: String = match self.pcr_registers.clone() {
            Some(pcr_registers) => pcr_registers,
            None => "".to_string(),
        };
        let comments: String = match self.comments.clone() {
            Some(comments) => comments,
            None => "".to_string(),
        };
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["approval_id", self.approval_id]);
        table.add_row(prettytable::row!["profile_id", self.profile_id]);
        table.add_row(prettytable::row!["approval_type", self.approval_type]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["pcr_registers", pcr_registers]);
        table.add_row(prettytable::row!["comments", comments]);
        Ok(table.to_string())
    }
}
