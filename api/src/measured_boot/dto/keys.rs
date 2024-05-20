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

/*
///////////////////////////////////////////////////////////////////////////////
/// keys.rs
/// Code for defining primary/foreign keys used by the measured boot
/// database tables.
///
/// The idea here is to make it very obvious which type of UUID is being
/// worked with, since it would be otherwise easy to pass the wrong UUID
/// to the wrong part of a query. Being able to type the specific ID ends
/// up catching a lot of potential bugs.
///
/// To make this work, the keys must derive {FromRow,Type}, and explicitly
/// set #[sqlx(type_name = "UUID")]. Without that trifecta, sqlx gets all
/// mad because it cant bind it as a UUID.
///////////////////////////////////////////////////////////////////////////////
*/

use crate::measured_boot::dto::traits::DbPrimaryUuid;
use crate::measured_boot::interface::common::ToTable;
use rpc::protos::measured_boot::Uuid;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::convert::{Into, TryFrom};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use tonic::Status;

///////////////////////////////////////////////////////////////////////////////
/// IdParseError is an error used for reporting back failures
/// to parse a UUIDv4 string back into a UUID.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct UuidEmptyStringError {}

impl fmt::Display for UuidEmptyStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "input UUID string cannot be empty",)
    }
}

impl Error for UuidEmptyStringError {}

#[derive(Debug)]
pub struct IdParseError {
    // from is the input string.
    from: String,
    // to is the intended type (e.g. MeasurementSystemProfileId).
    to: String,
    // msg is a useful msg
    msg: String,
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to parse UUIDv4 input '{}' to {}: {}",
            self.from, self.to, self.msg,
        )
    }
}

impl Error for IdParseError {}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementSystemProfileId
///
/// Primary key for a measurement_system_profiles table entry, which is the table
/// containing general metadata about a machine profile.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementSystemProfileId(pub uuid::Uuid);

impl MeasurementSystemProfileId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input system profile ID: {}", e)))
    }
}

impl From<MeasurementSystemProfileId> for uuid::Uuid {
    fn from(id: MeasurementSystemProfileId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementSystemProfileId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementSystemProfileId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementSystemProfileId(parsed))
    }
}

impl fmt::Display for MeasurementSystemProfileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementSystemProfileId {
    fn db_primary_uuid_name() -> &'static str {
        "profile_id"
    }
}

impl From<MeasurementSystemProfileId> for Uuid {
    fn from(val: MeasurementSystemProfileId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementSystemProfileId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementSystemProfileId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementSystemProfileAttrId
///
/// Primary key for a measurement_system_profiles_attrs table entry, which is
/// the table containing the attributes used to map machines to profiles.
///
/// Includes code for various implementations.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementSystemProfileAttrId(pub uuid::Uuid);

impl MeasurementSystemProfileAttrId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg).map_err(|e| {
            Status::invalid_argument(format!("bad input system profile attribute ID: {}", e))
        })
    }
}

impl From<MeasurementSystemProfileAttrId> for uuid::Uuid {
    fn from(id: MeasurementSystemProfileAttrId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementSystemProfileAttrId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementSystemProfileAttrId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementSystemProfileAttrId(parsed))
    }
}

impl fmt::Display for MeasurementSystemProfileAttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MeasurementSystemProfileAttrId> for Uuid {
    fn from(val: MeasurementSystemProfileAttrId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementSystemProfileAttrId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementSystemProfileAttrId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementBundleId
///
/// Primary key for a measurement_bundles table entry, where a bundle is
/// a collection of measurements that come from the measurement_bundles table.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, ToTable for printing via prettytable,
/// as well as other various trait impls as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementBundleId(pub uuid::Uuid);

impl MeasurementBundleId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input bundle ID: {}", e)))
    }
}

impl From<MeasurementBundleId> for uuid::Uuid {
    fn from(id: MeasurementBundleId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementBundleId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementBundleId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementBundleId(parsed))
    }
}

impl fmt::Display for MeasurementBundleId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementBundleId {
    fn db_primary_uuid_name() -> &'static str {
        "bundle_id"
    }
}

impl From<MeasurementBundleId> for Uuid {
    fn from(val: MeasurementBundleId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementBundleId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementBundleId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl ToTable for Vec<MeasurementBundleId> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["bundle_id"]);
        for bundle_id in self.iter() {
            table.add_row(prettytable::row![bundle_id]);
        }
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementBundleValueId
///
/// Primary key for a measurement_bundles_values table entry, where a value is
/// a single measurement that is part of a measurement bundle.
///
/// Includes code for various implementations.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementBundleValueId(pub uuid::Uuid);

impl MeasurementBundleValueId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input bundle value ID: {}", e)))
    }
}

impl From<MeasurementBundleValueId> for uuid::Uuid {
    fn from(id: MeasurementBundleValueId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementBundleValueId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementBundleValueId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementBundleValueId(parsed))
    }
}

impl fmt::Display for MeasurementBundleValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MeasurementBundleValueId> for Uuid {
    fn from(val: MeasurementBundleValueId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementBundleValueId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementBundleValueId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementReportId
///
/// Primary key for a measurement_reports table entry, which contains reports
/// of all reported measurement bundles for a given machine.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, Eq, Hash, FromRow, PartialEq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementReportId(pub uuid::Uuid);

impl MeasurementReportId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input report ID: {}", e)))
    }
}

impl From<MeasurementReportId> for uuid::Uuid {
    fn from(id: MeasurementReportId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementReportId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementReportId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementReportId(parsed))
    }
}

impl fmt::Display for MeasurementReportId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementReportId {
    fn db_primary_uuid_name() -> &'static str {
        "report_id"
    }
}

impl From<MeasurementReportId> for Uuid {
    fn from(val: MeasurementReportId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementReportId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementReportId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementReportValueId
///
/// Primary key for a measurement_reports_values table entry, which is the
/// backing values reported for each report into measurement_reports.
///
/// Includes code for various implementations.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementReportValueId(pub uuid::Uuid);

impl MeasurementReportValueId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input report value ID: {}", e)))
    }
}

impl From<MeasurementReportValueId> for uuid::Uuid {
    fn from(id: MeasurementReportValueId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementReportValueId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementReportValueId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementReportValueId(parsed))
    }
}

impl fmt::Display for MeasurementReportValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MeasurementReportValueId> for Uuid {
    fn from(val: MeasurementReportValueId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementReportValueId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementReportValueId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementJournalId
///
/// Primary key for a measurement_journal table entry, which is the journal
/// of all reported measurement bundles for a given machine.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, Eq, Hash, FromRow, PartialEq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementJournalId(pub uuid::Uuid);

impl MeasurementJournalId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input journal ID: {}", e)))
    }
}

impl From<MeasurementJournalId> for uuid::Uuid {
    fn from(id: MeasurementJournalId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementJournalId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementJournalId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementJournalId(parsed))
    }
}

impl fmt::Display for MeasurementJournalId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementJournalId {
    fn db_primary_uuid_name() -> &'static str {
        "journal_id"
    }
}

impl From<MeasurementJournalId> for Uuid {
    fn from(val: MeasurementJournalId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementJournalId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementJournalId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MockMachineId
///
/// Primary key for the mock_machines table, which is a table specific for
/// the PoC/demo for injecting a fake machine.
///
/// Includes code for various implementations.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "text")]
pub struct MockMachineId(pub String);

impl DbPrimaryUuid for MockMachineId {
    fn db_primary_uuid_name() -> &'static str {
        "machine_id"
    }
}

impl From<MockMachineId> for String {
    fn from(id: MockMachineId) -> Self {
        id.0
    }
}

impl FromStr for MockMachineId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        Ok(MockMachineId(input.to_string()))
    }
}

impl fmt::Display for MockMachineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ToTable for Vec<MockMachineId> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["machine_id"]);
        for machine_id in self.iter() {
            table.add_row(prettytable::row![machine_id]);
        }
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MockMachineAttrId
///
/// Primary key for a mock_machines_attrs table entry, which is
/// the table containing the attributes used to configure the
/// mock "discovery" info for a machine.
///
/// Includes code for various implementations.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MockMachineAttrId(pub uuid::Uuid);

impl MockMachineAttrId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad input mock machine attr ID: {}", e)))
    }
}

impl From<MockMachineAttrId> for uuid::Uuid {
    fn from(id: MockMachineAttrId) -> Self {
        id.0
    }
}

impl FromStr for MockMachineAttrId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MockMachineAttrId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MockMachineAttrId(parsed))
    }
}

impl fmt::Display for MockMachineAttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MockMachineAttrId> for Uuid {
    fn from(val: MockMachineAttrId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MockMachineAttrId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MockMachineAttrId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementApprovedMachineId
///
/// Primary key for a measurement_approved_machines table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// into golden measurement bundles.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementApprovedMachineId(pub uuid::Uuid);

impl MeasurementApprovedMachineId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg).map_err(|e| {
            Status::invalid_argument(format!("bad input trusted machine approval ID: {}", e))
        })
    }
}

impl From<MeasurementApprovedMachineId> for uuid::Uuid {
    fn from(id: MeasurementApprovedMachineId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementApprovedMachineId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementApprovedMachineId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementApprovedMachineId(parsed))
    }
}

impl fmt::Display for MeasurementApprovedMachineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementApprovedMachineId {
    fn db_primary_uuid_name() -> &'static str {
        "approval_id"
    }
}

impl From<MeasurementApprovedMachineId> for Uuid {
    fn from(val: MeasurementApprovedMachineId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementApprovedMachineId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementApprovedMachineId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

///////////////////////////////////////////////////////////////////////////////
/// MeasurementApprovedProfileId
///
/// Primary key for a measurement_approved_profiles table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// for a specific profile into golden measurement bundles.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "UUID")]
pub struct MeasurementApprovedProfileId(pub uuid::Uuid);

impl MeasurementApprovedProfileId {
    pub fn from_grpc(msg: Option<Uuid>) -> Result<Self, Status> {
        Self::try_from(msg).map_err(|e| {
            Status::invalid_argument(format!("bad input trusted profile approval ID: {}", e))
        })
    }
}

impl From<MeasurementApprovedProfileId> for uuid::Uuid {
    fn from(id: MeasurementApprovedProfileId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementApprovedProfileId {
    type Err = IdParseError;

    fn from_str(input: &str) -> Result<Self, IdParseError> {
        let parsed = uuid::Uuid::parse_str(input).map_err(|e| IdParseError {
            from: input.to_string(),
            to: "MeasurementApprovedProfileId".to_string(),
            msg: e.to_string(),
        })?;
        Ok(MeasurementApprovedProfileId(parsed))
    }
}

impl fmt::Display for MeasurementApprovedProfileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbPrimaryUuid for MeasurementApprovedProfileId {
    fn db_primary_uuid_name() -> &'static str {
        "approval_id"
    }
}

impl From<MeasurementApprovedProfileId> for Uuid {
    fn from(val: MeasurementApprovedProfileId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<Uuid> for MeasurementApprovedProfileId {
    type Error = IdParseError;
    fn try_from(msg: Uuid) -> Result<Self, IdParseError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<Uuid>> for MeasurementApprovedProfileId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(UuidEmptyStringError {}.into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}
