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
 *  Code for defining primary/foreign keys used by the measured boot
 *  database tables.
 *
 *  The idea here is to make it very obvious which type of UUID is being
 *  worked with, since it would be otherwise easy to pass the wrong UUID
 *  to the wrong part of a query. Being able to type the specific ID ends
 *  up catching a lot of potential bugs.
 *
 *  To make this work, the keys must derive {FromRow,Type}, and explicitly
 *  set #[sqlx(type_name = "UUID")]. Without that trifecta, sqlx gets all
 *  mad because it cant bind it as a UUID.
*/

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::PgTypeInfo,
    {Database, FromRow, Postgres, Type},
};

use super::DbPrimaryUuid;
use crate::machine::MachineId;
use crate::{UuidConversionError, grpc_uuid_message};

/// TrustedMachineId is a special adaptation of a
/// Carbide MachineId, which has support for being
/// expressed as a machine ID, or "*", for the purpose
/// of doing trusted machine approvals for measured
/// boot.
///
/// This makes it so you can provide "*" as an input,
/// as well as read it back into a bound instance, for
/// the admin CLI, API calls, and backend.
///
/// It includes all of the necessary trait implementations
/// to allow it to be used as a clap argument, sqlx binding,
/// etc.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustedMachineId {
    MachineId(MachineId),
    Any,
}

impl FromStr for TrustedMachineId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        if input == "*" {
            Ok(Self::Any)
        } else {
            Ok(Self::MachineId(MachineId::from_str(input).map_err(
                |_| UuidConversionError::InvalidMachineId(input.to_string()),
            )?))
        }
    }
}

impl fmt::Display for TrustedMachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Any => write!(f, "*"),
            Self::MachineId(machine_id) => write!(f, "{machine_id}"),
        }
    }
}

// Make TrustedMachineId bindable directly into a sqlx query.
// Similar code exists for other IDs, including MachineId.
#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for TrustedMachineId {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        buf.extend(self.to_string().as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Postgres> for TrustedMachineId {
    fn type_info() -> PgTypeInfo {
        <&str as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <&str as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl DbPrimaryUuid for TrustedMachineId {
    fn db_primary_uuid_name() -> &'static str {
        "machine_id"
    }
}

/// MeasurementSystemProfileId
///
/// Primary key for a measurement_system_profiles table entry, which is the table
/// containing general metadata about a machine profile.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementSystemProfileId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementSystemProfileId);

impl From<MeasurementSystemProfileId> for uuid::Uuid {
    fn from(id: MeasurementSystemProfileId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementSystemProfileId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementSystemProfileId",
                value: input.to_string(),
            }
        })?))
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

/// MeasurementSystemProfileAttrId
///
/// Primary key for a measurement_system_profiles_attrs table entry, which is
/// the table containing the attributes used to map machines to profiles.
///
/// Includes code for various implementations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementSystemProfileAttrId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementSystemProfileAttrId);

impl From<MeasurementSystemProfileAttrId> for uuid::Uuid {
    fn from(id: MeasurementSystemProfileAttrId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementSystemProfileAttrId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementSystemProfileAttrId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for MeasurementSystemProfileAttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// MeasurementBundleId
///
/// Primary key for a measurement_bundles table entry, where a bundle is
/// a collection of measurements that come from the measurement_bundles table.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, ToTable for printing via prettytable,
/// as well as other various trait impls as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementBundleId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementBundleId);

impl From<MeasurementBundleId> for uuid::Uuid {
    fn from(id: MeasurementBundleId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementBundleId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementBundleId",
                value: input.to_string(),
            }
        })?))
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

/// MeasurementBundleValueId
///
/// Primary key for a measurement_bundles_values table entry, where a value is
/// a single measurement that is part of a measurement bundle.
///
/// Includes code for various implementations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementBundleValueId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementBundleValueId);

impl From<MeasurementBundleValueId> for uuid::Uuid {
    fn from(id: MeasurementBundleValueId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementBundleValueId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementBundleValueId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for MeasurementBundleValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// MeasurementReportId
///
/// Primary key for a measurement_reports table entry, which contains reports
/// of all reported measurement bundles for a given machine.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Eq, Hash, Serialize, Deserialize, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementReportId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementReportId);

impl From<MeasurementReportId> for uuid::Uuid {
    fn from(id: MeasurementReportId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementReportId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementReportId",
                value: input.to_string(),
            }
        })?))
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

/// MeasurementReportValueId
///
/// Primary key for a measurement_reports_values table entry, which is the
/// backing values reported for each report into measurement_reports.
///
/// Includes code for various implementations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementReportValueId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementReportValueId);

impl From<MeasurementReportValueId> for uuid::Uuid {
    fn from(id: MeasurementReportValueId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementReportValueId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementReportValueId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for MeasurementReportValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// MeasurementJournalId
///
/// Primary key for a measurement_journal table entry, which is the journal
/// of all reported measurement bundles for a given machine.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Eq, Hash, Serialize, Deserialize, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementJournalId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementJournalId);

impl From<MeasurementJournalId> for uuid::Uuid {
    fn from(id: MeasurementJournalId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementJournalId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementJournalId",
                value: input.to_string(),
            }
        })?))
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

/// MeasurementApprovedMachineId
///
/// Primary key for a measurement_approved_machines table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// into golden measurement bundles.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementApprovedMachineId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementApprovedMachineId);

impl From<MeasurementApprovedMachineId> for uuid::Uuid {
    fn from(id: MeasurementApprovedMachineId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementApprovedMachineId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementApprovedMachineId",
                value: input.to_string(),
            }
        })?))
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

/// MeasurementApprovedProfileId
///
/// Primary key for a measurement_approved_profiles table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// for a specific profile into golden measurement bundles.
///
/// Impls the DbPrimaryUuid trait, which is used for doing generic selects
/// defined in db/interface/common.rs, as well as other various trait impls
/// as required by serde, sqlx, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct MeasurementApprovedProfileId(pub uuid::Uuid);
grpc_uuid_message!(MeasurementApprovedProfileId);

impl From<MeasurementApprovedProfileId> for uuid::Uuid {
    fn from(id: MeasurementApprovedProfileId) -> Self {
        id.0
    }
}

impl FromStr for MeasurementApprovedProfileId {
    type Err = UuidConversionError;

    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "MeasurementApprovedProfileId",
                value: input.to_string(),
            }
        })?))
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
