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
 */

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::PgTypeInfo,
    {Database, Postgres},
};

use crate::UuidConversionError;
use crate::machine::MachineId;
use crate::typed_uuids::{TypedUuid, UuidSubtype};

// ============================================================================
// TrustedMachineId - Special enum type (not migrated to TypedUuid)
// ============================================================================

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

impl crate::DbPrimaryUuid for TrustedMachineId {
    fn db_primary_uuid_name() -> &'static str {
        "machine_id"
    }
}

// ============================================================================
// MeasurementSystemProfileId
// ============================================================================

/// Marker type for MeasurementSystemProfileId
pub struct MeasurementSystemProfileIdMarker;

impl UuidSubtype for MeasurementSystemProfileIdMarker {
    const TYPE_NAME: &'static str = "MeasurementSystemProfileId";
    const DB_COLUMN_NAME: &'static str = "profile_id";
}

/// Primary key for a measurement_system_profiles table entry, which is the table
/// containing general metadata about a machine profile.
pub type MeasurementSystemProfileId = TypedUuid<MeasurementSystemProfileIdMarker>;

// ============================================================================
// MeasurementSystemProfileAttrId
// ============================================================================

/// Marker type for MeasurementSystemProfileAttrId
pub struct MeasurementSystemProfileAttrIdMarker;

impl UuidSubtype for MeasurementSystemProfileAttrIdMarker {
    const TYPE_NAME: &'static str = "MeasurementSystemProfileAttrId";
}

/// Primary key for a measurement_system_profiles_attrs table entry, which is
/// the table containing the attributes used to map machines to profiles.
pub type MeasurementSystemProfileAttrId = TypedUuid<MeasurementSystemProfileAttrIdMarker>;

// ============================================================================
// MeasurementBundleId
// ============================================================================

/// Marker type for MeasurementBundleId
pub struct MeasurementBundleIdMarker;

impl UuidSubtype for MeasurementBundleIdMarker {
    const TYPE_NAME: &'static str = "MeasurementBundleId";
    const DB_COLUMN_NAME: &'static str = "bundle_id";
}

/// Primary key for a measurement_bundles table entry, where a bundle is
/// a collection of measurements that come from the measurement_bundles table.
pub type MeasurementBundleId = TypedUuid<MeasurementBundleIdMarker>;

// ============================================================================
// MeasurementBundleValueId
// ============================================================================

/// Marker type for MeasurementBundleValueId
pub struct MeasurementBundleValueIdMarker;

impl UuidSubtype for MeasurementBundleValueIdMarker {
    const TYPE_NAME: &'static str = "MeasurementBundleValueId";
}

/// Primary key for a measurement_bundles_values table entry, where a value is
/// a single measurement that is part of a measurement bundle.
pub type MeasurementBundleValueId = TypedUuid<MeasurementBundleValueIdMarker>;

// ============================================================================
// MeasurementReportId
// ============================================================================

/// Marker type for MeasurementReportId
pub struct MeasurementReportIdMarker;

impl UuidSubtype for MeasurementReportIdMarker {
    const TYPE_NAME: &'static str = "MeasurementReportId";
    const DB_COLUMN_NAME: &'static str = "report_id";
}

/// Primary key for a measurement_reports table entry, which contains reports
/// of all reported measurement bundles for a given machine.
pub type MeasurementReportId = TypedUuid<MeasurementReportIdMarker>;

// ============================================================================
// MeasurementReportValueId
// ============================================================================

/// Marker type for MeasurementReportValueId
pub struct MeasurementReportValueIdMarker;

impl UuidSubtype for MeasurementReportValueIdMarker {
    const TYPE_NAME: &'static str = "MeasurementReportValueId";
}

/// Primary key for a measurement_reports_values table entry, which is the
/// backing values reported for each report into measurement_reports.
pub type MeasurementReportValueId = TypedUuid<MeasurementReportValueIdMarker>;

// ============================================================================
// MeasurementJournalId
// ============================================================================

/// Marker type for MeasurementJournalId
pub struct MeasurementJournalIdMarker;

impl UuidSubtype for MeasurementJournalIdMarker {
    const TYPE_NAME: &'static str = "MeasurementJournalId";
    const DB_COLUMN_NAME: &'static str = "journal_id";
}

/// Primary key for a measurement_journal table entry, which is the journal
/// of all reported measurement bundles for a given machine.
pub type MeasurementJournalId = TypedUuid<MeasurementJournalIdMarker>;

// ============================================================================
// MeasurementApprovedMachineId
// ============================================================================

/// Marker type for MeasurementApprovedMachineId
pub struct MeasurementApprovedMachineIdMarker;

impl UuidSubtype for MeasurementApprovedMachineIdMarker {
    const TYPE_NAME: &'static str = "MeasurementApprovedMachineId";
    const DB_COLUMN_NAME: &'static str = "approval_id";
}

/// Primary key for a measurement_approved_machines table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// into golden measurement bundles.
pub type MeasurementApprovedMachineId = TypedUuid<MeasurementApprovedMachineIdMarker>;

// ============================================================================
// MeasurementApprovedProfileId
// ============================================================================

/// Marker type for MeasurementApprovedProfileId
pub struct MeasurementApprovedProfileIdMarker;

impl UuidSubtype for MeasurementApprovedProfileIdMarker {
    const TYPE_NAME: &'static str = "MeasurementApprovedProfileId";
    const DB_COLUMN_NAME: &'static str = "approval_id";
}

/// Primary key for a measurement_approved_profiles table entry, which is how
/// control is enabled at the site-level for auto-approving machine reports
/// for a specific profile into golden measurement bundles.
pub type MeasurementApprovedProfileId = TypedUuid<MeasurementApprovedProfileIdMarker>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::DbPrimaryUuid;

    // MeasurementSystemProfileId tests
    #[test]
    fn test_system_profile_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementSystemProfileId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_system_profile_id_db_column() {
        assert_eq!(
            MeasurementSystemProfileId::db_primary_uuid_name(),
            "profile_id"
        );
    }

    #[test]
    fn test_system_profile_id_debug() {
        let id = MeasurementSystemProfileId::from(uuid::Uuid::nil());
        assert!(format!("{:?}", id).contains("MeasurementSystemProfileId"));
    }

    // MeasurementSystemProfileAttrId tests
    #[test]
    fn test_system_profile_attr_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementSystemProfileAttrId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_system_profile_attr_id_db_column() {
        assert_eq!(MeasurementSystemProfileAttrId::db_primary_uuid_name(), "id");
    }

    // MeasurementBundleId tests
    #[test]
    fn test_bundle_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementBundleId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_bundle_id_db_column() {
        assert_eq!(MeasurementBundleId::db_primary_uuid_name(), "bundle_id");
    }

    #[test]
    fn test_bundle_id_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementBundleId::from(orig);
        let parsed = MeasurementBundleId::from_str(&id.to_string()).unwrap();
        assert_eq!(id, parsed);
    }

    // MeasurementBundleValueId tests
    #[test]
    fn test_bundle_value_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementBundleValueId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_bundle_value_id_db_column() {
        assert_eq!(MeasurementBundleValueId::db_primary_uuid_name(), "id");
    }

    // MeasurementReportId tests
    #[test]
    fn test_report_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementReportId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_report_id_db_column() {
        assert_eq!(MeasurementReportId::db_primary_uuid_name(), "report_id");
    }

    #[test]
    fn test_report_id_json_round_trip() {
        let id = MeasurementReportId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: MeasurementReportId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    // MeasurementReportValueId tests
    #[test]
    fn test_report_value_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementReportValueId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_report_value_id_db_column() {
        assert_eq!(MeasurementReportValueId::db_primary_uuid_name(), "id");
    }

    // MeasurementJournalId tests
    #[test]
    fn test_journal_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementJournalId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_journal_id_db_column() {
        assert_eq!(MeasurementJournalId::db_primary_uuid_name(), "journal_id");
    }

    // MeasurementApprovedMachineId tests
    #[test]
    fn test_approved_machine_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementApprovedMachineId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_approved_machine_id_db_column() {
        assert_eq!(
            MeasurementApprovedMachineId::db_primary_uuid_name(),
            "approval_id"
        );
    }

    // MeasurementApprovedProfileId tests
    #[test]
    fn test_approved_profile_id_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = MeasurementApprovedProfileId::from(orig);
        assert_eq!(uuid::Uuid::from(id), orig);
    }

    #[test]
    fn test_approved_profile_id_db_column() {
        assert_eq!(
            MeasurementApprovedProfileId::db_primary_uuid_name(),
            "approval_id"
        );
    }

    // TrustedMachineId tests (special enum type)
    #[test]
    fn test_trusted_machine_id_any() {
        let id = TrustedMachineId::from_str("*").expect("failed to parse");
        assert_eq!(id, TrustedMachineId::Any);
        assert_eq!(id.to_string(), "*");
    }

    #[test]
    fn test_trusted_machine_id_db_column_name() {
        assert_eq!(TrustedMachineId::db_primary_uuid_name(), "machine_id");
    }
}
