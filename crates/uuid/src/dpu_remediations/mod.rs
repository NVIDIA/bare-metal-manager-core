/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::convert::TryFrom;

use crate::typed_uuids::{TypedUuid, UuidSubtype};

/// Marker type for RemediationId.
pub struct RemediationIdMarker;

impl UuidSubtype for RemediationIdMarker {
    const TYPE_NAME: &'static str = "RemediationId";
}

/// RemediationId is a strongly typed UUID specific to a Remediation ID.
pub type RemediationId = TypedUuid<RemediationIdMarker>;

impl From<RemediationId> for Option<uuid::Uuid> {
    fn from(val: RemediationId) -> Self {
        Some(val.into())
    }
}

impl TryFrom<Option<uuid::Uuid>> for RemediationId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<uuid::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(eyre::eyre!("missing remediation_id argument").into());
        };
        Ok(Self::from(input_uuid))
    }
}

/// Marker type for RemediationPrefixId.
pub struct RemediationPrefixMarker;

impl UuidSubtype for RemediationPrefixMarker {
    const TYPE_NAME: &'static str = "RemediationPrefixId";
}

pub type RemediationPrefixId = TypedUuid<RemediationPrefixMarker>;

#[cfg(test)]
mod remediation_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    // Run all boilerplate TypedUuid tests for this type, also
    // ensuring TYPE_NAME and DB_COLUMN_NAME test correctly.
    typed_uuid_tests!(RemediationId, "RemediationId", "id");

    // Additional tests for RemediationId-specific conversions.
    #[test]
    fn test_into_option_uuid() {
        let id = RemediationId::new();
        let opt: Option<uuid::Uuid> = id.into();
        assert!(opt.is_some());
        assert_eq!(opt.unwrap(), uuid::Uuid::from(id));
    }

    #[test]
    fn test_try_from_option_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let id = RemediationId::try_from(Some(uuid)).expect("failed to convert");
        assert_eq!(uuid::Uuid::from(id), uuid);

        let err = RemediationId::try_from(None);
        assert!(err.is_err());
    }
}

#[cfg(test)]
mod remediation_prefix_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    // Run all boilerplate TypedUuid tests for this type, also
    // ensuring TYPE_NAME and DB_COLUMN_NAME test correctly.
    typed_uuid_tests!(RemediationPrefixId, "RemediationPrefixId", "id");
}
