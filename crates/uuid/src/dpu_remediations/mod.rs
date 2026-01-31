/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/// Marker type for RemediationId
pub struct RemediationIdMarker;

impl UuidSubtype for RemediationIdMarker {
    const TYPE_NAME: &'static str = "RemediationId";
}

/// RemediationId is a strongly typed UUID specific to a Remediation ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
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

/// Marker type for RemediationPrefixId
pub struct RemediationPrefixMarker;

impl UuidSubtype for RemediationPrefixMarker {
    const TYPE_NAME: &'static str = "RemediationPrefixId";
}

pub type RemediationPrefixId = TypedUuid<RemediationPrefixMarker>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = RemediationId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = RemediationId::from(orig);
        let as_string = id.to_string();
        let parsed = RemediationId::from_str(&as_string).expect("failed to parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_json_round_trip() {
        let id = RemediationId::new();
        let json = serde_json::to_string(&id).expect("failed to serialize");
        let parsed: RemediationId = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(id, parsed);
        assert!(json.starts_with('"') && json.ends_with('"'));
    }

    #[test]
    fn test_ordering() {
        let id1 = RemediationId::from(uuid::Uuid::nil());
        let id2 = RemediationId::from(uuid::Uuid::max());
        assert!(id1 < id2);
    }

    #[test]
    fn test_default() {
        let id = RemediationId::default();
        assert_eq!(uuid::Uuid::from(id), uuid::Uuid::nil());
    }

    #[test]
    fn test_copy() {
        let id1 = RemediationId::new();
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hash_consistency() {
        let uuid = uuid::Uuid::new_v4();
        let id1 = RemediationId::from(uuid);
        let id2 = RemediationId::from(uuid);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_debug_includes_type_name() {
        let id = RemediationId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("RemediationId"));
    }

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
