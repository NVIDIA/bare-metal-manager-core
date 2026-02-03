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

use crate::typed_uuids::{TypedUuid, UuidSubtype};

/// Marker type for ExtensionServiceId
pub struct ExtensionServiceIdMarker;

impl UuidSubtype for ExtensionServiceIdMarker {
    const TYPE_NAME: &'static str = "ExtensionServiceId";
}

/// ExtensionServiceId is a strongly typed UUID specific to an extension service.
pub type ExtensionServiceId = TypedUuid<ExtensionServiceIdMarker>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = ExtensionServiceId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = ExtensionServiceId::from(orig);
        let as_string = id.to_string();
        let parsed = ExtensionServiceId::from_str(&as_string).expect("failed to parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_json_round_trip() {
        let id = ExtensionServiceId::new();
        let json = serde_json::to_string(&id).expect("failed to serialize");
        let parsed: ExtensionServiceId =
            serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(id, parsed);
        assert!(json.starts_with('"') && json.ends_with('"'));
    }

    #[test]
    fn test_ordering() {
        let id1 = ExtensionServiceId::from(uuid::Uuid::nil());
        let id2 = ExtensionServiceId::from(uuid::Uuid::max());
        assert!(id1 < id2);
    }

    #[test]
    fn test_default() {
        let id = ExtensionServiceId::default();
        assert_eq!(uuid::Uuid::from(id), uuid::Uuid::nil());
    }

    #[test]
    fn test_copy() {
        let id1 = ExtensionServiceId::new();
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hash_consistency() {
        let uuid = uuid::Uuid::new_v4();
        let id1 = ExtensionServiceId::from(uuid);
        let id2 = ExtensionServiceId::from(uuid);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_debug_includes_type_name() {
        let id = ExtensionServiceId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("ExtensionServiceId"));
    }
}
