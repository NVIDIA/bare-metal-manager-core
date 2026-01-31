/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/// Marker type for VpcId
pub struct VpcIdMarker;

impl UuidSubtype for VpcIdMarker {
    const TYPE_NAME: &'static str = "VpcId";
}

/// VpcId is a strongly typed UUID specific to a VPC ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
pub type VpcId = TypedUuid<VpcIdMarker>;

/// Marker type for VpcPrefixId
pub struct VpcPrefixMarker;

impl UuidSubtype for VpcPrefixMarker {
    const TYPE_NAME: &'static str = "VpcPrefixId";
}

pub type VpcPrefixId = TypedUuid<VpcPrefixMarker>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_vpc_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = VpcId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_vpc_id_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = VpcId::from(orig);
        let as_string = id.to_string();
        let parsed = VpcId::from_str(&as_string).expect("failed to parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_vpc_id_json_round_trip() {
        let id = VpcId::new();
        let json = serde_json::to_string(&id).expect("failed to serialize");
        let parsed: VpcId = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(id, parsed);
        assert!(json.starts_with('"') && json.ends_with('"'));
    }

    #[test]
    fn test_vpc_id_ordering() {
        let id1 = VpcId::from(uuid::Uuid::nil());
        let id2 = VpcId::from(uuid::Uuid::max());
        assert!(id1 < id2);
    }

    #[test]
    fn test_vpc_id_default() {
        let id = VpcId::default();
        assert_eq!(uuid::Uuid::from(id), uuid::Uuid::nil());
    }

    #[test]
    fn test_vpc_id_copy() {
        let id1 = VpcId::new();
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_vpc_id_hash_consistency() {
        let uuid = uuid::Uuid::new_v4();
        let id1 = VpcId::from(uuid);
        let id2 = VpcId::from(uuid);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_vpc_id_debug_includes_type_name() {
        let id = VpcId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("VpcId"));
    }
}
