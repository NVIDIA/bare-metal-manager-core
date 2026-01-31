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

/// Marker type for NetworkSegmentId
pub struct NetworkSegmentIdMarker;

impl UuidSubtype for NetworkSegmentIdMarker {
    const TYPE_NAME: &'static str = "NetworkSegmentId";
}

/// NetworkSegmentId is a strongly typed UUID specific to a network
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc.
pub type NetworkSegmentId = TypedUuid<NetworkSegmentIdMarker>;

/// Marker type for NetworkPrefixId
pub struct NetworkPrefixIdMarker;

impl UuidSubtype for NetworkPrefixIdMarker {
    const TYPE_NAME: &'static str = "NetworkPrefixId";
}

/// NetworkPrefixId is a strongly typed UUID for network prefixes.
pub type NetworkPrefixId = TypedUuid<NetworkPrefixIdMarker>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use super::*;

    // NetworkSegmentId tests
    #[test]
    fn test_segment_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NetworkSegmentId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_segment_id_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NetworkSegmentId::from(orig);
        let as_string = id.to_string();
        let parsed = NetworkSegmentId::from_str(&as_string).expect("failed to parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_segment_id_json_round_trip() {
        let id = NetworkSegmentId::new();
        let json = serde_json::to_string(&id).expect("failed to serialize");
        let parsed: NetworkSegmentId = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(id, parsed);
        assert!(json.starts_with('"') && json.ends_with('"'));
    }

    #[test]
    fn test_segment_id_ordering() {
        let id1 = NetworkSegmentId::from(uuid::Uuid::nil());
        let id2 = NetworkSegmentId::from(uuid::Uuid::max());
        assert!(id1 < id2);
    }

    #[test]
    fn test_segment_id_default() {
        let id = NetworkSegmentId::default();
        assert_eq!(uuid::Uuid::from(id), uuid::Uuid::nil());
    }

    #[test]
    fn test_segment_id_copy() {
        let id1 = NetworkSegmentId::new();
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_segment_id_hash_consistency() {
        let uuid = uuid::Uuid::new_v4();
        let id1 = NetworkSegmentId::from(uuid);
        let id2 = NetworkSegmentId::from(uuid);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_segment_id_debug_includes_type_name() {
        let id = NetworkSegmentId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("NetworkSegmentId"));
    }

    // NetworkPrefixId tests
    #[test]
    fn test_network_prefix_id_serialization() {
        // Make sure NetworkPrefixId serializes as a simple UUID.
        let id = uuid::Uuid::new_v4();
        let network_prefix_id = NetworkPrefixId::from(id);

        let uuid_json = serde_json::to_string(&id).unwrap();
        let nsid_json = serde_json::to_string(&network_prefix_id).unwrap();

        assert_eq!(uuid_json, nsid_json);
    }

    #[test]
    fn test_prefix_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NetworkPrefixId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_prefix_id_debug_includes_type_name() {
        let id = NetworkPrefixId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("NetworkPrefixId"));
    }
}
