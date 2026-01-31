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

/// Marker type for NvLinkPartitionId
pub struct NvLinkPartitionIdMarker;

impl UuidSubtype for NvLinkPartitionIdMarker {
    const TYPE_NAME: &'static str = "NvLinkPartitionId";
}

/// NvLinkPartitionId is a strongly typed UUID specific to an NvLink partition.
pub type NvLinkPartitionId = TypedUuid<NvLinkPartitionIdMarker>;

/// Marker type for NvLinkLogicalPartitionId
pub struct NvLinkLogicalPartitionIdMarker;

impl UuidSubtype for NvLinkLogicalPartitionIdMarker {
    const TYPE_NAME: &'static str = "NvLinkLogicalPartitionId";
}

/// NvLinkLogicalPartitionId is a strongly typed UUID for NvLink logical partitions.
pub type NvLinkLogicalPartitionId = TypedUuid<NvLinkLogicalPartitionIdMarker>;

/// Marker type for NvLinkDomainId
pub struct NvLinkDomainIdMarker;

impl UuidSubtype for NvLinkDomainIdMarker {
    const TYPE_NAME: &'static str = "NvLinkDomainId";
}

/// NvLinkDomainId is a strongly typed UUID for NvLink domains.
pub type NvLinkDomainId = TypedUuid<NvLinkDomainIdMarker>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use super::*;

    // NvLinkPartitionId tests
    #[test]
    fn test_partition_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NvLinkPartitionId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_partition_id_string_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NvLinkPartitionId::from(orig);
        let as_string = id.to_string();
        let parsed = NvLinkPartitionId::from_str(&as_string).expect("failed to parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_partition_id_json_round_trip() {
        let id = NvLinkPartitionId::new();
        let json = serde_json::to_string(&id).expect("failed to serialize");
        let parsed: NvLinkPartitionId = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(id, parsed);
        assert!(json.starts_with('"') && json.ends_with('"'));
    }

    #[test]
    fn test_partition_id_ordering() {
        let id1 = NvLinkPartitionId::from(uuid::Uuid::nil());
        let id2 = NvLinkPartitionId::from(uuid::Uuid::max());
        assert!(id1 < id2);
    }

    #[test]
    fn test_partition_id_default() {
        let id = NvLinkPartitionId::default();
        assert_eq!(uuid::Uuid::from(id), uuid::Uuid::nil());
    }

    #[test]
    fn test_partition_id_copy() {
        let id1 = NvLinkPartitionId::new();
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_partition_id_hash_consistency() {
        let uuid = uuid::Uuid::new_v4();
        let id1 = NvLinkPartitionId::from(uuid);
        let id2 = NvLinkPartitionId::from(uuid);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_partition_id_debug_includes_type_name() {
        let id = NvLinkPartitionId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("NvLinkPartitionId"));
    }

    // NvLinkLogicalPartitionId tests
    #[test]
    fn test_logical_partition_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NvLinkLogicalPartitionId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_logical_partition_id_debug_includes_type_name() {
        let id = NvLinkLogicalPartitionId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("NvLinkLogicalPartitionId"));
    }

    // NvLinkDomainId tests
    #[test]
    fn test_domain_id_uuid_round_trip() {
        let orig = uuid::Uuid::new_v4();
        let id = NvLinkDomainId::from(orig);
        let back = uuid::Uuid::from(id);
        assert_eq!(orig, back);
    }

    #[test]
    fn test_domain_id_debug_includes_type_name() {
        let id = NvLinkDomainId::from(uuid::Uuid::nil());
        let debug = format!("{:?}", id);
        assert!(debug.contains("NvLinkDomainId"));
    }
}
