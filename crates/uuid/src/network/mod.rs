/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
mod network_segment_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    typed_uuid_tests!(NetworkSegmentId, "NetworkSegmentId", "id");
}

#[cfg(test)]
mod network_prefix_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    typed_uuid_tests!(NetworkPrefixId, "NetworkPrefixId", "id");
}
