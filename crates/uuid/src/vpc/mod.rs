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
mod vpc_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    typed_uuid_tests!(VpcId, "VpcId", "id");
}

#[cfg(test)]
mod vpc_prefix_id_tests {
    use super::*;
    use crate::typed_uuid_tests;
    typed_uuid_tests!(VpcPrefixId, "VpcPrefixId", "id");
}
