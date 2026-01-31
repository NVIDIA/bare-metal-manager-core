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

use crate::typed_uuids::{TypedUuid, UuidSubtype};

/// Marker type for VpcPeeringId
pub struct VpcPeeringIdMarker;

impl UuidSubtype for VpcPeeringIdMarker {
    const TYPE_NAME: &'static str = "VpcPeeringId";
}

/// VpcPeeringId is a strongly typed UUID specific to a VPC peering relationship.
pub type VpcPeeringId = TypedUuid<VpcPeeringIdMarker>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_uuid_tests;
    typed_uuid_tests!(VpcPeeringId, "VpcPeeringId", "id");
}
