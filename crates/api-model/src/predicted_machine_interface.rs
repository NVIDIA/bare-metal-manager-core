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
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::FromRow;
use uuid::Uuid;

use crate::network_segment::NetworkSegmentType;

#[derive(Debug, Clone, FromRow)]
pub struct PredictedMachineInterface {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}

#[derive(Debug, Clone)]
pub struct NewPredictedMachineInterface<'a> {
    pub machine_id: &'a MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}
