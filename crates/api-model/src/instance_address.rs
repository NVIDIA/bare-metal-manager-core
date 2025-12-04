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
use carbide_uuid::instance::InstanceId;
use carbide_uuid::network::NetworkSegmentId;
use sqlx::FromRow;

#[derive(Debug, FromRow, Clone)]
pub struct InstanceAddress {
    pub instance_id: InstanceId,
    pub segment_id: NetworkSegmentId,
    // pub id: Uuid,          // unused
    pub address: std::net::IpAddr,
    // pub prefix: IpNetwork, // unused
}
