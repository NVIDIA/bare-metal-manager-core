/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::network::NetworkSegmentId;
use mac_address::MacAddress;
use model::dhcp_record::DhcpRecord;
use sqlx::PgConnection;

use crate::DatabaseError;

pub async fn find_by_mac_address(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
    segment_id: &NetworkSegmentId,
) -> Result<DhcpRecord, DatabaseError> {
    let query = "SELECT * FROM machine_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid";
    sqlx::query_as(query)
        .bind(mac_address)
        .bind(segment_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
