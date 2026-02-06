/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
