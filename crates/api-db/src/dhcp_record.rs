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

use carbide_network::ip::IpAddressFamily;
use carbide_uuid::network::NetworkSegmentId;
use mac_address::MacAddress;
use model::dhcp_record::DhcpRecord;
use sqlx::PgConnection;

use crate::DatabaseError;

/// Look up the DHCP record for a MAC on a segment, for one address family.
///
/// Returns `Ok(None)` when the `machine_dhcp_records` view has no row for the
/// triple -- e.g. no address of that family is allocated to the interface, or
/// the allocated address has no containing prefix on the segment.
pub async fn find_by_mac_address(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
    segment_id: &NetworkSegmentId,
    address_family: IpAddressFamily,
) -> Result<Option<DhcpRecord>, DatabaseError> {
    let query = "SELECT * FROM machine_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid AND family(address) = $3";
    sqlx::query_as(query)
        .bind(mac_address)
        .bind(segment_id)
        .bind(address_family.pg_family())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
