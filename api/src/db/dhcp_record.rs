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

use ::rpc::forge as rpc;
use forge_uuid::{
    domain::DomainId, machine::MachineId, machine::MachineInterfaceId, network::NetworkSegmentId,
};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::{FromRow, PgConnection};
use std::net::IpAddr;

use crate::db::DatabaseError;

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response.
///
/// A DhcpRecord is populated by a database view (named machine_dhcp_records).
///
#[derive(Debug, FromRow)]
pub struct DhcpRecord {
    machine_id: Option<MachineId>,
    segment_id: NetworkSegmentId,
    machine_interface_id: MachineInterfaceId,
    subdomain_id: Option<DomainId>,

    fqdn: String,

    mac_address: MacAddress,
    address: IpAddr,
    mtu: i32,

    prefix: IpNetwork,
    gateway: Option<IpAddr>,

    last_invalidation_time: chrono::DateTime<chrono::Utc>,
}

impl From<DhcpRecord> for rpc::DhcpRecord {
    fn from(record: DhcpRecord) -> Self {
        Self {
            machine_id: record.machine_id.map(|id| id.into()),
            machine_interface_id: Some(record.machine_interface_id.into()),
            segment_id: Some(record.segment_id.into()),
            subdomain_id: record.subdomain_id.map(::rpc::common::Uuid::from),
            fqdn: record.fqdn,
            mac_address: record.mac_address.to_string(),
            address: record.address.to_string(),
            mtu: record.mtu,
            prefix: record.prefix.to_string(),
            gateway: record.gateway.map(|gw| gw.to_string()),
            booturl: None, // TODO(ajf): extend database, synthesize URL
            last_invalidation_time: Some(record.last_invalidation_time.into()),
        }
    }
}

impl DhcpRecord {
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
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
