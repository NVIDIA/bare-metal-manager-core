/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use ::rpc::forge as rpc;

use crate::{
    dhcp::allocation::DhcpError, model::instance::config::network::InterfaceFunctionId,
    CarbideError, CarbideResult,
};

use super::instance::Instance;

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug, FromRow)]
pub struct DhcpRecord {
    machine_id: Option<uuid::Uuid>,
    segment_id: uuid::Uuid,
    machine_interface_id: uuid::Uuid,
    subdomain_id: Option<uuid::Uuid>,

    fqdn: String,

    mac_address: MacAddress,
    address: IpNetwork,
    mtu: i32,

    prefix: IpNetwork,
    gateway: Option<IpNetwork>,
}

impl From<DhcpRecord> for rpc::DhcpRecord {
    fn from(record: DhcpRecord) -> Self {
        Self {
            machine_id: record.machine_id.map(rpc::Uuid::from),
            machine_interface_id: Some(record.machine_interface_id.into()),
            segment_id: Some(record.segment_id.into()),
            subdomain_id: record.subdomain_id.map(rpc::Uuid::from),
            fqdn: record.fqdn,
            mac_address: record.mac_address.to_string(),
            address: record.address.to_string(),
            mtu: record.mtu,
            prefix: record.prefix.to_string(),
            gateway: record.gateway.map(|gw| gw.to_string()),
        }
    }
}

impl DhcpRecord {
    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: &MacAddress,
        segment_id: &uuid::Uuid,
    ) -> CarbideResult<DhcpRecord> {
        Ok(sqlx::query_as("SELECT * FROM machine_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid")
            .bind(mac_address)
            .bind(segment_id)
            .fetch_one(&mut *txn).await?)
    }

    pub fn address(&self) -> IpNetwork {
        self.address
    }
}

#[derive(Debug)]
pub struct InstanceDhcpRecord {
    machine_id: Option<uuid::Uuid>,
    segment_id: uuid::Uuid,
    machine_interface_id: uuid::Uuid,
    subdomain_id: Option<uuid::Uuid>,

    fqdn: String,

    mac_address: Option<MacAddress>,
    address: IpNetwork,
    mtu: i32,

    prefix: IpNetwork,
    gateway: Option<IpNetwork>,
    function_id: Option<InterfaceFunctionId>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for InstanceDhcpRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(InstanceDhcpRecord {
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            machine_interface_id: row.try_get("machine_interface_id")?,
            subdomain_id: row.try_get("subdomain_id")?,
            fqdn: row.try_get("fqdn")?,
            mac_address: None,
            address: row.try_get("address")?,
            mtu: row.try_get("mtu")?,
            prefix: row.try_get("prefix")?,
            gateway: row.try_get("gateway")?,
            function_id: None,
        })
    }
}

impl TryFrom<InstanceDhcpRecord> for rpc::DhcpRecord {
    type Error = CarbideError;
    fn try_from(record: InstanceDhcpRecord) -> CarbideResult<Self> {
        Ok(Self {
            machine_id: record.machine_id.map(rpc::Uuid::from),
            machine_interface_id: match record.function_id.ok_or_else(|| {
                DhcpError::MissingCircuitIdForMachine(
                    record
                        .machine_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                )
            })? {
                InterfaceFunctionId::PhysicalFunctionId {} => {
                    Some(record.machine_interface_id.into())
                }
                InterfaceFunctionId::VirtualFunctionId { .. } => None,
            },
            segment_id: Some(record.segment_id.into()),
            subdomain_id: record.subdomain_id.map(rpc::Uuid::from),
            fqdn: record.fqdn,
            mac_address: record
                .mac_address
                .ok_or_else(|| CarbideError::InvalidArgument("Unknown Mac".to_string()))?
                .to_string(),
            address: record.address.to_string(),
            mtu: record.mtu,
            prefix: record.prefix.to_string(),
            gateway: record.gateway.map(|gw| gw.to_string()),
        })
    }
}

impl InstanceDhcpRecord {
    fn update_mac(&mut self, mac_address: MacAddress) {
        self.mac_address = Some(mac_address);
    }

    fn update_function_id(&mut self, function_id: InterfaceFunctionId) {
        self.function_id = Some(function_id)
    }

    pub async fn find_for_instance(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: MacAddress,
        circuit_id: String,
        instance: Instance,
    ) -> CarbideResult<InstanceDhcpRecord> {
        let mut record: InstanceDhcpRecord = sqlx::query_as("SELECT * FROM instance_dhcp_records WHERE machine_id=$1::uuid AND circuit_id=$2 AND family(prefix) = 4")
            .bind(instance.machine_id)
            .bind(circuit_id.clone())
            .fetch_one(&mut *txn).await?;

        record.update_mac(mac_address);
        let function_id =
            crate::instance::circuit_id_to_function_id(&mut *txn, instance.id, circuit_id.clone())
                .await?;
        record.update_function_id(function_id);
        Ok(record)
    }
    pub fn address(&self) -> IpNetwork {
        self.address
    }
}
