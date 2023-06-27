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

pub use ::rpc::forge as rpc;
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::{
    db::{
        machine_interface::MachineInterface,
        machine_interface_address::MachineInterfaceAddress,
        network_segment::{NetworkSegment, NetworkSegmentSearchConfig},
        UuidKeyedObjectFilter,
    },
    model::{instance::config::network::InstanceInterfaceConfig, machine::machine_id::MachineId},
    CarbideError,
};

#[derive(Default, Clone)]
pub struct EthVirtData {
    pub asn: u32,
    pub dhcp_servers: Vec<String>,
    pub route_servers: Vec<String>,
}

pub async fn admin_network(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: &MachineId,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let admin_segment = NetworkSegment::admin(txn)
        .await
        .map_err(CarbideError::from)?;

    let prefix = match admin_segment.prefixes.get(0) {
        Some(p) => p,
        None => {
            return Err(Status::internal(format!(
                "Admin network segment '{}' has no network_prefix, expected 1",
                admin_segment.id,
            )));
        }
    };

    let interface =
        MachineInterface::find_by_machine_and_segment(txn, host_machine_id, admin_segment.id)
            .await
            .map_err(CarbideError::from)?;

    let address = MachineInterfaceAddress::find_ipv4_for_interface(txn, interface.id)
        .await
        .map_err(CarbideError::from)?;

    let cfg = rpc::FlatInterfaceConfig {
        function: rpc::InterfaceFunctionType::Physical.into(),
        vlan_id: admin_segment.vlan_id.unwrap_or_default() as u32,
        vni: 0, // admin isn't an overlay network, so no vni
        gateway: prefix.gateway_cidr().unwrap_or_default(),
        ip: address.address.ip().to_string(),
    };
    Ok(cfg)
}

pub async fn tenant_network(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
    iface: &InstanceInterfaceConfig,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let segments = &NetworkSegment::find(
        txn,
        UuidKeyedObjectFilter::One(iface.network_segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .map_err(CarbideError::from)?;
    let Some(segment) = segments.get(0) else {
        return Err(Status::internal(format!(
            "Tenant network segment id '{}' matched more than one segment",
            iface.network_segment_id
        )));
    };

    let v4_prefix = segment
        .prefixes
        .iter()
        .find(|prefix| prefix.prefix.is_ipv4())
        .ok_or_else(|| {
            Status::internal(format!(
                "No IPv4 prefix is available for instance {} on segment {}",
                instance_id, segment.id
            ))
        })?;
    let address = iface.ip_addrs.get(&v4_prefix.id).ok_or_else(|| {
        Status::internal(format!(
            "No IPv4 address is available for instance {} on segment {}",
            instance_id, segment.id
        ))
    })?;

    let rpc_ft: rpc::InterfaceFunctionType = iface.function_id.function_type().into();
    Ok(rpc::FlatInterfaceConfig {
        function: rpc_ft.into(),
        vlan_id: segment.vlan_id.unwrap_or_default() as u32,
        vni: segment.vni.unwrap_or_default() as u32,
        gateway: v4_prefix.gateway_cidr().unwrap_or_default(),
        ip: address.to_string(),
    })
}
