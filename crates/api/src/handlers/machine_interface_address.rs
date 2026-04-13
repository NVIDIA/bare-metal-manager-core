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

use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::allocation_type::AllocationType;
use rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::Api;
use crate::errors::CarbideError;

/// Resolve the correct segment for a static IP. If the IP is within a
/// managed network prefix, use that segment. Otherwise use the
/// static-assignments anchor segment.
async fn resolve_segment_for_static_ip(
    txn: &mut sqlx::PgConnection,
    ip: std::net::IpAddr,
) -> Result<model::network_segment::NetworkSegment, CarbideError> {
    match db::network_segment::for_relay(txn, ip).await? {
        Some(seg) => Ok(seg),
        None => Ok(db::network_segment::static_assignments(txn).await?),
    }
}

/// Pre-allocate a `machine_interface` with a static address so Site Explorer can discover the BMC
/// at that IP. Expected machine / switch / power shelf handlers call this when the operator sets a
/// configured BMC IP before DHCP has appeared.
///
/// If the IP is within a managed network prefix, the interface is created on that segment.
/// Otherwise it uses the internal `static-assignments` anchor segment.
///
/// Fails if a `machine_interface` already exists for this MAC. Use
/// [`update_preallocated_machine_interface`] to follow up on an existing interface.
pub async fn preallocate_machine_interface(
    txn: &mut sqlx::PgConnection,
    bmc_mac_address: MacAddress,
    bmc_ip: std::net::IpAddr,
) -> Result<(), CarbideError> {
    // Check if an interface already exists for this MAC.
    let existing = db::machine_interface::find_by_mac_address(&mut *txn, bmc_mac_address).await?;
    if !existing.is_empty() {
        return Err(CarbideError::InvalidArgument(format!(
            "a machine interface already exists for MAC {bmc_mac_address}; \
             use update to change the IP address"
        )));
    }

    // Check if the IP is already allocated to another interface.
    if let Some(existing_addr) =
        db::machine_interface_address::find_by_address(&mut *txn, bmc_ip).await?
    {
        return Err(CarbideError::InvalidArgument(format!(
            "IP address {bmc_ip} is already allocated to interface {} \
             on segment {}; use 'machine-interfaces assign-address' to reassign it",
            existing_addr.id, existing_addr.name,
        )));
    }

    let segment = resolve_segment_for_static_ip(txn, bmc_ip).await?;

    db::machine_interface::create(
        txn,
        &segment,
        &bmc_mac_address,
        segment.subdomain_id,
        true,
        AddressSelectionStrategy::StaticAddress(bmc_ip),
    )
    .await?;

    tracing::info!(
        %bmc_mac_address,
        %bmc_ip,
        segment_id = %segment.id,
        "Pre-allocated static machine interface"
    );

    Ok(())
}

/// Update or create a machine_interface with a static address.
///
/// If no interface exists for this MAC, creates a new one. If an
/// interface exists but has no addresses, assigns the static IP.
/// If an interface exists and already has addresses, we leave it
/// alone -- this is not an error, because expected device updates
/// are decoupled from managed device state. The expected data is
/// updated in the database by the caller; we only touch the
/// machine_interface if it's safe to do so (no existing addresses).
/// To change the IP on a live interface, operators should use
/// 'machine-interfaces assign-address' or 'remove-address'.
pub async fn update_preallocated_machine_interface(
    txn: &mut sqlx::PgConnection,
    bmc_mac_address: MacAddress,
    bmc_ip: std::net::IpAddr,
) -> Result<(), CarbideError> {
    let existing = db::machine_interface::find_by_mac_address(&mut *txn, bmc_mac_address).await?;

    if let Some(iface) = existing.first() {
        if iface.addresses.is_empty() {
            // No addresses -- safe to assign the static IP.
            db::machine_interface_address::assign_static(txn, iface.id, bmc_ip).await?;

            let segment = resolve_segment_for_static_ip(txn, bmc_ip).await?;
            if iface.segment_id != segment.id {
                db::machine_interface::update_segment_id(
                    txn,
                    iface.id,
                    segment.id,
                    segment.subdomain_id,
                )
                .await?;
            }

            tracing::info!(
                %bmc_mac_address,
                %bmc_ip,
                interface_id = %iface.id,
                "Assigned static address to existing interface without addresses"
            );
        } else {
            // Interface already has address(es). We don't touch it --
            // expected data updates are decoupled from managed state.
            // The caller updates the expected data table; we just log.
            tracing::info!(
                %bmc_mac_address,
                %bmc_ip,
                existing_addresses = ?iface.addresses,
                "Interface already has addresses, updated expected data only"
            );
        }
    } else {
        // No interface yet -- create a new one.
        let segment = resolve_segment_for_static_ip(txn, bmc_ip).await?;

        db::machine_interface::create(
            txn,
            &segment,
            &bmc_mac_address,
            segment.subdomain_id,
            true,
            AddressSelectionStrategy::StaticAddress(bmc_ip),
        )
        .await?;

        tracing::info!(
            %bmc_mac_address,
            %bmc_ip,
            segment_id = %segment.id,
            "Pre-allocated static machine interface"
        );
    }

    Ok(())
}

pub async fn assign_static_address(
    api: &Api,
    request: Request<rpc::AssignStaticAddressRequest>,
) -> Result<Response<rpc::AssignStaticAddressResponse>, CarbideError> {
    let req = request.into_inner();
    let interface_id = req.interface_id.ok_or(CarbideError::InvalidArgument(
        "interface_id is required".into(),
    ))?;
    let ip_address: std::net::IpAddr = req.ip_address.parse()?;

    let mut txn = api.txn_begin().await?;
    let result =
        db::machine_interface_address::assign_static(&mut txn, interface_id, ip_address).await?;

    // Resolve the correct segment for this IP and update the interface
    // if needed. IPs within a managed prefix go on that prefix's segment.
    // External IPs go on the static-assignments anchor segment.
    let target_segment = resolve_segment_for_static_ip(txn.as_pgconn(), ip_address).await?;

    let current_iface = db::machine_interface::find_one(txn.as_pgconn(), interface_id).await?;
    if current_iface.segment_id != target_segment.id {
        db::machine_interface::update_segment_id(
            &mut txn,
            interface_id,
            target_segment.id,
            target_segment.subdomain_id,
        )
        .await?;
        tracing::info!(
            %interface_id,
            %ip_address,
            old_segment_id = %current_iface.segment_id,
            new_segment_id = %target_segment.id,
            "Moved interface to correct segment for static address"
        );
    }

    txn.commit().await?;

    let status: rpc::AssignStaticAddressStatus = result.into();
    tracing::info!(%interface_id, %ip_address, ?status, "Static address assignment");

    Ok(Response::new(rpc::AssignStaticAddressResponse {
        interface_id: Some(interface_id),
        ip_address: ip_address.to_string(),
        status: status.into(),
    }))
}

pub async fn remove_static_address(
    api: &Api,
    request: Request<rpc::RemoveStaticAddressRequest>,
) -> Result<Response<rpc::RemoveStaticAddressResponse>, CarbideError> {
    let req = request.into_inner();
    let interface_id = req.interface_id.ok_or(CarbideError::InvalidArgument(
        "interface_id is required".into(),
    ))?;
    let ip_address: std::net::IpAddr = req.ip_address.parse()?;

    let mut txn = api.txn_begin().await?;
    let deleted = db::machine_interface_address::delete_by_address(
        &mut txn,
        ip_address,
        AllocationType::Static,
    )
    .await?;
    txn.commit().await?;

    let status = if deleted {
        tracing::info!(%interface_id, %ip_address, "Removed static address");
        rpc::RemoveStaticAddressStatus::Removed
    } else {
        tracing::info!(%interface_id, %ip_address, "Static address not found");
        rpc::RemoveStaticAddressStatus::NotFound
    };

    Ok(Response::new(rpc::RemoveStaticAddressResponse {
        interface_id: Some(interface_id),
        ip_address: ip_address.to_string(),
        status: status.into(),
    }))
}

pub async fn find_interface_addresses(
    api: &Api,
    request: Request<rpc::FindInterfaceAddressesRequest>,
) -> Result<Response<rpc::FindInterfaceAddressesResponse>, Status> {
    let req = request.into_inner();
    let interface_id = req.interface_id.ok_or(CarbideError::InvalidArgument(
        "interface_id is required".into(),
    ))?;

    let mut txn = api.txn_begin().await?;
    let addresses =
        db::machine_interface_address::find_for_interface(&mut txn, interface_id).await?;
    txn.commit().await?;

    let proto_addresses = addresses
        .into_iter()
        .map(|a| rpc::InterfaceAddress {
            address: a.address.to_string(),
            allocation_type: match a.allocation_type {
                AllocationType::Dhcp => "dhcp".to_string(),
                AllocationType::Static => "static".to_string(),
            },
        })
        .collect();

    Ok(Response::new(rpc::FindInterfaceAddressesResponse {
        interface_id: Some(interface_id),
        addresses: proto_addresses,
    }))
}
