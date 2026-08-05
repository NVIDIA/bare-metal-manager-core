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

use carbide_instrument::emit;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::allocation_type::AllocationType;
use model::expected_machine::ExpectedInterface;
use model::machine_interface::InterfaceType;
use model::network_segment::NetworkSegmentType;
use rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::Api;
use crate::errors::CarbideError;
use crate::handlers::static_address_metrics::{
    PreallocationSuccess, StaticAddressAssignmentCompleted, StaticAddressPreallocationCompleted,
    StaticAddressRemovalCompleted,
};

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
pub(super) async fn update_preallocated_machine_interface(
    txn: &mut sqlx::PgConnection,
    bmc_mac_address: MacAddress,
    bmc_ip: std::net::IpAddr,
    retained_window: Option<chrono::Duration>,
) -> Result<PreallocationSuccess, CarbideError> {
    emit_preallocation_error(
        update_preallocated_machine_interface_with_settings(
            txn,
            bmc_mac_address,
            bmc_ip,
            None,
            retained_window,
        )
        .await,
    )
}

/// Apply the existing safe update behavior to a fixed expected interface.
///
/// An addressed interface remains unchanged. A missing row is created with
/// the declared interface settings. Any addressless row receives the fixed IP,
/// but only an unassociated row also receives the role-derived settings.
pub(super) async fn update_preallocated_expected_machine_interface(
    txn: &mut sqlx::PgConnection,
    expected_interface: &ExpectedInterface,
    retained_window: Option<chrono::Duration>,
) -> Result<PreallocationSuccess, CarbideError> {
    emit_preallocation_error(
        update_preallocated_expected_machine_interface_inner(
            txn,
            expected_interface,
            retained_window,
        )
        .await,
    )
}

async fn update_preallocated_expected_machine_interface_inner(
    txn: &mut sqlx::PgConnection,
    expected_interface: &ExpectedInterface,
    retained_window: Option<chrono::Duration>,
) -> Result<PreallocationSuccess, CarbideError> {
    let fixed_ip = expected_interface
        .fixed_reservation_ip()
        .map_err(|message| {
            CarbideError::InvalidArgument(format!(
                "expected interface {}: {message}",
                expected_interface.mac_address,
            ))
        })?;

    update_preallocated_machine_interface_with_settings(
        txn,
        expected_interface.mac_address,
        fixed_ip,
        Some(ExpectedInterfaceSettings {
            interface_type: expected_interface.role.interface_type(),
            primary_interface: expected_interface.role.primary_interface_override(),
            segment_type_guard: expected_interface.segment_type_guard(),
            require_managed_prefix: !expected_interface.allows_static_assignments_fallback(),
        }),
        retained_window,
    )
    .await
}

/// ExpectedInterface settings that may be applied with a fixed-address
/// reservation.
///
/// These settings configure a new row, but only update an existing row while
/// it is still unassociated. ExpectedMachine is an ingestion template and must
/// not reclassify an interface after another resource owns it.
#[derive(Clone, Copy)]
struct ExpectedInterfaceSettings {
    /// Database interface type represented by the configured role.
    interface_type: InterfaceType,
    /// Role-specific primary-interface value, when the role declares one.
    primary_interface: Option<bool>,
    /// Segment type that the fixed address must resolve to.
    segment_type_guard: Option<NetworkSegmentType>,
    /// Require a managed prefix to contain the fixed address instead of
    /// falling back to `static-assignments`.
    require_managed_prefix: bool,
}

/// Create or safely update a fixed-address reservation.
///
/// Existing addressed rows remain unchanged. Addressless rows receive the
/// fixed address, but ExpectedInterface settings are applied only while the row
/// is unassociated. Passing no settings preserves the existing generic
/// reservation update behavior.
async fn update_preallocated_machine_interface_with_settings(
    txn: &mut sqlx::PgConnection,
    mac_address: MacAddress,
    ip_address: std::net::IpAddr,
    settings: Option<ExpectedInterfaceSettings>,
    retained_window: Option<chrono::Duration>,
) -> Result<PreallocationSuccess, CarbideError> {
    let segment_type_guard = settings.and_then(|settings| settings.segment_type_guard);
    // Generalized ExpectedInterface declarations require a managed prefix
    // even when an addressed interface will otherwise remain unchanged.
    // Legacy callers resolve lazily to preserve that addressed-row no-op.
    let resolved_segment = if settings.is_some_and(|settings| settings.require_managed_prefix) {
        Some(
            db::network_segment::for_managed_static_address(txn, ip_address, segment_type_guard)
                .await?,
        )
    } else {
        None
    };
    let existing = db::machine_interface::find_by_mac_address(&mut *txn, mac_address).await?;

    if let Some(iface) = existing.first() {
        if iface.addresses.is_empty() {
            // No addresses -- safe to assign the static IP.
            db::machine_interface_address::assign_static(txn, iface.id, ip_address).await?;

            let segment = match resolved_segment {
                Some(segment) => segment,
                None => db::network_segment::for_static_address(txn, ip_address).await?,
            };
            if iface.segment_id != segment.id {
                db::machine_interface::update_segment_id(
                    txn,
                    iface.id,
                    segment.id,
                    segment.config.subdomain_id,
                )
                .await?;
            }
            // Address reconciliation is independent from these settings. A
            // configured fixed address is still assigned above when an
            // associated row has no addresses; ownership only prevents role
            // and primary-interface changes.
            if let Some(settings) = settings {
                db::machine_interface::update_unassociated_expected_interface_settings(
                    txn,
                    iface.id,
                    Some(settings.interface_type),
                    settings.primary_interface,
                )
                .await?;
            }
            db::machine_interface::sync_hostname_after_address_assignment(
                txn,
                iface.id,
                segment.config.subdomain_id,
            )
            .await?;

            tracing::info!(
                %mac_address,
                ip_address = %ip_address,
                machine_interface_id = %iface.id,
                "Assigned static address to existing interface without addresses"
            );

            Ok(PreallocationSuccess::Assigned)
        } else {
            // Interface already has address(es). We don't touch it --
            // expected data updates are decoupled from managed state.
            // The caller updates the expected data table; we just log.
            tracing::info!(
                %mac_address,
                ip_address = %ip_address,
                existing_addresses = ?iface.addresses,
                "Interface already has addresses, updated expected data only"
            );

            Ok(PreallocationSuccess::Skipped)
        }
    } else {
        // No interface yet -- create a new one.
        let segment = match resolved_segment {
            Some(segment) => segment,
            None => db::network_segment::for_static_address(txn, ip_address).await?,
        };
        let interface_type = settings
            .map(|settings| settings.interface_type)
            .unwrap_or(InterfaceType::Data);
        let primary_interface = settings
            .and_then(|settings| settings.primary_interface)
            .unwrap_or(true);
        db::machine_interface::create_with_type(
            txn,
            std::slice::from_ref(&segment),
            &mac_address,
            primary_interface,
            AddressSelectionStrategy::StaticAddress(ip_address),
            interface_type,
            retained_window,
        )
        .await?;

        tracing::info!(
            %mac_address,
            ip_address = %ip_address,
            network_segment_id = %segment.id,
            "Pre-allocated static machine interface"
        );

        Ok(PreallocationSuccess::Created)
    }
}

fn emit_preallocation_error(
    result: Result<PreallocationSuccess, CarbideError>,
) -> Result<PreallocationSuccess, CarbideError> {
    if let Err(error) = &result {
        emit(StaticAddressPreallocationCompleted::Error {
            error: error.to_string(),
        });
    }

    result
}

pub(crate) async fn assign_static_address(
    api: &Api,
    request: Request<rpc::AssignStaticAddressRequest>,
) -> Result<Response<rpc::AssignStaticAddressResponse>, CarbideError> {
    let result = assign_static_address_inner(api, request).await;

    let event = match &result {
        Ok(response) => match rpc::AssignStaticAddressStatus::try_from(response.get_ref().status) {
            Ok(rpc::AssignStaticAddressStatus::Assigned) => {
                StaticAddressAssignmentCompleted::Assigned {}
            }
            Ok(rpc::AssignStaticAddressStatus::ReplacedStatic) => {
                StaticAddressAssignmentCompleted::ReplacedStatic {}
            }
            Ok(rpc::AssignStaticAddressStatus::ReplacedDhcp) => {
                StaticAddressAssignmentCompleted::ReplacedDhcp {}
            }
            Err(error) => StaticAddressAssignmentCompleted::Error {
                error: error.to_string(),
            },
        },
        Err(error) => StaticAddressAssignmentCompleted::Error {
            error: error.to_string(),
        },
    };
    emit(event);

    result
}

async fn assign_static_address_inner(
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
    let target_segment =
        db::network_segment::for_static_address(txn.as_pgconn(), ip_address).await?;

    let current_iface = db::machine_interface::find_one(txn.as_pgconn(), interface_id).await?;
    if current_iface.segment_id != target_segment.id {
        db::machine_interface::update_segment_id(
            &mut txn,
            interface_id,
            target_segment.id,
            target_segment.config.subdomain_id,
        )
        .await?;
        tracing::info!(
            machine_interface_id = %interface_id,
            %ip_address,
            previous_network_segment_id = %current_iface.segment_id,
            next_network_segment_id = %target_segment.id,
            "Moved interface to correct segment for static address"
        );
    }

    // Keep the interface's IP-derived hostname/domain consistent with the new
    // address, matching every other assignment path. Skipping this leaves a
    // stale hostname that encodes a now-freed IP and collides with the
    // fqdn_must_be_unique constraint when the allocator reuses that IP.
    db::machine_interface::sync_hostname_after_address_assignment(
        &mut txn,
        interface_id,
        target_segment.config.subdomain_id,
    )
    .await?;

    txn.commit().await?;

    let status: rpc::AssignStaticAddressStatus = result.into();
    tracing::info!(machine_interface_id = %interface_id, %ip_address, assignment_status = ?status, "Static address assignment");

    Ok(Response::new(rpc::AssignStaticAddressResponse {
        interface_id: Some(interface_id),
        ip_address: ip_address.to_string(),
        status: status.into(),
    }))
}

pub(crate) async fn remove_static_address(
    api: &Api,
    request: Request<rpc::RemoveStaticAddressRequest>,
) -> Result<Response<rpc::RemoveStaticAddressResponse>, CarbideError> {
    let result = remove_static_address_inner(api, request).await;

    let event = match &result {
        Ok(response) => match rpc::RemoveStaticAddressStatus::try_from(response.get_ref().status) {
            Ok(rpc::RemoveStaticAddressStatus::Removed) => {
                StaticAddressRemovalCompleted::Removed {}
            }
            Ok(rpc::RemoveStaticAddressStatus::NotFound) => {
                StaticAddressRemovalCompleted::NotFound {}
            }
            Err(error) => StaticAddressRemovalCompleted::Error {
                error: error.to_string(),
            },
        },
        Err(error) => StaticAddressRemovalCompleted::Error {
            error: error.to_string(),
        },
    };
    emit(event);

    result
}

async fn remove_static_address_inner(
    api: &Api,
    request: Request<rpc::RemoveStaticAddressRequest>,
) -> Result<Response<rpc::RemoveStaticAddressResponse>, CarbideError> {
    let req = request.into_inner();
    let interface_id = req.interface_id.ok_or(CarbideError::InvalidArgument(
        "interface_id is required".into(),
    ))?;
    let ip_address: std::net::IpAddr = req.ip_address.parse()?;

    let mut txn = api.txn_begin().await?;
    // Scope the delete to the caller's interface so remove-address only ever
    // removes that interface's own address, matching the command's contract
    // ("remove the address from a machine interface"). A mismatched interface_id
    // deletes nothing and returns NotFound rather than removing another
    // interface's row that happens to hold the same IP.
    let deleted = db::machine_interface_address::delete_by_interface_and_address(
        &mut txn,
        interface_id,
        ip_address,
        AllocationType::Static,
    )
    .await?;

    // Re-derive the interface's hostname/domain now that its address is gone,
    // matching the DHCP lease-expiry path. Without this the interface keeps a
    // hostname pinned to the removed IP.
    if deleted {
        db::machine_interface::sync_hostname_after_address_change(&mut txn, interface_id).await?;
    }

    txn.commit().await?;

    let status = if deleted {
        tracing::info!(machine_interface_id = %interface_id, %ip_address, "Removed static address");
        rpc::RemoveStaticAddressStatus::Removed
    } else {
        tracing::info!(machine_interface_id = %interface_id, %ip_address, "Static address not found");
        rpc::RemoveStaticAddressStatus::NotFound
    };

    Ok(Response::new(rpc::RemoveStaticAddressResponse {
        interface_id: Some(interface_id),
        ip_address: ip_address.to_string(),
        status: status.into(),
    }))
}

pub(crate) async fn find_interface_addresses(
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
                AllocationType::Slaac => "slaac".to_string(),
            },
        })
        .collect();

    Ok(Response::new(rpc::FindInterfaceAddressesResponse {
        interface_id: Some(interface_id),
        addresses: proto_addresses,
    }))
}

#[cfg(test)]
mod tests {
    use carbide_instrument::testing::capture_logs;

    use super::*;

    #[test]
    fn preallocation_error_is_emitted_once() {
        let logs = capture_logs(|| {
            let result = emit_preallocation_error(Err(CarbideError::InvalidArgument(
                "operation failed".to_string(),
            )));
            assert!(matches!(result, Err(CarbideError::InvalidArgument(_))));
        });

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, tracing::Level::WARN);
    }
}
