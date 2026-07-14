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

use std::net::SocketAddr;

use ::rpc::forge as rpc;
use ::rpc::model::machine::machine_id::try_parse_machine_id;
use carbide_redfish::boot_interface::BootInterfaceTarget;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::machine::MachineId;
use db::WithTransaction;
use db::machine_interface::find_by_ip;
use libredfish::RoleId;
use mac_address::MacAddress;
use model::expected_entity::ExpectedEntity;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, MachineInterfaceSnapshot};
use model::machine_boot_interface::MachineBootInterface;
use model::predicted_machine_interface::PredictedMachineInterface;
use model::site_explorer::{NicMode, PreingestionState};
use sqlx::PgConnection;
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data, log_request_data_redacted};

/// Resolve the boot interface an admin Redfish action should target, the same
/// way the machine-controller resolves it.
///
/// When a machine exists for the endpoint, its interfaces alone decide:
/// `pick_boot_interface` selects the machine's primary interface -- the same
/// row the machine-controller configures boot from -- and the row's own
/// captured id completes the [`MachineBootInterface`], or the action targets
/// the MAC alone ([`BootInterfaceTarget::MacOnly`], no id fallback), exactly
/// like the controller's `boot_interface_target`.
///
/// A machine with no `machine_interfaces` rows yet (a zero-DPU/NIC-mode
/// machine awaiting its first DHCP lease) resolves from its
/// `predicted_machine_interfaces` instead: the predicted NIC's MAC and
/// recorded Redfish interface id form the same [`MachineBootInterface`] the
/// real row will hold once the lease promotes it. The candidate is chosen by
/// the shared `pick_boot_prediction` -- the declared `ExpectedHostNic.primary`
/// (recorded on the prediction), else the sole non-underlay prediction. With
/// several (e.g. a host whose report lists SuperNICs alongside the boot NIC) and
/// none declared primary the boot NIC is unknowable; resolution refuses to guess
/// and the action keeps requiring an explicit MAC, which the matching
/// prediction's recorded id completes. The machine-controller resolves the same
/// way, through the same `pick_boot_prediction`.
///
/// Site-explorer's stored default (`ExploredEndpoint::boot_interface()`)
/// answers only for endpoints no machine owns. An owned machine resolves
/// from its own rows and predictions alone -- when neither offers an
/// unambiguous candidate, there is no target and the action requires an
/// explicit MAC, matching the machine-controller (which never consults the
/// explored default either).
///
/// An explicitly entered MAC is always honored as given, never redirected to
/// another NIC; any of the stores may complete it with the id recorded for
/// that exact MAC.
fn resolve_admin_boot_interface_target(
    stored: Option<MachineBootInterface>,
    candidates: Option<&BootInterfaceCandidates>,
    entered_mac: Option<MacAddress>,
) -> Option<BootInterfaceTarget> {
    // The machine's `MachineBootInterface` for `mac`, if known -- its own row
    // first, then its predictions.
    let known_pair_for = |mac: MacAddress| -> Option<MachineBootInterface> {
        let candidates = candidates?;
        candidates
            .interfaces
            .iter()
            .find(|row| row.mac_address == mac)
            .and_then(MachineInterfaceSnapshot::boot_interface)
            .or_else(|| {
                candidates
                    .predicted
                    .iter()
                    .find(|predicted| predicted.mac_address == mac)
                    .and_then(PredictedMachineInterface::boot_interface)
            })
    };
    // Resolution chose `mac`; its `MachineBootInterface` is the target, or the
    // MAC alone when no interface id has been captured (no id fallback).
    let target_for = |mac: MacAddress, pair: Option<MachineBootInterface>| -> BootInterfaceTarget {
        pair.map_or(BootInterfaceTarget::MacOnly(mac), BootInterfaceTarget::Pair)
    };

    match entered_mac {
        Some(mac) => Some(target_for(
            mac,
            known_pair_for(mac).or_else(|| stored.filter(|pair| pair.mac_address == mac)),
        )),
        None => {
            let Some(candidates) = candidates else {
                // No machine owns the endpoint -- the explored default
                // answers, when site-explorer has recorded one.
                return stored.map(BootInterfaceTarget::Pair);
            };
            if let Some(picked) = model::machine::pick_boot_interface(&candidates.interfaces) {
                // The machine's own row decides, exactly like the
                // machine-controller's boot_interface_target.
                return Some(target_for(picked.mac_address, picked.boot_interface()));
            }
            // The rows offered no boot candidate: the machine's predicted NICs
            // answer, via the shared `pick_boot_prediction` -- the declared
            // primary, else the sole non-underlay prediction. With several and
            // none declared primary the boot NIC is unknowable, so it returns
            // `None` and the action keeps requiring an explicit MAC.
            if let Some(predicted) = model::machine::pick_boot_prediction(&candidates.predicted) {
                return Some(target_for(
                    predicted.mac_address,
                    predicted.boot_interface(),
                ));
            }
            // An owned machine resolves from its own data alone: no
            // unambiguous candidate means no target, and the action requires
            // an explicit MAC -- never a guess from the explored default.
            None
        }
    }
}

/// What a host machine offers boot-interface resolution to select from: its
/// real `machine_interfaces` rows, and -- for the window before a NIC's first
/// DHCP lease creates a real row -- its `predicted_machine_interfaces`.
pub(crate) struct BootInterfaceCandidates {
    /// The machine's non-BMC `machine_interfaces` rows. When they offer a
    /// boot candidate (the machine-controller's own `pick_boot_interface`
    /// selection), it alone decides.
    pub interfaces: Vec<MachineInterfaceSnapshot>,
    /// The machine's predicted interfaces, consulted only when the rows
    /// offer no boot candidate -- none exist yet (zero-DPU/NIC-mode machines
    /// awaiting their first lease), or none are selectable (e.g. only
    /// underlay-typed declared NICs).
    pub predicted: Vec<PredictedMachineInterface>,
}

/// Load what boot-interface resolution selects from, when the BMC endpoint
/// belongs to a (predicted or confirmed) host machine.
///
/// Returns `None` -- meaning resolution falls through to the explored
/// default -- for endpoints with no machine, and for DPU machines, whose own
/// setup runs without a boot-interface target, exactly like the
/// machine-controller path. A host machine always gets `Some`, though both
/// lists can be empty (`find_by_machine_ids` filters BMC rows, so a host
/// whose only discovered interface is its BMC offers no real candidates).
pub(crate) async fn boot_interface_candidates(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
) -> Result<Option<BootInterfaceCandidates>, CarbideError> {
    let Some(machine_id) = machine_id.filter(|id| !id.machine_type().is_dpu()) else {
        return Ok(None);
    };
    let interfaces = db::machine_interface::find_by_machine_ids(txn, &[machine_id])
        .await?
        .remove(&machine_id)
        .unwrap_or_default();
    let predicted = db::predicted_machine_interface::find_by_machine_id(txn, &machine_id).await?;
    Ok(Some(BootInterfaceCandidates {
        interfaces,
        predicted,
    }))
}

pub(crate) async fn admin_bmc_reset(
    api: &Api,
    request: Request<rpc::AdminBmcResetRequest>,
) -> Result<Response<rpc::AdminBmcResetResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: AdminBmcResetRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();

    tracing::info!(
        use_ipmitool = req.use_ipmitool,
        bmc_ip_address = %endpoint_address,
        "Resetting BMC",
    );

    if req.use_ipmitool {
        ipmitool_reset_bmc(api, bmc_endpoint_request).await?;
    } else {
        redfish_reset_bmc(api, bmc_endpoint_request).await?;
    }

    tracing::info!(
        use_ipmitool = req.use_ipmitool,
        bmc_ip_address = %endpoint_address,
        "BMC reset request succeeded",
    );

    Ok(Response::new(rpc::AdminBmcResetResponse {}))
}

pub(crate) async fn disable_secure_boot(
    api: &Api,
    request: Request<rpc::BmcEndpointRequest>,
) -> Result<Response<rpc::DisableSecureBootResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, Some(req), None).await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .disable_secure_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Disable secure boot request succeeded",
    );

    Ok(Response::new(rpc::DisableSecureBootResponse {}))
}

pub(crate) async fn lockdown(
    api: &Api,
    request: Request<rpc::LockdownRequest>,
) -> Result<Response<rpc::LockdownResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let action = req.action();
    let action = match action {
        rpc::LockdownAction::Enable => libredfish::EnabledDisabled::Enabled,
        rpc::LockdownAction::Disable => libredfish::EnabledDisabled::Disabled,
    };

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
        &mut txn,
        req.bmc_endpoint_request,
        req.machine_id,
    )
    .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .lockdown(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        action = %action.to_string().to_lowercase(),
        bmc_ip_address = %endpoint_address,
        "lockdown request succeeded",
    );

    Ok(Response::new(rpc::LockdownResponse {}))
}

pub(crate) async fn lockdown_status(
    api: &Api,
    request: Request<rpc::LockdownStatusRequest>,
) -> Result<Response<::rpc::site_explorer::LockdownStatus>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
        &mut txn,
        req.bmc_endpoint_request,
        req.machine_id,
    )
    .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let response = api
        .endpoint_explorer
        .lockdown_status(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(response.into()))
}

pub(crate) async fn enable_infinite_boot(
    api: &Api,
    request: Request<rpc::EnableInfiniteBootRequest>,
) -> Result<Response<rpc::EnableInfiniteBootResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: EnableInfiniteBootRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .enable_infinite_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Enable infinite boot request succeeded",
    );

    Ok(Response::new(rpc::EnableInfiniteBootResponse {}))
}

pub(crate) async fn is_infinite_boot_enabled(
    api: &Api,
    request: Request<rpc::IsInfiniteBootEnabledRequest>,
) -> Result<Response<rpc::IsInfiniteBootEnabledResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: IsInfiniteBootEnabledRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let is_enabled = api
        .endpoint_explorer
        .is_infinite_boot_enabled(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(
        bmc_ip_address = %bmc_endpoint_request.ip_address,
        is_enabled,
        "Infinite boot status request succeeded",
    );

    Ok(Response::new(rpc::IsInfiniteBootEnabledResponse {
        is_enabled,
    }))
}

pub(crate) async fn machine_setup(
    api: &Api,
    request: Request<rpc::MachineSetupRequest>,
) -> Result<Response<rpc::MachineSetupResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: MachineSetupRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, owning_machine_id) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;
    let candidates = boot_interface_candidates(&mut txn, owning_machine_id).await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Starting machine setup",
    );

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let entered_mac = req
        .boot_interface_mac
        .as_deref()
        .map(str::trim)
        .none_if_empty()
        .map(|m| m.parse::<MacAddress>())
        .transpose()
        .map_err(|e| CarbideError::InvalidArgument(format!("invalid boot_interface_mac: {e}")))?;
    let stored = db::explored_endpoints::find_by_ips(&api.database_connection, vec![bmc_addr.ip()])
        .await?
        .into_iter()
        .next()
        .and_then(|ep| ep.boot_interface());
    let boot_interface =
        resolve_admin_boot_interface_target(stored, candidates.as_ref(), entered_mac);

    api.endpoint_explorer
        .machine_setup(bmc_addr, &machine_interface, boot_interface.as_ref())
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Machine setup request succeeded",
    );

    Ok(Response::new(rpc::MachineSetupResponse {}))
}

pub(crate) async fn set_dpu_first_boot_order(
    api: &Api,
    request: Request<rpc::SetDpuFirstBootOrderRequest>,
) -> Result<Response<rpc::SetDpuFirstBootOrderResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: SetDpuFirstBootOrderRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, owning_machine_id) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;
    let candidates = boot_interface_candidates(&mut txn, owning_machine_id).await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Setting DPU first in boot order",
    );

    let entered_mac = req
        .boot_interface_mac
        .as_deref()
        .map(str::trim)
        .none_if_empty()
        .map(|m| m.parse::<MacAddress>())
        .transpose()
        .map_err(|e| CarbideError::InvalidArgument(format!("invalid boot_interface_mac: {e}")))?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let stored = db::explored_endpoints::find_by_ips(&api.database_connection, vec![bmc_addr.ip()])
        .await?
        .into_iter()
        .next()
        .and_then(|ep| ep.boot_interface());
    let boot_interface =
        resolve_admin_boot_interface_target(stored, candidates.as_ref(), entered_mac).ok_or_else(
            || {
                CarbideError::InvalidArgument(
                    "no boot interface available: enter a MAC or explore the host first"
                        .to_string(),
                )
            },
        )?;

    api.endpoint_explorer
        .set_boot_order_dpu_first(bmc_addr, &machine_interface, &boot_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(
        bmc_ip_address = %endpoint_address,
        "Set DPU first in boot order request succeeded",
    );

    Ok(Response::new(rpc::SetDpuFirstBootOrderResponse {}))
}

pub(crate) async fn admin_power_control(
    api: &Api,
    request: Request<rpc::AdminPowerControlRequest>,
) -> Result<Response<rpc::AdminPowerControlResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: AdminPowerControlRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let action = req.action();

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, machine_id) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    let action = match action {
        rpc::admin_power_control_request::SystemPowerControl::On => {
            libredfish::SystemPowerControl::On
        }
        rpc::admin_power_control_request::SystemPowerControl::GracefulShutdown => {
            libredfish::SystemPowerControl::GracefulShutdown
        }
        rpc::admin_power_control_request::SystemPowerControl::ForceOff => {
            libredfish::SystemPowerControl::ForceOff
        }
        rpc::admin_power_control_request::SystemPowerControl::GracefulRestart => {
            libredfish::SystemPowerControl::GracefulRestart
        }
        rpc::admin_power_control_request::SystemPowerControl::ForceRestart => {
            libredfish::SystemPowerControl::ForceRestart
        }
        rpc::admin_power_control_request::SystemPowerControl::AcPowercycle => {
            libredfish::SystemPowerControl::ACPowercycle
        }
    };

    let mut msg: Option<String> = None;
    if let Some(machine_id) = machine_id {
        let power_manager_enabled = api.runtime_config.power_manager_options.enabled;
        if power_manager_enabled {
            let snapshot = db::managed_host::load_snapshot(
                &mut txn,
                &machine_id,
                LoadSnapshotOptions {
                    include_history: true,
                    include_instance_data: false,
                    host_health_config: api.runtime_config.host_health,
                },
            )
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

            if let Some(power_state) = snapshot
                .host_snapshot
                .power_options
                .map(|x| x.desired_power_state)
                && power_state == model::power_manager::PowerState::On
                && action == libredfish::SystemPowerControl::ForceOff
            {
                msg = Some(
                        "!!WARNING!! Desired power state for the host is set as On while the requested action is Off. Carbide will attempt to bring the host online after some time.".to_string(),
                    )
            }
        }
    }

    txn.commit().await?;

    redfish_power_control(api, bmc_endpoint_request, action).await?;

    Ok(Response::new(rpc::AdminPowerControlResponse { msg }))
}

// Ad-hoc BMC exploration
pub(crate) async fn explore(
    api: &Api,
    request: tonic::Request<rpc::BmcEndpointRequest>,
) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &req).await?;

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    // TODO(chet): Track down Vinod's Jira to optimize code for
    // existing sites where there is no nvswitch or power shelf.
    let expected = if let Some(expected_machine) =
        crate::handlers::expected_machine::query(api, bmc_mac_address).await?
    {
        Some(ExpectedEntity::Machine(expected_machine))
    } else if let Some(expected_switch) =
        crate::handlers::expected_switch::query(api, bmc_mac_address).await?
    {
        Some(ExpectedEntity::Switch(expected_switch))
    } else {
        crate::handlers::expected_power_shelf::query(api, bmc_mac_address)
            .await?
            .map(ExpectedEntity::PowerShelf)
    };

    // Look up boot_interface_mac from existing explored endpoint if available
    let mut txn = api.txn_begin().await?;
    let boot_interface_mac = db::explored_endpoints::find_by_ips(&mut txn, vec![bmc_addr.ip()])
        .await?
        .first()
        .and_then(|ep| ep.boot_interface_mac);
    txn.commit().await?;

    let report = api
        .endpoint_explorer
        .explore_endpoint(
            bmc_addr,
            &machine_interface,
            expected.as_ref(),
            None,
            boot_interface_mac,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(tonic::Response::new(report.into()))
}

async fn redfish_reset_bmc(
    api: &Api,
    request: rpc::BmcEndpointRequest,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .redfish_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn ipmitool_reset_bmc(
    api: &Api,
    request: rpc::BmcEndpointRequest,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .ipmitool_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn redfish_power_control(
    api: &Api,
    request: rpc::BmcEndpointRequest,
    action: libredfish::SystemPowerControl,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .redfish_power_control(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn bmc_credential_status(
    api: &Api,
    request: tonic::Request<rpc::BmcEndpointRequest>,
) -> Result<Response<rpc::BmcCredentialStatusResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let (_bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &req).await?;

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    let have_credentials = api
        .endpoint_explorer
        .have_credentials(&machine_interface)
        .await;

    Ok(Response::new(rpc::BmcCredentialStatusResponse {
        have_credentials,
    }))
}

pub(crate) async fn copy_bfb_to_dpu_rshim(
    api: &Api,
    request: Request<rpc::CopyBfbToDpuRshimRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let ip_str = match &req.ssh_request {
        Some(ssh_req) => match &ssh_req.endpoint_request {
            Some(bmc_request) => bmc_request.ip_address.clone(),
            None => return Err(CarbideError::MissingArgument("bmc_endpoint_request").into()),
        },
        None => return Err(CarbideError::MissingArgument("ssh_request").into()),
    };

    let dpu_ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| CarbideError::InvalidArgument(format!("Invalid DPU IP: {ip_str}")))?;

    if req.host_bmc_ip.is_empty() {
        return Err(CarbideError::MissingArgument("host_bmc_ip").into());
    }
    let host_bmc_ip: std::net::IpAddr = req.host_bmc_ip.parse().map_err(|_| {
        CarbideError::InvalidArgument(format!("Invalid host BMC IP: {}", req.host_bmc_ip))
    })?;

    let pre_copy_powercycle = req.pre_copy_powercycle;

    let dpu_in_managed_host =
        carbide_site_explorer::is_endpoint_in_managed_host(dpu_ip, &api.database_connection)
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;
    if dpu_in_managed_host {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot trigger BFB recovery: DPU {dpu_ip} is already ingested. \
             Force-delete the managed host first.",
        ))
        .into());
    }

    let dpu_endpoints = db::explored_endpoints::find_by_ips(&api.database_connection, vec![dpu_ip])
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;
    let dpu_endpoint = dpu_endpoints.first().ok_or(CarbideError::NotFoundError {
        kind: "explored_endpoint",
        id: dpu_ip.to_string(),
    })?;

    // If the DPU is in NIC mode, don't allow operators to copy_bfb_to_dpu_rshim
    // at all to begin with. While the rshim + copy part will technically
    // work, the problem is there's no ARM OS to actually reboot into. The
    // BFB preingestion flow will work its way through the states, and then
    // wait for the ARM OS to come up, which it never will. Waiting will
    // eventually, time out (SLA), and then the host will mark as failed.
    if dpu_endpoint.report.nic_mode() == Some(NicMode::Nic) {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot trigger BFB recovery: DPU {dpu_ip} is in NIC mode. \
             Update the host's `ExpectedMachine.dpu_mode` to `DpuMode` \
             and wait for site-explorer to reconcile the DPU back to \
             DPU mode before retrying.",
        ))
        .into());
    }

    match &dpu_endpoint.preingestion_state {
        PreingestionState::Initial
        | PreingestionState::Complete
        | PreingestionState::Failed { .. } => {}
        other => {
            return Err(CarbideError::InvalidArgument(format!(
                "Cannot trigger BFB recovery: DPU endpoint is in state {other:?}. \
                 Wait for it to complete or fail first.",
            ))
            .into());
        }
    }

    {
        let host_endpoints =
            db::explored_endpoints::find_by_ips(&api.database_connection, vec![host_bmc_ip])
                .await
                .map_err(|e| CarbideError::internal(e.to_string()))?;
        let host_ep = host_endpoints.first().ok_or(CarbideError::NotFoundError {
            kind: "explored_endpoint",
            id: host_bmc_ip.to_string(),
        })?;
        match &host_ep.preingestion_state {
            PreingestionState::Complete | PreingestionState::Failed { .. } => {}
            other => {
                return Err(CarbideError::InvalidArgument(format!(
                    "Cannot power-cycle host: host {host_bmc_ip} is in state {other:?}. \
                     Retry after host preingestion completes.",
                ))
                .into());
            }
        }
    }

    api.database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                db::explored_endpoints::set_preingestion_bfb_recovery_needed(
                    dpu_ip,
                    "Triggered via CLI".to_string(),
                    host_bmc_ip,
                    pre_copy_powercycle,
                    txn,
                )
                .await?;

                // Pause site explorer remediation on the host so it doesn't
                // issue BMC resets during the power-cycle phases.
                db::explored_endpoints::set_pause_remediation(host_bmc_ip, true, txn).await?;

                Ok::<(), db::DatabaseError>(())
            })
        })
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn resolve_bmc_interface(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
) -> Result<(SocketAddr, MacAddress), Status> {
    let address = if request.ip_address.contains(':') {
        request.ip_address.clone()
    } else {
        format!("{}:443", request.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(CarbideError::InvalidArgument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            request.ip_address
        ))
        .into());
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = &request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else if let Some(bmc_machine_interface) =
        find_by_ip(&api.database_connection, bmc_addr.ip()).await?
    {
        bmc_mac_address = bmc_machine_interface.mac_address;
    } else {
        return Err(CarbideError::InvalidArgument(format!(
            "could not find a mac address for the specified IP: {request:#?}"
        ))
        .into());
    };

    Ok((bmc_addr, bmc_mac_address))
}

pub(crate) async fn create_bmc_user(
    api: &Api,
    request: Request<rpc::CreateBmcUserRequest>,
) -> Result<Response<rpc::CreateBmcUserResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: CreateBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    let role: RoleId = match req
        .create_role_id
        .unwrap_or("Administrator".to_string())
        .to_lowercase()
        .as_str()
    {
        "administrator" => RoleId::Administrator,
        "operator" => RoleId::Operator,
        "readonly" => RoleId::ReadOnly,
        "noaccess" => RoleId::NoAccess,
        _ => RoleId::Administrator,
    };

    tracing::info!(
        username = %req.create_username,
        role = %role,
        bmc_ip_address = %endpoint_address,
        "Creating BMC user",
    );

    do_create_bmc_user(
        api,
        &bmc_endpoint_request,
        &req.create_username,
        &req.create_password,
        role,
    )
    .await?;

    tracing::info!(
        username = %req.create_username,
        role = %role,
        bmc_ip_address = %endpoint_address,
        "Successfully created BMC user",
    );

    Ok(Response::new(rpc::CreateBmcUserResponse {}))
}

pub(crate) async fn delete_bmc_user(
    api: &Api,
    request: Request<rpc::DeleteBmcUserRequest>,
) -> Result<Response<rpc::DeleteBmcUserResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: DeleteBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;
    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!(
        username = %req.delete_username,
        bmc_ip_address = %endpoint_address,
        "Deleting BMC user",
    );

    do_delete_bmc_user(api, &bmc_endpoint_request, &req.delete_username).await?;

    tracing::info!(
        username = %req.delete_username,
        bmc_ip_address = %endpoint_address,
        "Successfully deleted BMC user",
    );

    Ok(Response::new(rpc::DeleteBmcUserResponse {}))
}

pub(crate) async fn set_bmc_root_password(
    api: &Api,
    request: Request<rpc::SetBmcRootPasswordRequest>,
) -> Result<Response<rpc::SetBmcRootPasswordResponse>, Status> {
    // Redact: the request carries the plaintext BMC root password. Log only the
    // non-secret targeting fields.
    {
        let r = request.get_ref();
        log_request_data_redacted(format!(
            "SetBmcRootPasswordRequest {{ bmc_endpoint_request: {:?}, machine_id: {:?}, new_password: <redacted> }}",
            r.bmc_endpoint_request, r.machine_id,
        ));
    }
    let req = request.into_inner();

    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;
    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;
    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    tracing::info!(bmc_address = %bmc_addr, "Setting BMC root password");

    api.endpoint_explorer
        .set_bmc_root_password(bmc_addr, &machine_interface, &req.new_password)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(bmc_address = %bmc_addr, "Successfully set BMC root password");

    Ok(Response::new(rpc::SetBmcRootPasswordResponse {}))
}

pub(crate) async fn probe_bmc_vendor(
    api: &Api,
    request: Request<rpc::ProbeBmcVendorRequest>,
) -> Result<Response<rpc::ProbeBmcVendorResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin().await?;
    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;
    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let vendor = api
        .endpoint_explorer
        .probe_bmc_vendor(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(bmc_address = %bmc_addr, %vendor, "Probed BMC vendor");

    Ok(Response::new(rpc::ProbeBmcVendorResponse {
        vendor: vendor.to_string(),
    }))
}

async fn do_create_bmc_user(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
    create_username: &str,
    create_password: &str,
    create_role_id: RoleId,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .create_bmc_user(
            bmc_addr,
            &machine_interface,
            create_username,
            create_password,
            create_role_id,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn do_delete_bmc_user(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
    delete_user: &str,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .delete_bmc_user(bmc_addr, &machine_interface, delete_user)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

/// Accepts an optional partial or complete BmcEndpointRequest and optional machine ID and returns a complete and valid BmcEndpointRequest.
///
/// * `txn`                  - Active database transaction
/// * `bmc_endpoint_request` - Optional BmcEndpointRequest.  Can supply _only_ ip_address or all fields.
/// * `machine_id`           - Optional machine ID that can be used to build a new BmcEndpointRequest.
pub(crate) async fn validate_and_complete_bmc_endpoint_request(
    txn: &mut PgConnection,
    bmc_endpoint_request: Option<rpc::BmcEndpointRequest>,
    machine_id: Option<MachineId>,
) -> Result<(rpc::BmcEndpointRequest, Option<MachineId>), CarbideError> {
    match (bmc_endpoint_request, machine_id) {
        (Some(bmc_endpoint_request), _) => {
            let parsed_ip = bmc_endpoint_request.ip_address.parse().map_err(|e| {
                CarbideError::InvalidArgument(format!(
                    "invalid ip_address {:?}: {e}",
                    bmc_endpoint_request.ip_address
                ))
            })?;
            let interface = db::machine_interface::find_by_ip(txn, parsed_ip)
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "machine_interface",
                    id: bmc_endpoint_request.ip_address.clone(),
                })?;

            let bmc_mac = match bmc_endpoint_request.mac_address {
                // No MAC in the request, use the interface MAC
                None => interface.mac_address.to_string(),

                // MAC passed in the request, check if it matches the interface MAC
                Some(request_mac) => {
                    let parsed_mac = request_mac
                        .parse::<MacAddress>()
                        .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;

                    if parsed_mac != interface.mac_address {
                        return Err(CarbideError::BmcMacIpMismatch {
                            requested_ip: bmc_endpoint_request.ip_address.clone(),
                            requested_mac: request_mac,
                            found_mac: interface.mac_address.to_string(),
                        });
                    }

                    request_mac
                }
            };

            Ok((
                rpc::BmcEndpointRequest {
                    ip_address: bmc_endpoint_request.ip_address,
                    mac_address: Some(bmc_mac),
                },
                interface.machine_id,
            ))
        }
        // User provided machine_id
        (_, Some(machine_id)) => {
            log_machine_id(&machine_id);

            let machine = db::machine::find_one(txn, &machine_id, MachineSearchConfig::default())
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?;

            let bmc_ip = machine.bmc_info.ip.as_ref().ok_or_else(|| {
                CarbideError::internal(format!(
                    "Machine found for {machine_id} but BMC IP is missing"
                ))
            })?;

            let bmc_mac_address = machine.bmc_info.mac.ok_or_else(|| {
                CarbideError::internal(format!("BMC endpoint for {bmc_ip} ({machine_id}) found but does not have associated MAC"))
            })?;

            Ok((
                rpc::BmcEndpointRequest {
                    ip_address: bmc_ip.to_string(),
                    mac_address: Some(bmc_mac_address.to_string()),
                },
                Some(machine_id),
            ))
        }

        _ => Err(CarbideError::InvalidArgument(
            "provide either machine_id or BmcEndpointRequest with at least ip_address".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use model::network_segment::NetworkSegmentType;

    use super::*;

    fn row(mac: &str, primary: bool, boot_interface_id: Option<&str>) -> MachineInterfaceSnapshot {
        let mut row = MachineInterfaceSnapshot::mock_with_mac(mac.parse().unwrap());
        row.primary_interface = primary;
        row.boot_interface_id = boot_interface_id.map(String::from);
        row
    }

    fn predicted(mac: &str, boot_interface_id: Option<&str>) -> PredictedMachineInterface {
        PredictedMachineInterface {
            id: uuid::Uuid::nil(),
            // Any valid machine id -- the resolver never reads it.
            machine_id: "fm100ds27v4uuq7sgs4gsjummskt0b3tedugtpevjrbfh6su081n9jufcq0"
                .parse()
                .unwrap(),
            mac_address: mac.parse().unwrap(),
            expected_network_segment_type: NetworkSegmentType::HostInband,
            boot_interface_id: boot_interface_id.map(String::from),
            primary_interface: false,
        }
    }

    fn pair(mac: &str, interface_id: &str) -> MachineBootInterface {
        MachineBootInterface {
            mac_address: mac.parse().unwrap(),
            interface_id: interface_id.to_string(),
        }
    }

    #[test]
    fn entered_mac_upgrades_to_a_pair_from_the_machines_own_row() {
        // The operator picked a NIC; its machine_interface row holds the Redfish
        // id, so the target is the full pair -- even though the explored default
        // names a different NIC.
        let c = BootInterfaceCandidates {
            interfaces: vec![
                row("00:00:5e:00:53:01", true, Some("NIC.Integrated.1-1-1")),
                row("00:00:5e:00:53:02", false, Some("NIC.Slot.7-1-1")),
            ],
            predicted: vec![],
        };
        let stored = Some(pair("00:00:5e:00:53:01", "NIC.Integrated.1-1-1"));
        let target = resolve_admin_boot_interface_target(
            stored,
            Some(&c),
            Some("00:00:5e:00:53:02".parse().unwrap()),
        );
        assert_eq!(
            target,
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:02",
                "NIC.Slot.7-1-1"
            ))),
        );
    }

    #[test]
    fn entered_mac_upgrades_to_a_pair_from_a_predicted_interface() {
        // The named NIC has no machine_interfaces row yet (its first lease is
        // still pending), but the machine's prediction for it recorded the
        // Redfish id -- the entered MAC is completed from there.
        let c = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![predicted("00:00:5e:00:53:02", Some("NIC.Embedded.1-1-1"))],
        };
        let target = resolve_admin_boot_interface_target(
            None,
            Some(&c),
            Some("00:00:5e:00:53:02".parse().unwrap()),
        );
        assert_eq!(
            target,
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:02",
                "NIC.Embedded.1-1-1"
            ))),
        );
    }

    #[test]
    fn entered_mac_falls_back_to_the_explored_default_then_mac_only() {
        // No machine: the explored default completes the pair only when it
        // names the entered MAC; any other entered MAC is targeted alone.
        let stored = pair("00:00:5e:00:53:01", "NIC.Integrated.1-1-1");
        assert_eq!(
            resolve_admin_boot_interface_target(
                Some(stored.clone()),
                None,
                Some("00:00:5e:00:53:01".parse().unwrap()),
            ),
            Some(BootInterfaceTarget::Pair(stored.clone())),
        );
        assert_eq!(
            resolve_admin_boot_interface_target(
                Some(stored),
                None,
                Some("00:00:5e:00:53:99".parse().unwrap()),
            ),
            Some(BootInterfaceTarget::MacOnly(
                "00:00:5e:00:53:99".parse().unwrap()
            )),
        );
    }

    #[test]
    fn no_mac_prefers_the_machines_designation_over_the_explored_default() {
        // The machine's primary row is the authority; the explored default
        // (site-explorer's automatic pick) names a different NIC and loses.
        let c = BootInterfaceCandidates {
            interfaces: vec![
                row("00:00:5e:00:53:01", false, Some("NIC.Integrated.1-1-1")),
                row("00:00:5e:00:53:02", true, Some("NIC.Slot.7-1-1")),
            ],
            predicted: vec![],
        };
        let stored = Some(pair("00:00:5e:00:53:01", "NIC.Integrated.1-1-1"));
        assert_eq!(
            resolve_admin_boot_interface_target(stored, Some(&c), None),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:02",
                "NIC.Slot.7-1-1"
            ))),
        );
    }

    #[test]
    fn no_mac_real_rows_beat_predicted_interfaces() {
        // Once any real machine_interfaces row exists, predictions are out of
        // the running -- even a fully-populated one.
        let c = BootInterfaceCandidates {
            interfaces: vec![row("00:00:5e:00:53:02", true, Some("NIC.Slot.7-1-1"))],
            predicted: vec![predicted("00:00:5e:00:53:01", Some("NIC.Embedded.1-1-1"))],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(None, Some(&c), None),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:02",
                "NIC.Slot.7-1-1"
            ))),
        );
    }

    #[test]
    fn no_mac_machine_row_without_an_id_targets_the_mac_alone() {
        // The designated row hasn't captured an id yet: the action targets the
        // MAC alone, exactly like the machine-controller's
        // boot_interface_target. The explored default is not consulted for an
        // owned machine -- even when it holds an id for the very same NIC.
        let c = BootInterfaceCandidates {
            interfaces: vec![row("00:00:5e:00:53:02", true, None)],
            predicted: vec![],
        };
        for stored in [
            Some(pair("00:00:5e:00:53:02", "NIC.Slot.7-1-1")),
            Some(pair("00:00:5e:00:53:01", "NIC.Integrated.1-1-1")),
            None,
        ] {
            assert_eq!(
                resolve_admin_boot_interface_target(stored, Some(&c), None),
                Some(BootInterfaceTarget::MacOnly(
                    "00:00:5e:00:53:02".parse().unwrap()
                )),
            );
        }
    }

    #[test]
    fn no_mac_a_sole_prediction_decides_when_no_rows_exist() {
        // A machine awaiting its first lease resolves from its prediction when
        // there is exactly one: the recorded id completes the pair, and a
        // prediction without an id is targeted by MAC alone.
        let c = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![predicted("00:00:5e:00:53:01", Some("NIC.Embedded.1-1-1"))],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(None, Some(&c), None),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:01",
                "NIC.Embedded.1-1-1"
            ))),
        );

        let idless = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![predicted("00:00:5e:00:53:01", None)],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(None, Some(&idless), None),
            Some(BootInterfaceTarget::MacOnly(
                "00:00:5e:00:53:01".parse().unwrap()
            )),
        );
    }

    #[test]
    fn no_mac_multiple_predictions_refuse_to_guess_a_boot_device() {
        // These predictions are non-primary and this resolver doesn't consult
        // the primary flag yet, so with several (a report listing SuperNICs
        // alongside the boot NIC) the declared intent is unknowable: resolution
        // refuses to guess rather than silently programming boot order against
        // whichever NIC sorts lowest. The operator's explicit MAC still
        // resolves, completed from the matching prediction.
        let c = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![
                predicted("00:00:5e:00:53:02", Some("NIC.Slot.7-1-1")),
                predicted("00:00:5e:00:53:01", Some("NIC.Embedded.1-1-1")),
            ],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(None, Some(&c), None),
            None
        );
        let stored = Some(pair("00:00:5e:00:53:09", "NIC.Other.9-9-9"));
        assert_eq!(
            resolve_admin_boot_interface_target(stored, Some(&c), None),
            None,
            "an explored default must never answer for an owned machine",
        );
        assert_eq!(
            resolve_admin_boot_interface_target(
                None,
                Some(&c),
                Some("00:00:5e:00:53:02".parse().unwrap()),
            ),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:02",
                "NIC.Slot.7-1-1"
            ))),
        );
    }

    // A declared-primary prediction disambiguates a multi-prediction host:
    // `pick_boot_prediction` selects it, so resolution targets the declared NIC
    // rather than refusing. (Multiple NON-primary predictions still refuse --
    // see `no_mac_multiple_predictions_refuse_to_guess_a_boot_device`.)
    #[test]
    fn no_mac_declared_primary_prediction_wins_over_other_predictions() {
        let declared_primary = PredictedMachineInterface {
            primary_interface: true,
            ..predicted("00:00:5e:00:53:01", Some("NIC.Embedded.1-1-1"))
        };
        let other = predicted("00:00:5e:00:53:02", Some("NIC.Slot.7-1-1"));
        let c = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![other, declared_primary],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(None, Some(&c), None),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:01",
                "NIC.Embedded.1-1-1"
            ))),
        );
    }

    #[test]
    fn no_mac_underlay_only_rows_let_a_sole_prediction_answer() {
        // Real rows exist but none is a boot candidate (declared bmc/oob NICs
        // land on Underlay segments); the sole prediction answers, ahead of
        // the explored default.
        let mut underlay = row("00:00:5e:00:53:09", false, None);
        underlay.network_segment_type = Some(NetworkSegmentType::Underlay);
        let c = BootInterfaceCandidates {
            interfaces: vec![underlay],
            predicted: vec![predicted("00:00:5e:00:53:01", Some("NIC.Embedded.1-1-1"))],
        };
        let stored = Some(pair("00:00:5e:00:53:09", "NIC.Other.9-9-9"));
        assert_eq!(
            resolve_admin_boot_interface_target(stored, Some(&c), None),
            Some(BootInterfaceTarget::Pair(pair(
                "00:00:5e:00:53:01",
                "NIC.Embedded.1-1-1"
            ))),
        );
    }

    #[test]
    fn no_mac_only_an_unowned_endpoint_uses_the_explored_default() {
        // The explored default answers for endpoints no machine owns. An
        // owned machine resolves from its own data alone: with no candidate
        // at all there is no target, even when a stored default exists.
        let stored = pair("00:00:5e:00:53:01", "NIC.Integrated.1-1-1");
        assert_eq!(
            resolve_admin_boot_interface_target(Some(stored.clone()), None, None),
            Some(BootInterfaceTarget::Pair(stored.clone())),
        );
        let empty = BootInterfaceCandidates {
            interfaces: vec![],
            predicted: vec![],
        };
        assert_eq!(
            resolve_admin_boot_interface_target(Some(stored), Some(&empty), None),
            None,
        );
        assert_eq!(resolve_admin_boot_interface_target(None, None, None), None);
    }
}
