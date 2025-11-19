/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use model::machine::machine_search_config::MachineSearchConfig;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

// This is a work-around for FORGE-7085.  Due to an issue with interface reporting in the host BMC
// its possible that the primary DPU is not the lowest slot DPU.  Functionally this is not a problem
// but the host names interfaces by pci address so the behavior between machines of the same type
// is different.
//
// this function is broken into the following parts
// 1. collect interface and bmc information
// 2. set the boot device
// 3. update the primary interface and network config versions.
// 4. reboot the host if requested.
//
// No transaction should be held during 2 or 4 since they are requests to the host bmc.
//
pub(crate) async fn set_primary_dpu(
    api: &Api,
    request: Request<rpc::SetPrimaryDpuRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let host_machine_id = request
        .host_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("Host Machine ID is required".to_string()))?;
    let dpu_machine_id = request
        .dpu_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("DPU Machine ID is required".to_string()))?;

    log_machine_id(&host_machine_id);

    let mut txn = api.txn_begin("set_primary_dpu").await?;

    let interface_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;

    let interface_snapshots =
        interface_map
            .get(&host_machine_id)
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;

    // Find the interface id for the old primary dpu and the interface for the new primary dpu.  they have to be found
    // before the db update since the "only one primary" constraint will cause a failure
    // if the new interface is found first.
    let mut current_primary_interface_id = None;
    let mut new_primary_interface = None;

    for interface_snapshot in interface_snapshots {
        if interface_snapshot.primary_interface {
            let Some(attached_dpu_machine_id) = interface_snapshot.attached_dpu_machine_id else {
                return Err(CarbideError::InvalidArgument(
                    "Primary interface is not associated with a DPU.  Operation not supported"
                        .to_string(),
                )
                .into());
            };

            if attached_dpu_machine_id == dpu_machine_id {
                return Err(CarbideError::InvalidArgument(
                    "Requested DPU is already primary".to_string(),
                )
                .into());
            }
            current_primary_interface_id = Some(interface_snapshot.id);
            tracing::info!("Removing primary from {}", attached_dpu_machine_id);
        } else if interface_snapshot.attached_dpu_machine_id == Some(dpu_machine_id) {
            new_primary_interface = Some(interface_snapshot);
            tracing::info!("Setting primary on {}", dpu_machine_id);
        }
    }

    // we need to set the boot device or the host will no longer be able to boot.  we need BMC info.
    // the same BMC info is used if a reboot was requested.
    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Machine",
            id: host_machine_id.to_string(),
        })?;

    let bmc_addr_str = machine
        .bmc_info
        .ip
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC IP",
            id: host_machine_id.to_string(),
        })?;

    let bmc_addr = IpAddr::from_str(&bmc_addr_str).map_err(CarbideError::AddressParseError)?;
    let bmc_socket_addr = SocketAddr::new(bmc_addr, 443);

    let bmc_interface = db::machine_interface::find_by_ip(&mut txn, bmc_addr)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC Interface",
            id: bmc_addr.to_string(),
        })?;

    let primary_interface_mac_address = new_primary_interface
        .ok_or_else(|| {
            CarbideError::internal("Primary interface disappeared during update".to_string())
        })?
        .mac_address
        .to_string();

    txn.rollback().await?;

    let Some(current_primary_interface_id) = current_primary_interface_id else {
        return Err(CarbideError::internal(
            "Could not determing old primary interface id".to_string(),
        )
        .into());
    };
    let Some(new_primary_interface) = new_primary_interface else {
        return Err(CarbideError::internal(
            "Could not determing new primary interface id".to_string(),
        )
        .into());
    };

    // set the boot device
    api.endpoint_explorer
        .set_boot_order_dpu_first(
            bmc_socket_addr,
            &bmc_interface,
            &primary_interface_mac_address,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let mut txn = api.txn_begin("set_primary_dpu").await?;

    // update the primary interface
    db::machine_interface::set_primary_interface(&current_primary_interface_id, false, &mut txn)
        .await?;
    db::machine_interface::set_primary_interface(&new_primary_interface.id, true, &mut txn).await?;

    // increment the network config version so that the DPUs pick up their new config
    let (network_config, network_config_version) =
        db::machine::get_network_config(&mut txn, &host_machine_id)
            .await?
            .take();
    db::machine::try_update_network_config(
        &mut txn,
        &host_machine_id,
        network_config_version,
        &network_config,
    )
    .await?;

    // if there is an instance, update the instances network config version so the DPUs pick up the new config
    if let Some(instance) = db::instance::find_by_machine_id(&mut txn, &host_machine_id).await? {
        db::instance::update_network_config(
            &mut txn,
            instance.id,
            instance.network_config_version,
            &instance.config.network,
            true,
        )
        .await?;
    }

    txn.commit().await?;

    // optionally reboot the host.  if there is an instance, this is probably a required step,
    // but an operator will need to make that call.  The scout image handles this pretty well,
    // albeit with a leftover IP on the unused interface
    if request.reboot {
        api.endpoint_explorer
            .redfish_power_control(
                bmc_socket_addr,
                &bmc_interface,
                libredfish::SystemPowerControl::ForceRestart,
            )
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;
    }
    Ok(Response::new(()))
}
