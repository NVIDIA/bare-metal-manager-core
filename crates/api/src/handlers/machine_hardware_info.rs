/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use ::rpc::forge::{MachineHardwareInfoUpdateType, UpdateMachineHardwareInfoRequest};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn handle_machine_hardware_info_update(
    api: &Api,
    request: Request<UpdateMachineHardwareInfoRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let update_hardware_info_request = request.into_inner();

    let machine_id = convert_and_log_machine_id(update_hardware_info_request.machine_id.as_ref())?;

    let request_hardware_info =
        update_hardware_info_request
            .info
            .ok_or(CarbideError::MissingArgument(
                "Missing hardware info in update request",
            ))?;

    let update_type = MachineHardwareInfoUpdateType::try_from(
        update_hardware_info_request.update_type,
    )
    .map_err(|e| {
        CarbideError::internal(format!(
            "failure converting MachineHardwareInfoUpdateType gRPC type {e:?}"
        ))
    })?;

    let mut txn = api.txn_begin().await?;

    let machine_topology =
        db::machine_topology::find_latest_by_machine_ids(&mut txn, &[machine_id]).await?;

    let machine_topology =
        machine_topology
            .get(&machine_id)
            .ok_or(CarbideError::NotFoundError {
                kind: "machine topology not found",
                id: machine_id.to_string(),
            })?;

    let mut new_hardware_info = machine_topology.topology().discovery_data.info.clone();
    match update_type {
        MachineHardwareInfoUpdateType::Gpus => {
            let gpus: Vec<model::hardware_info::Gpu> = request_hardware_info
                .gpus
                .into_iter()
                .map(model::hardware_info::Gpu::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            if gpus.is_empty() {
                new_hardware_info.gpus.clear();
            } else {
                new_hardware_info.gpus.extend(gpus);
            }
        }
    }

    // This is kinda messy, but it's this or make db::machine_topology::update public.
    db::machine_topology::set_topology_update_needed(&mut txn, &machine_id, true).await?;
    db::machine_topology::create_or_update(&mut txn, &machine_id, &new_hardware_info).await?;

    // Set this so the next machine discovery overwrites the data?
    db::machine_topology::set_topology_update_needed(&mut txn, &machine_id, true).await?;

    txn.commit().await?;
    Ok(Response::new(()))
}
