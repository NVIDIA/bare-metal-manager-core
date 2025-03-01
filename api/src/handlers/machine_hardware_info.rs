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
use crate::{
    CarbideError,
    api::{Api, log_machine_id, log_request_data},
    db::{DatabaseError, machine_topology::MachineTopology},
};
use ::rpc::forge::{MachineHardwareInfoUpdateType, UpdateMachineHardwareInfoRequest};
use tonic::{Request, Response, Status};

pub(crate) async fn handle_machine_hardware_info_update(
    api: &Api,
    request: Request<UpdateMachineHardwareInfoRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let update_hardware_info_request = request.into_inner();

    let machine_id = crate::model::machine::machine_id::try_parse_machine_id(
        &update_hardware_info_request
            .machine_id
            .ok_or(CarbideError::InvalidArgument(String::from(
                "Machine ID not set",
            )))?,
    )
    .map_err(CarbideError::from)?;
    log_machine_id(&machine_id);

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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update machine hardware info",
            e,
        ))
    })?;

    let machine_topology = MachineTopology::find_latest_by_machine_ids(&mut txn, &[machine_id])
        .await
        .map_err(CarbideError::from)?;

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
            let gpus: Vec<crate::model::hardware_info::Gpu> = request_hardware_info
                .gpus
                .into_iter()
                .map(crate::model::hardware_info::Gpu::from)
                .collect();
            if gpus.is_empty() {
                new_hardware_info.gpus.clear();
            } else {
                new_hardware_info.gpus.extend(gpus);
            }
        }
    }

    // This is kinda messy, but it's this or make MachineTopology::update public.
    MachineTopology::set_topology_update_needed(&mut txn, &machine_id, true)
        .await
        .map_err(CarbideError::from)?;
    MachineTopology::create_or_update(&mut txn, &machine_id, &new_hardware_info).await?;

    // Set this so the next machine discovery overwrites the data?
    MachineTopology::set_topology_update_needed(&mut txn, &machine_id, true)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update machine hardware info",
            e,
        ))
    })?;
    Ok(Response::new(()))
}
