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

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineInterfaceId;
use model::machine_boot_override::MachineBootOverride;

use crate::api::Api;

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<MachineInterfaceId>,
) -> Result<tonic::Response<rpc::MachineBootOverride>, tonic::Status> {
    crate::api::log_request_data(&request);

    let machine_interface_id = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let machine_id = match db::machine_interface::find_one(&mut txn, machine_interface_id).await {
        Ok(interface) => interface.machine_id,
        Err(_) => None,
    };

    if let Some(machine_id) = machine_id {
        crate::api::log_machine_id(&machine_id);
    }

    let mbo = match db::machine_boot_override::find_optional(&mut txn, machine_interface_id).await?
    {
        Some(mbo) => mbo,
        None => MachineBootOverride {
            machine_interface_id,
            custom_pxe: None,
            custom_user_data: None,
        },
    };

    txn.commit().await?;

    Ok(tonic::Response::new(mbo.into()))
}

pub(crate) async fn set(
    api: &Api,
    request: tonic::Request<rpc::MachineBootOverride>,
) -> Result<tonic::Response<()>, tonic::Status> {
    crate::api::log_request_data(&request);

    let mbo: MachineBootOverride = request.into_inner().try_into()?;
    let mut txn = api.txn_begin().await?;

    let machine_id = match db::machine_interface::find_one(&mut txn, mbo.machine_interface_id).await
    {
        Ok(interface) => interface.machine_id,
        Err(_) => None,
    };
    match machine_id {
        Some(machine_id) => {
            crate::api::log_machine_id(&machine_id);
            tracing::warn!(
                machine_interface_id = mbo.machine_interface_id.to_string(),
                machine_id = machine_id.to_string(),
                "Boot override for machine_interface_id is active. Bypassing regular boot"
            );
        }

        None => tracing::warn!(
            machine_interface_id = mbo.machine_interface_id.to_string(),
            "Boot override for machine_interface_id is active. Bypassing regular boot"
        ),
    }

    db::machine_boot_override::update_or_insert(&mbo, &mut txn).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn clear(
    api: &Api,
    request: tonic::Request<MachineInterfaceId>,
) -> Result<tonic::Response<()>, tonic::Status> {
    crate::api::log_request_data(&request);

    let machine_interface_id = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let machine_id = match db::machine_interface::find_one(&mut txn, machine_interface_id).await {
        Ok(interface) => interface.machine_id,
        Err(_) => None,
    };
    match machine_id {
        Some(machine_id) => {
            crate::api::log_machine_id(&machine_id);
            tracing::info!(
                machine_interface_id = machine_interface_id.to_string(),
                machine_id = machine_id.to_string(),
                "Boot override for machine_interface_id disabled."
            );
        }

        None => tracing::info!(
            machine_interface_id = machine_interface_id.to_string(),
            "Boot override for machine_interface_id disabled"
        ),
    }
    db::machine_boot_override::clear(&mut txn, machine_interface_id).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}
