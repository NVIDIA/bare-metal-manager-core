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
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;

use crate::api::Api;
use crate::db::machine_boot_override::MachineBootOverride;
use crate::db::machine_interface::MachineInterface;
use crate::db::DatabaseError;
use crate::CarbideError;

pub(crate) async fn get<C1, C2>(
    api: &Api<C1, C2>,
    request: tonic::Request<rpc::Uuid>,
) -> Result<tonic::Response<rpc::MachineBootOverride>, tonic::Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let machine_interface_id_str = &request.into_inner().value;

    let machine_interface_id = uuid::Uuid::parse_str(machine_interface_id_str)
        .map_err(CarbideError::UuidConversionError)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_boot_override ",
            e,
        ))
    })?;

    let machine_id = match MachineInterface::find_one(&mut txn, machine_interface_id).await {
        Ok(interface) => interface.machine_id,
        Err(_) => None,
    };

    if let Some(machine_id) = machine_id {
        crate::api::log_machine_id(&machine_id);
    }

    let mbo = match MachineBootOverride::find_optional(&mut txn, machine_interface_id).await? {
        Some(mbo) => mbo,
        None => MachineBootOverride {
            machine_interface_id,
            custom_pxe: None,
            custom_user_data: None,
        },
    };

    Ok(tonic::Response::new(mbo.into()))
}

pub(crate) async fn set<C1, C2>(
    api: &Api<C1, C2>,
    request: tonic::Request<rpc::MachineBootOverride>,
) -> Result<tonic::Response<()>, tonic::Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let mbo: MachineBootOverride = request.into_inner().try_into()?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin set_machine_boot_override ",
            e,
        ))
    })?;

    let machine_id = match MachineInterface::find_one(&mut txn, mbo.machine_interface_id).await {
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

    mbo.update_or_insert(&mut txn).await?;

    txn.commit().await.unwrap();

    Ok(tonic::Response::new(()))
}

pub(crate) async fn clear<C1, C2>(
    api: &Api<C1, C2>,
    request: tonic::Request<rpc::Uuid>,
) -> Result<tonic::Response<()>, tonic::Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let machine_interface_id_str = &request.into_inner().value;

    let machine_interface_id = uuid::Uuid::parse_str(machine_interface_id_str)
        .map_err(CarbideError::UuidConversionError)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin clear_machine_boot_override ",
            e,
        ))
    })?;

    let machine_id = match MachineInterface::find_one(&mut txn, machine_interface_id).await {
        Ok(interface) => interface.machine_id,
        Err(_) => None,
    };
    match machine_id {
        Some(machine_id) => {
            crate::api::log_machine_id(&machine_id);
            tracing::info!(
                machine_interface_id = machine_interface_id_str,
                machine_id = machine_id.to_string(),
                "Boot override for machine_interface_id disabled."
            );
        }

        None => tracing::info!(
            machine_interface_id = machine_interface_id_str,
            "Boot override for machine_interface_id disabled"
        ),
    }
    MachineBootOverride::clear(&mut txn, machine_interface_id).await?;

    txn.commit().await.unwrap();

    Ok(tonic::Response::new(()))
}
