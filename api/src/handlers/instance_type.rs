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

use ::rpc::{errors::RpcDataConversionError, forge as rpc};
use config_version::ConfigVersion;
use forge_uuid::{instance_type::InstanceTypeId, machine::MachineId};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::api::{log_request_data, Api};
use crate::db::{instance_type, machine::Machine, DatabaseError};
use crate::model::{instance_type::InstanceTypeMachineCapability, metadata::Metadata};
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::CreateInstanceTypeRequest>,
) -> Result<Response<rpc::CreateInstanceTypeResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Get the ID from the request
    let id = match req.id {
        None => InstanceTypeId::from(Uuid::new_v4()),
        Some(i) => i.parse::<InstanceTypeId>().map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
        })?,
    };

    // Prepare the metadata
    let metadata = match req.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            )
        }
    };

    metadata.validate().map_err(CarbideError::from)?;

    // Prepare the capabilities list
    let mut desired_capabilities = Vec::<InstanceTypeMachineCapability>::new();

    for cap in req
        .instance_type_attributes
        .unwrap_or(rpc::InstanceTypeAttributes {
            ..Default::default()
        })
        .desired_capabilities
    {
        desired_capabilities.push(cap.try_into()?);
    }

    // Start a new transaction for a db write.
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_instance_type",
            e,
        ))
    })?;

    // Write a new instance type to the DB and get back
    // our new InstanceType.
    let instance_type =
        instance_type::create(&mut txn, &id, &metadata, &desired_capabilities).await?;

    // Prepare the response to send back
    let rpc_out = rpc::CreateInstanceTypeResponse {
        instance_type: Some(instance_type.try_into()?),
    };

    //  Commit our txn if nothing has gone wrong so far.
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_instance_type",
            e,
        ))
    })?;

    // Send our response back.
    Ok(Response::new(rpc_out))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::FindInstanceTypeIdsRequest>,
) -> Result<Response<rpc::FindInstanceTypeIdsResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instance_type_ids",
            e,
        ))
    })?;

    let instance_type_ids = instance_type::find_ids(&mut txn, false).await?;

    let rpc_out = rpc::FindInstanceTypeIdsResponse {
        instance_type_ids: instance_type_ids.iter().map(|i| i.to_string()).collect(),
    };

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_instance_type_ids",
            e,
        ))
    })?;

    Ok(Response::new(rpc_out))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::FindInstanceTypesByIdsRequest>,
) -> Result<Response<rpc::FindInstanceTypesByIdsResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if req.instance_type_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be submitted"
        ))
        .into());
    }

    if req.instance_type_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut instance_type_ids = Vec::<InstanceTypeId>::with_capacity(req.instance_type_ids.len());

    // Convert the IDs in the request to a list of InstanceTypeId
    // we can send to the DB.
    for id in req.instance_type_ids {
        instance_type_ids.push(id.parse::<InstanceTypeId>().map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
        })?);
    }

    // Prepare our txn to grab the instance types from the DB
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instance_types_by_ids",
            e,
        ))
    })?;

    // Make our DB query for the IDs to get our instance types
    let instance_types = instance_type::find_by_ids(&mut txn, &instance_type_ids, false).await?;

    let mut rpc_instance_types = Vec::<rpc::InstanceType>::with_capacity(instance_types.len());

    // Convert the list of internal InstanceType to a
    // list of proto message InstanceType to send back
    // in the response.
    for i in instance_types {
        rpc_instance_types.push(i.try_into()?);
    }

    // Prepare the response message
    let rpc_out = rpc::FindInstanceTypesByIdsResponse {
        instance_types: rpc_instance_types,
    };

    // Commit if nothing has gone wrong up to now
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_instance_types_by_ids",
            e,
        ))
    })?;

    // Send our response back
    Ok(Response::new(rpc_out))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::UpdateInstanceTypeRequest>,
) -> Result<Response<rpc::UpdateInstanceTypeResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Get the target ID
    let id = req.id.parse::<InstanceTypeId>().map_err(|e| {
        CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
    })?;

    // Prepare the metadata
    let metadata = match req.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            )
        }
    };

    metadata.validate().map_err(CarbideError::from)?;

    // Prepare the desired capabilities list
    let mut desired_capabilities = Vec::<InstanceTypeMachineCapability>::new();

    for cap in req
        .instance_type_attributes
        .unwrap_or(rpc::InstanceTypeAttributes {
            ..Default::default()
        })
        .desired_capabilities
    {
        desired_capabilities.push(cap.try_into()?);
    }

    // Start a new transaction for a db write.
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_instance_type",
            e,
        ))
    })?;

    // Look up the instance type.  We'll need to check the current
    // version. We could probably do everything with a single query
    // with a few subqueries, but we'd only be able to send back a
    // NotFound, leaving the caller with no way to know if it was
    // because their instance type wasn't found or because the version
    // didn't match.  We'll need to also bump the version, anyway.
    let mut current_instance_type =
        instance_type::find_by_ids(&mut txn, &[id.clone()], true).await?;

    // If we found more than one, the DB is corrupt.
    if current_instance_type.len() > 1 {
        // CarbideError::FindOneReturnedManyResultsError expects a uuid,
        // and we've said we want to move away from uuid::Uuid
        return Err(CarbideError::Internal {
            message: format!("multiple InstanceType records found for '{}'", id),
        }
        .into());
    }

    let current_instance_type = match current_instance_type.pop() {
        Some(i) => i,
        None => {
            return Err(CarbideError::NotFoundError {
                kind: "InstanceType",
                id: metadata.name.clone(),
            }
            .into())
        }
    };

    // Prepare the version match if present.
    if let Some(if_version_match) = req.if_version_match {
        let target_version = if_version_match
            .parse::<ConfigVersion>()
            .map_err(CarbideError::from)?;

        if current_instance_type.version != target_version {
            return Err(CarbideError::ConcurrentModificationError(
                "InstanceType",
                target_version.to_string(),
            )
            .into());
        }
    };

    // Look for any related machines.  Instance types associated with machines
    // should not be updated.  This is another one that could be a subquery, but
    // we want the caller to know the actual reason for failure.
    // At first glance, it seems a little aggressive to block metadata changes,
    // but name, description, and label changes could also be total lies depending on
    // the changes and the machines associated with the instance type.
    // Still, users might get annoyed if an instance type becomes totally immutable
    // as soon as machines are associated with it.
    // We could split update endpoints into one for metadata and one for capabilities.
    let existing_associated_machines = Machine::find_ids_by_instance_type_id(&mut txn, &id, true)
        .await
        .map_err(CarbideError::from)?;

    if !existing_associated_machines.is_empty() {
        return Err(CarbideError::FailedPrecondition(format!(
            "InstanceType {} is associated with active machines",
            id
        ))
        .into());
    }

    // Update instance in the DB and get back
    // our new InstanceType state.
    let instance_type = instance_type::update(
        &mut txn,
        &id,
        &metadata,
        &desired_capabilities,
        current_instance_type.version,
    )
    .await?;

    // Prepare the response to send back
    let rpc_out = rpc::UpdateInstanceTypeResponse {
        instance_type: Some(instance_type.try_into()?),
    };

    // Commit our txn if nothing has gone wrong so far.
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit udpdate_instance_type",
            e,
        ))
    })?;

    // Send our response back.
    Ok(Response::new(rpc_out))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::DeleteInstanceTypeRequest>,
) -> Result<Response<rpc::DeleteInstanceTypeResponse>, Status> {
    log_request_data(&request);

    let id = request
        .into_inner()
        .id
        .parse::<InstanceTypeId>()
        .map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
        })?;

    // Prepare our txn to delete from the DB
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instance_types_by_ids",
            e,
        ))
    })?;

    // Look for any related machines.  Instance types associated
    // with machines should not be deleted.  This could be a
    // subquery, but we want the caller to know the actual reason
    // for failure.
    let existing_associated_machines = Machine::find_ids_by_instance_type_id(&mut txn, &id, true)
        .await
        .map_err(CarbideError::from)?;

    if !existing_associated_machines.is_empty() {
        return Err(CarbideError::FailedPrecondition(format!(
            "InstanceType {} is associated with active machines",
            id
        ))
        .into());
    }

    // Make our DB query to soft delete the instance type
    let _id = instance_type::soft_delete(&mut txn, &id).await?;

    // Prepare the response message
    let rpc_out = rpc::DeleteInstanceTypeResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_instance_types_by_ids",
            e,
        ))
    })?;

    // Send our response back
    Ok(Response::new(rpc_out))
}

pub(crate) async fn associate_machines(
    api: &Api,
    request: Request<rpc::AssociateMachinesWithInstanceTypeRequest>,
) -> Result<Response<rpc::AssociateMachinesWithInstanceTypeResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if req.machine_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} machine IDs can be submitted"
        ))
        .into());
    }

    if req.machine_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "at least one machine ID must be provided".to_string(),
        )
        .into());
    }

    if req.machine_ids.is_empty() {
        return Err(CarbideError::from(RpcDataConversionError::MissingArgument(
            "machine_ids list must not be empty",
        ))
        .into());
    }

    let instance_type_id = req
        .instance_type_id
        .parse::<InstanceTypeId>()
        .map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
        })?;

    // Prepare our txn to associate machines with the instance type
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin associate_machines",
            e,
        ))
    })?;

    // Query the DB to make sure the instance type is valid/active.
    let instance_types =
        instance_type::find_by_ids(&mut txn, &[instance_type_id.clone()], true).await?;

    if instance_types.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "InstanceType",
            id: req.instance_type_id,
        }
        .into());
    }

    let mut machine_ids = Vec::<MachineId>::new();

    // Convert the rpc machine ID strings into MachineId, but reject if any
    // DPU machine IDs are found.
    for mac_id in req.machine_ids {
        machine_ids.push(
            match mac_id.parse::<MachineId>().map_err(|e| {
                CarbideError::from(RpcDataConversionError::InvalidMachineId(e.to_string()))
            }) {
                Err(e) => return Err(e.into()),
                Ok(m_id) => match m_id.machine_type().is_dpu() {
                    false => m_id,
                    true => {
                        return Err(
                            CarbideError::InvalidArgument(format!("{} is a DPU", m_id)).into()
                        )
                    }
                },
            },
        );
    }

    // TODO: A follow-up MR should add a check here to verify that a
    // machine's capabilities match those required by the instance type.

    // Make our DB query for the association
    let _ids =
        Machine::associate_machines_with_instance_type(&mut txn, &instance_type_id, &machine_ids)
            .await
            .map_err(CarbideError::from)?;

    // Prepare the response message
    let rpc_out = rpc::AssociateMachinesWithInstanceTypeResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit associate_machines",
            e,
        ))
    })?;

    // Send our response back
    Ok(Response::new(rpc_out))
}

pub(crate) async fn remove_machine_association(
    api: &Api,
    request: Request<rpc::RemoveMachineInstanceTypeAssociationRequest>,
) -> Result<Response<rpc::RemoveMachineInstanceTypeAssociationResponse>, Status> {
    log_request_data(&request);

    let machine_id = request
        .into_inner()
        .machine_id
        .parse::<MachineId>()
        .map_err(|e| CarbideError::from(RpcDataConversionError::InvalidMachineId(e.to_string())))?;

    // Prepare our txn to associate machines with the instance type
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin remove_machine_association",
            e,
        ))
    })?;

    // Make our DB query to remove the association
    let _id = Machine::remove_instance_type_association(&mut txn, &machine_id)
        .await
        .map_err(CarbideError::from)?;

    // Prepare the response message
    let rpc_out = rpc::RemoveMachineInstanceTypeAssociationResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit remove_machine_association",
            e,
        ))
    })?;

    // Send our response back
    Ok(Response::new(rpc_out))
}
