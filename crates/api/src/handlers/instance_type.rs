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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use config_version::ConfigVersion;
use db::{ObjectFilter, instance, instance_type};
use model::instance_type::InstanceTypeMachineCapabilityFilter;
use model::machine::machine_search_config::MachineSearchConfig;
use model::metadata::Metadata;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::CarbideError;
use crate::api::{Api, log_request_data};

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
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
        })?,
    };

    // Prepare the metadata
    let metadata = match req.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            );
        }
    };

    metadata.validate(true).map_err(CarbideError::from)?;

    // Prepare the capabilities list
    let mut desired_capabilities = Vec::<InstanceTypeMachineCapabilityFilter>::new();

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
    let mut txn = api.txn_begin().await?;

    // Write a new instance type to the DB and get back
    // our new InstanceType.
    let instance_type =
        instance_type::create(&mut txn, &id, &metadata, &desired_capabilities).await?;

    // Prepare the response to send back
    let rpc_out = rpc::CreateInstanceTypeResponse {
        instance_type: Some(instance_type.try_into()?),
    };

    //  Commit our txn if nothing has gone wrong so far.
    txn.commit().await?;

    // Send our response back.
    Ok(Response::new(rpc_out))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::FindInstanceTypeIdsRequest>,
) -> Result<Response<rpc::FindInstanceTypeIdsResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let instance_type_ids = instance_type::find_ids(&mut txn, false).await?;

    let rpc_out = rpc::FindInstanceTypeIdsResponse {
        instance_type_ids: instance_type_ids.iter().map(|i| i.to_string()).collect(),
    };

    txn.commit().await?;

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
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
        })?);
    }

    // Prepare our txn to grab the instance types from the DB
    let mut txn = api.txn_begin().await?;

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
    txn.commit().await?;

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
        CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
    })?;

    // Prepare the metadata
    let metadata = match req.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            );
        }
    };

    metadata.validate(true).map_err(CarbideError::from)?;

    // Prepare the desired capabilities list
    let mut desired_capabilities = Vec::<InstanceTypeMachineCapabilityFilter>::new();

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
    let mut txn = api.txn_begin().await?;

    // Look up the instance type.  We'll need to check the current
    // version. We could probably do everything with a single query
    // with a few subqueries, but we'd only be able to send back a
    // NotFound, leaving the caller with no way to know if it was
    // because their instance type wasn't found or because the version
    // didn't match.  We'll need to also bump the version, anyway.
    let mut current_instance_type =
        instance_type::find_by_ids(&mut txn, std::slice::from_ref(&id), true).await?;

    // If we found more than one, the DB is corrupt.
    if current_instance_type.len() > 1 {
        // CarbideError::FindOneReturnedManyResultsError expects a uuid,
        // and we've said we want to move away from uuid::Uuid
        return Err(CarbideError::Internal {
            message: format!("multiple InstanceType records found for '{id}'"),
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
            .into());
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
    let existing_associated_machines =
        db::machine::find_ids_by_instance_type_id(&mut txn, &id, true).await?;

    // Forge-cloud allows users to change metadata changes (name, description, and label),
    // so we'll need to allow the same here.
    // The burden of maintaining the order of the capability filters is on the caller.
    // Capability filters are NOT allowed to change if an InstanceType is in use.
    if current_instance_type.desired_capabilities != desired_capabilities
        && !existing_associated_machines.is_empty()
    {
        return Err(CarbideError::FailedPrecondition(format!(
            "InstanceType {id} is associated with active machines"
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
    txn.commit().await?;

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
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
        })?;

    // Prepare our txn to delete from the DB
    let mut txn = api.txn_begin().await?;

    // Look for any related machines.  Forge-Cloud provides users with
    // the behavior of removing all machine associations to an InstanceType for machines
    // as long as all machines affected have no associated instances.
    // We need to replicate this here so that it's a single call.

    //  This will also grab a row lock on the requested machines so we can
    // coordinate with the instance allocation handler.
    let existing_associated_machines =
        db::machine::find_ids_by_instance_type_id(&mut txn, &id, true).await?;

    // Check that there are no associated instances for the machines.
    let instances = instance::find_by_machine_ids(
        &mut txn,
        &existing_associated_machines
            .iter()
            .map(|v| &v.0)
            .collect::<Vec<_>>(),
    )
    .await?;

    if !instances.is_empty() {
        return Err(CarbideError::FailedPrecondition(format!(
            "InstanceType {id} is associated with machines that have active instances"
        ))
        .into());
    }

    // Make our DB query to remove the machine associations.
    let _ids = db::machine::remove_instance_type_associations(
        &mut txn,
        &existing_associated_machines
            .iter()
            .map(|v| (&v.0, &v.1))
            .collect::<Vec<_>>(),
    )
    .await?;

    // Make our DB query to soft delete the instance type
    let _id = instance_type::soft_delete(&mut txn, &id).await?;

    // Prepare the response message
    let rpc_out = rpc::DeleteInstanceTypeResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await?;

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

    let instance_type_id = req
        .instance_type_id
        .parse::<InstanceTypeId>()
        .map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
        })?;

    // Prepare our txn to associate machines with the instance type
    let mut txn = api.txn_begin().await?;

    // Query the DB to make sure the instance type is valid/active.
    let instance_types =
        instance_type::find_by_ids(&mut txn, std::slice::from_ref(&instance_type_id), true).await?;

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
                            CarbideError::InvalidArgument(format!("{m_id} is a DPU")).into()
                        );
                    }
                },
            },
        );
    }

    let instance_type_id = req
        .instance_type_id
        .parse::<InstanceTypeId>()
        .map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
        })?;

    // Query the DB to make sure the instance type is valid/active.
    let instance_types =
        instance_type::find_by_ids(&mut txn, std::slice::from_ref(&instance_type_id), true).await?;

    if instance_types.len() > 1 {
        return Err(CarbideError::Internal {
            message: format!("multiple InstanceType records found for '{instance_type_id}'"),
        }
        .into());
    }

    if instance_types.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "InstanceType",
            id: req.instance_type_id,
        }
        .into());
    }

    // Grab the requested machines so we can row-lock and
    // also get their most recent snapshots so we can check
    // their capabilities.
    let machines = db::machine::find(
        &mut txn,
        ObjectFilter::List(&machine_ids),
        MachineSearchConfig {
            for_update: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;

    // Check that there are no associated instances for the machines.
    // I expected machine.has_instance() to handle this, but the data
    // that drives that doesn't seem to get persisted until sometime in
    // the future after an instance is created in the DB.
    let instances =
        instance::find_by_machine_ids(&mut txn, &machine_ids.iter().collect::<Vec<_>>()).await?;

    if !instances.is_empty() {
        return Err(CarbideError::FailedPrecondition(
            "one or more machines have instances assigned".to_string(),
        )
        .into());
    }

    let mut machine_versions = Vec::new();

    // Go through the requested machines and make sure they
    //actually meet the requirements of the instance type.
    for machine in machines.iter() {
        let capabilities = machine
            .to_capabilities()
            .ok_or(CarbideError::InvalidArgument(format!(
                "capabilities of machine {} do not satisfy the requested InstanceType ({})",
                machine.id, instance_type_id
            )))?;

        if !instance_types[0].matches_capability_set(&capabilities) {
            return Err(CarbideError::InvalidArgument(format!(
                "capabilities of machine {} do not satisfy the requested InstanceType ({})",
                machine.id, instance_type_id
            ))
            .into());
        }
        machine_versions.push((&machine.id, &machine.version));
    }

    // Make our DB query for the association
    let ids = db::machine::associate_machines_with_instance_type(
        &mut txn,
        &instance_type_id,
        &machine_versions,
    )
    .await?;

    if ids.len() != machine_versions.len() {
        tracing::error!(
            "Not all machine's instances updated. This should never happen because we take row-lock. Something is terribly wrong. ids: {ids:?}; versions: {machine_versions:?}"
        )
    }

    // Prepare the response message
    let rpc_out = rpc::AssociateMachinesWithInstanceTypeResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await?;

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
    let mut txn = api.txn_begin().await?;

    // Grab a row lock on the requested machine so we can
    // coordinate with the instance allocation handler and
    // check for the existence of instances.
    let mut machines = db::machine::find(
        &mut txn,
        ObjectFilter::List(&[machine_id]),
        MachineSearchConfig {
            for_update: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;

    let Some(machine) = machines.pop() else {
        return Err(CarbideError::NotFoundError {
            kind: "Machine",
            id: machine_id.to_string(),
        }
        .into());
    };

    // Check that there are no associated instances for the machines.
    let instances = instance::find_by_machine_ids(&mut txn, &[&machine_id]).await?;

    if let Some(instance) = instances.first()
        && instance.deleted.is_none()
    {
        return Err(CarbideError::FailedPrecondition(format!(
            "machine {} has instance assigned. This operation is allowed only in terminating state.",
            &machine.id
        ))
        .into());
    }

    // Make our DB query to remove the association
    let _id = db::machine::remove_instance_type_associations(
        &mut txn,
        &[(&machine.id, &machine.version)],
    )
    .await?;

    // Prepare the response message
    let rpc_out = rpc::RemoveMachineInstanceTypeAssociationResponse {};

    // Commit if nothing has gone wrong up to now
    txn.commit().await?;

    // Send our response back
    Ok(Response::new(rpc_out))
}
