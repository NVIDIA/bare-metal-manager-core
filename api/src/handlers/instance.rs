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
use crate::api::{log_machine_id, log_request_data, Api};
use crate::db::{
    self,
    instance::{DeleteInstance, Instance},
    managed_host::LoadSnapshotOptions,
    network_security_group, DatabaseError,
};
use crate::instance::{allocate_instance, InstanceAllocationRequest};
use crate::model::instance::config::tenant_config::TenantConfig;
use crate::model::instance::config::InstanceConfig;
use crate::model::instance::status::network::InstanceNetworkStatusObservation;
use crate::model::machine::machine_id::try_parse_machine_id;
use crate::model::machine::ManagedHostStateSnapshot;
use crate::model::metadata::Metadata;
use crate::model::os::OperatingSystem;
use crate::redfish::RedfishAuth;
use crate::CarbideError;
use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey};
use forge_uuid::instance::InstanceId;
use std::str::FromStr;
use tonic::{Request, Response, Status};

pub(crate) async fn allocate(
    api: &Api,
    request: Request<rpc::InstanceAllocationRequest>,
) -> Result<Response<rpc::Instance>, Status> {
    log_request_data(&request);

    let request = InstanceAllocationRequest::try_from(request.into_inner())?;

    log_machine_id(&request.machine_id);

    // Row-locking on Machine records happens in allocate_instance
    let mh_snapshot = allocate_instance(
        request,
        &api.database_connection,
        api.runtime_config.host_health.hardware_health_reports,
        api,
    )
    .await?;

    Ok(Response::new(snapshot_to_instance(mh_snapshot)?))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::InstanceSearchFilter>,
) -> Result<Response<rpc::InstanceIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin instance::find_ids",
            e,
        ))
    })?;

    let filter: rpc::InstanceSearchFilter = request.into_inner();

    let instance_ids = Instance::find_ids(&mut txn, filter).await?;

    Ok(tonic::Response::new(rpc::InstanceIdList {
        instance_ids: instance_ids
            .into_iter()
            .map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            })
            .collect(),
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::InstancesByIdsRequest>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    let instance_ids: Result<Vec<InstanceId>, CarbideError> = request
        .into_inner()
        .instance_ids
        .iter()
        .map(|id| {
            InstanceId::from_str(id.value.as_str()).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidInstanceId(
                    id.value.to_string(),
                ))
            })
        })
        .collect();
    let instance_ids = instance_ids?;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if instance_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if instance_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin instance::find_by_ids",
            e,
        ))
    })?;
    let snapshots = db::managed_host::load_by_instance_ids(
        &mut txn,
        instance_ids.as_ref(),
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?;
    let mut instances = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots.into_iter() {
        instances.push(snapshot_to_instance(snapshot)?);
    }
    let _ = txn.rollback().await;

    Ok(Response::new(rpc::InstanceList { instances }))
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::InstanceSearchQuery>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instances",
            e,
        ))
    })?;

    let rpc::InstanceSearchQuery { id, label, .. } = request.into_inner();
    let instance_ids = match (id, label) {
        (Some(id), None) => {
            vec![InstanceId::try_from(id)
                .map_err(|_| CarbideError::InvalidArgument("id".to_string()))?]
        }
        (None, None) => Instance::find_ids(&mut txn, Default::default())
            .await
            .map_err(CarbideError::from)?,

        (None, Some(label)) => Instance::find_ids(
            &mut txn,
            rpc::InstanceSearchFilter {
                label: Some(label),
                ..Default::default()
            },
        )
        .await
        .map_err(CarbideError::from)?,

        (Some(_id), Some(_label)) => {
            return Err(CarbideError::InvalidArgument(
                "Searching instances based on both id and labels is not supported.".to_string(),
            )
            .into());
        }
    };

    let snapshots = db::managed_host::load_by_instance_ids(
        &mut txn,
        &instance_ids,
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?;

    // Convert snapshots to instances via [`snapshot_to_instance`]
    let instances = snapshots
        .into_iter()
        .map(snapshot_to_instance)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Response::new(rpc::InstanceList { instances }))
}

pub(crate) async fn find_by_machine_id(
    api: &Api,
    request: Request<::rpc::common::MachineId>,
) -> Result<Response<rpc::InstanceList>, Status> {
    log_request_data(&request);

    let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;
    log_machine_id(&machine_id);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instance_by_machine_id",
            e,
        ))
    })?;

    let mh_snapshot = match db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return Ok(Response::new(rpc::InstanceList { instances: vec![] })),
        Err(e) => return Err(CarbideError::from(e).into()),
    };

    let maybe_instance =
        Option::<rpc::Instance>::try_from(mh_snapshot).map_err(CarbideError::from)?;

    let instances = if let Some(instance) = maybe_instance {
        vec![instance]
    } else {
        vec![]
    };

    let response = Response::new(rpc::InstanceList { instances });

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_instance_by_machine_id",
            e,
        ))
    })?;

    Ok(response)
}

pub(crate) async fn release(
    api: &Api,
    request: Request<rpc::InstanceReleaseRequest>,
) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
    log_request_data(&request);
    let delete_instance = DeleteInstance::try_from(request.into_inner())?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin release_instance",
            e,
        ))
    })?;

    let instance = Instance::find_by_id(&mut txn, delete_instance.instance_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "instance",
            id: delete_instance.instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    if instance.deleted.is_some() {
        tracing::info!(
            instance_id = %delete_instance.instance_id,
            "Instance is already marked for deletion.",
        );
        return Ok(Response::new(rpc::InstanceReleaseResult {}));
    }

    // TODO: This is racy. If the instance just got deleted we still
    // see an error here that is not returned as `NotFound` error. Ideally
    // we convert this case of the DatabaseError into NotFound too.
    delete_instance.mark_as_deleted(&mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit release_instance",
            e,
        ))
    })?;

    Ok(Response::new(rpc::InstanceReleaseResult {}))
}

pub(crate) async fn record_observed_network_status(
    api: &Api,
    request: Request<rpc::InstanceNetworkStatusObservation>,
) -> Result<Response<rpc::ObservedInstanceNetworkStatusRecordResult>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let instance_id = InstanceId::from_grpc(request.instance_id.clone())?;

    let observation =
        InstanceNetworkStatusObservation::try_from(request).map_err(CarbideError::from)?;
    observation
        .validate()
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin record_observed_instance_network_status",
            e,
        ))
    })?;
    Instance::update_network_status_observation(&mut txn, instance_id, &observation)
        .await
        .map_err(CarbideError::from)?;
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit record_observed_instance_network_status",
            e,
        ))
    })?;

    Ok(Response::new(
        rpc::ObservedInstanceNetworkStatusRecordResult {},
    ))
}

pub(crate) async fn update_phone_home_last_contact(
    api: &Api,
    request: Request<rpc::InstancePhoneHomeLastContactRequest>,
) -> Result<Response<rpc::InstancePhoneHomeLastContactResponse>, Status> {
    let request = request.into_inner();
    let instance_id = InstanceId::from_grpc(request.instance_id.clone())?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_instance_phone_home_last_contact",
            e,
        ))
    })?;

    let instance = Instance::find_by_id(&mut txn, instance_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "instance",
            id: instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    let res = Instance::update_phone_home_last_contact(&mut txn, instance.id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_instance_phone_home_last_contact",
            e,
        ))
    })?;

    Ok(Response::new(rpc::InstancePhoneHomeLastContactResponse {
        timestamp: Some(res.into()),
    }))
}

pub(crate) async fn invoke_power(
    api: &Api,
    request: Request<rpc::InstancePowerRequest>,
) -> Result<Response<rpc::InstancePowerResult>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin invoke_instance_power",
            e,
        ))
    })?;

    let request = request.into_inner();
    let machine_id = match &request.machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(Status::invalid_argument("A machine id is required"));
        }
    };
    log_machine_id(&machine_id);

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;
    if snapshot.instance.is_none() {
        return Err(Status::invalid_argument(format!(
            "Supplied invalid UUID: {}",
            machine_id
        )));
    }
    let bmc_ip =
        snapshot
            .host_snapshot
            .bmc_info
            .ip
            .as_ref()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_ip",
                id: machine_id.to_string(),
            })?;

    let run_provisioning_instructions_on_every_boot = snapshot
        .instance
        .map(|instance| {
            instance
                .config
                .os
                .run_provisioning_instructions_on_every_boot
        })
        .unwrap_or_default();

    if !run_provisioning_instructions_on_every_boot {
        Instance::use_custom_ipxe_on_next_boot(
            &machine_id,
            request.boot_with_custom_ipxe,
            &mut txn,
        )
        .await
        .map_err(CarbideError::from)?;
    }

    // Check if reprovision is requested.
    // TODO: multidpu: Fix it for multiple dpus.
    let mut reprovision_handled = false;
    if request.apply_updates_on_reboot {
        if snapshot.dpu_snapshots.is_empty() {
            return Err(CarbideError::internal(
                "Request update for DPU is requested, but no DPU found.".to_string(),
            )
            .into());
        }
        for dpu_snapshot in &snapshot.dpu_snapshots {
            let Some(rr) = &dpu_snapshot.reprovision_requested else {
                continue;
            };

            if rr.started_at.is_some() {
                return Err(CarbideError::DpuReprovisioningInProgress(format!(
                    "Can't reboot host: {}",
                    machine_id
                ))
                .into());
            }

            reprovision_handled = true;

            // This will trigger DPU reprovisioning/update via state machine.
            db::machine::approve_dpu_reprovision_request(&dpu_snapshot.id, &mut txn)
                .await
                .map_err(|err| {
                    // print actual error for debugging, but don't leak internal info to user.
                    tracing::error!(machine=%machine_id, "{:?}", err);

                    // TODO: What does this error actually mean
                    CarbideError::internal(
                        "Internal Failure. Try again after sometime.".to_string(),
                    )
                })?;
        }
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit invoke_instance_power",
            e,
        ))
    })?;

    if reprovision_handled {
        // Host will reboot once DPU reprovisioning is successfully finished.
        return Ok(Response::new(rpc::InstancePowerResult {}));
    }

    let bmc_mac_address =
        snapshot
            .host_snapshot
            .bmc_info
            .mac
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_mac",
                id: machine_id.to_string(),
            })?;

    // TODO: The API call should maybe not directly trigger the reboot
    // but instead queue it for the state handler. That will avoid racing
    // with other internal reboot requests from the state handler.
    let client = api
        .redfish_pool
        .create_client(
            bmc_ip,
            snapshot.host_snapshot.bmc_info.port,
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
            }),
            true,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    // Lenovo does not yet provide a BMC lockdown so a user could
    // change the boot order which we set in `libredfish::forge_setup`.
    // We also can't call `boot_once` for other vendors because lockdown
    // prevents it.
    if snapshot.host_snapshot.bmc_vendor().is_lenovo() {
        client
            .boot_once(libredfish::Boot::Pxe)
            .await
            .map_err(CarbideError::from)?;
    }
    client
        .power(libredfish::SystemPowerControl::ForceRestart)
        .await
        .map_err(|e| {
            CarbideError::internal(format!("Failed redfish ForceRestart subtask: {}", e))
        })?;

    Ok(Response::new(rpc::InstancePowerResult {}))
}

pub(crate) async fn update_operating_system(
    api: &Api,
    request: Request<rpc::InstanceOperatingSystemUpdateRequest>,
) -> Result<Response<rpc::Instance>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let instance_id = InstanceId::from_grpc(request.instance_id.clone())?;

    let os: OperatingSystem = match request.os {
        None => return Err(CarbideError::MissingArgument("os").into()),
        Some(os) => os.try_into().map_err(CarbideError::from)?,
    };
    os.validate().map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_instance_operating_system",
            e,
        ))
    })?;

    let instance = Instance::find_by_id(&mut txn, instance_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or(CarbideError::NotFoundError {
            kind: "instance",
            id: instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    let expected_version = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => instance.config_version,
    };

    Instance::update_os(&mut txn, instance.id, expected_version, os)
        .await
        .map_err(CarbideError::from)?;

    let mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &instance.machine_id,
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "instance",
        id: instance_id.to_string(),
    })?;
    let instance = snapshot_to_instance(mh_snapshot)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_instance_operating_system",
            e,
        ))
    })?;

    Ok(Response::new(instance))
}

pub(crate) async fn update_instance_config(
    api: &Api,
    request: tonic::Request<rpc::InstanceConfigUpdateRequest>,
) -> Result<tonic::Response<rpc::Instance>, Status> {
    let request = request.into_inner();
    let instance_id = InstanceId::from_grpc(request.instance_id.clone())?;

    let config: InstanceConfig = match request.config {
        None => return Err(CarbideError::MissingArgument("config").into()),
        Some(config) => config.try_into().map_err(CarbideError::from)?,
    };
    config.validate().map_err(CarbideError::from)?;

    // TODO: Should a missing metadata field
    // - be an error
    // - lead to writing empty metadata (same as initial instance creation will do)
    // - keep existing metadata
    let metadata: Metadata = match request.metadata {
        None => return Err(CarbideError::MissingArgument("metadata").into()),
        Some(metadata) => metadata.try_into().map_err(CarbideError::from)?,
    };
    metadata.validate(true).map_err(|e| {
        CarbideError::InvalidArgument(format!("Instance metadata is not valid: {}", e))
    })?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_instance_config",
            e,
        ))
    })?;

    let instance = Instance::find_by_id(&mut txn, instance_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or(CarbideError::NotFoundError {
            kind: "instance",
            id: instance_id.to_string(),
        })?;

    log_machine_id(&instance.machine_id);

    // Check whether the update is allowed
    instance
        .config
        .verify_update_allowed_to(&config)
        .map_err(CarbideError::from)?;

    let expected_version = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => instance.config_version,
    };

    // If an NSG is applied, we need to do a little more validation.
    if let InstanceConfig {
        network_security_group_id: Some(ref nsg_id),
        tenant:
            TenantConfig {
                tenant_organization_id: ref tenant_org,
                ..
            },
        ..
    } = config
    {
        // Query to check the validity of the NSG ID but to also grab
        // a row-level lock on it if it exists.
        if network_security_group::find_by_ids(&mut txn, &[nsg_id.clone()], Some(tenant_org), true)
            .await?
            .pop()
            .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                nsg_id,
                tenant_org.clone(),
            ))
            .into());
        }
    }

    Instance::update_config(&mut txn, instance.id, expected_version, config, metadata)
        .await
        .map_err(CarbideError::from)?;

    let mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &instance.machine_id,
        LoadSnapshotOptions::default()
            .with_hw_health(api.runtime_config.host_health.hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "instance",
        id: instance_id.to_string(),
    })?;
    let instance = snapshot_to_instance(mh_snapshot)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_instance_config",
            e,
        ))
    })?;

    Ok(Response::new(instance))
}

/// Extracts the RPC representation of Instances from a ManagedHost snapshot
///
/// This method expects that the snapshot must contain an instance definition.
/// If this is not required, then `Option::<rpc::Instance>::try_from(mh_snapshot)`
/// can be utilized.
fn snapshot_to_instance(
    mh_snapshot: ManagedHostStateSnapshot,
) -> Result<rpc::Instance, CarbideError> {
    let machine_id = mh_snapshot.host_snapshot.id;
    Option::<rpc::Instance>::try_from(mh_snapshot)
        .map_err(CarbideError::from)?
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "Instance on Machine {} can be converted from snapshot",
                machine_id
            ))
        })
}
