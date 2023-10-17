/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use itertools::Itertools;
use sqlx::PgPool;

use crate::{
    db::{
        ib_partition,
        instance::{Instance, NewInstance},
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
        network_segment::NetworkSegment,
    },
    dhcp::allocation::DhcpError,
    model::{
        config_version::{ConfigVersion, Versioned},
        instance::{
            config::{
                network::{InstanceNetworkConfig, InterfaceFunctionId},
                InstanceConfig,
            },
            snapshot::InstanceSnapshot,
        },
        machine::machine_id::{try_parse_machine_id, MachineId},
        machine::ManagedHostState,
        ConfigValidationError, RpcDataConversionError,
    },
    state_controller::snapshot_loader::{DbSnapshotLoader, InstanceSnapshotLoader},
    CarbideError, CarbideResult,
};

/// User parameters for creating an instance
#[derive(Debug)]
pub struct InstanceAllocationRequest {
    // The Machine on top of which we create an Instance
    pub machine_id: MachineId,

    // Desired configuration of the instance
    pub config: InstanceConfig,

    // Public SSH keys which are trusted
    pub ssh_keys: Vec<String>,
}

// TODO: This part will be replaced when the new API which supports multiple
// instances comes in
impl TryFrom<rpc::InstanceAllocationRequest> for InstanceAllocationRequest {
    type Error = CarbideError;

    fn try_from(request: rpc::InstanceAllocationRequest) -> Result<Self, Self::Error> {
        let machine_id = try_parse_machine_id(
            &request
                .machine_id
                .ok_or(RpcDataConversionError::MissingArgument("machine_id"))?,
        )?;
        let config = request
            .config
            .ok_or(RpcDataConversionError::MissingArgument("config"))?;

        let config = InstanceConfig::try_from(config)?;

        // The `tenant` field in the config is optional - but we need it here
        if config.tenant.is_none() {
            return Err(RpcDataConversionError::MissingArgument("InstanceConfig::tenant").into());
        }

        Ok(InstanceAllocationRequest {
            machine_id,
            config,
            ssh_keys: request.ssh_keys,
        })
    }
}

/// Allocates an instance for a tenant
pub async fn allocate_instance(
    mut request: InstanceAllocationRequest,
    database: &PgPool,
) -> Result<InstanceSnapshot, CarbideError> {
    // Validate the configuration for the instance
    // Note that this basic validation can not cross-check references
    // like `machine_id` or any `network_segments`.
    request.config.validate()?;

    let mut txn = database
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin allocate_instance", e))?;

    let tenant_config = request
        .config
        .tenant
        .take()
        .ok_or_else(|| ConfigValidationError::invalid_value("TenantConfig is missing"))?;

    let network_config = Versioned::new(request.config.network, ConfigVersion::initial());
    let ib_config = Versioned::new(request.config.infiniband, ConfigVersion::initial());

    // SSH keys can have 3 segments <algorithm> <key> <owner>
    // We are interested only in key.
    let new_instance = NewInstance {
        machine_id: request.machine_id,
        tenant_config: &tenant_config,
        ssh_keys: request
            .ssh_keys
            .into_iter()
            .map(|x| {
                x.split(' ')
                    .collect::<Vec<&str>>()
                    .get(1)
                    .map(|x| x.to_string())
                    .unwrap_or(x)
            })
            .collect_vec(),
        network_config: network_config.as_ref(),
        ib_config: ib_config.as_ref(),
    };

    let machine_id = new_instance.machine_id.clone();
    if !machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(format!(
            "Machine with UUID {} is of type {} and can not be converted into an instance",
            machine_id,
            machine_id.machine_type()
        )));
    }

    let machine = Machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!("Machine with UUID {} was not found", machine_id))
        })?;

    // A new instance can be created only in Ready state.
    // This is possible that a instance is created by user, but still not picked by state machine.
    // To avoid that race condition, need to check if db has any entry with given machine id.
    let possible_instance = Instance::find_by_machine_id(&mut txn, &machine_id).await?;

    if ManagedHostState::Ready != machine.current_state() || possible_instance.is_some() {
        return Err(CarbideError::InvalidArgument(format!(
            "Could not create instance on machine {} given machine state {:?}, Unprocessed instance: {}",
            machine_id,
            machine.current_state(),
            possible_instance.is_some()
        )));
    }

    // HBN must be working on the DPU before we allow an instance
    match Machine::find_dpu_by_host_machine_id(&mut txn, &machine_id).await? {
        Some(dpu_machine) => {
            if let Ok(false) = dpu_machine.has_healthy_network() {
                tracing::error!(%machine_id, "DPU with unhealthy network. Instance will have issues.");
                // TODO(gk) Return this error once this is done: https://jirasw.nvidia.com/browse/FORGE-2243
                //return Err(CarbideError::UnhealthyNetwork);
            }
        }
        None => {
            return Err(CarbideError::GenericError(format!(
                "Machine {machine_id} has no DPU. Cannot allocate."
            )));
        }
    }

    if machine.is_maintenance_mode() {
        return Err(CarbideError::MaintenanceMode);
    }

    // This persists the instance with initial configs, but this is lacking the config
    // for related items we are allocating. At this point in time mostly the allocated
    // IPs for the instance.
    // We allocate those now in a separate call and update `Instance`. This is ok
    // because the transaction doesn't become visible until committed anyway.
    // We can't allocate IPs before creating the instance, because the IP table
    // requires the InstanceId as owner reference.
    let instance = new_instance.persist(&mut txn).await?;
    // TODO: Should we check that the network segment actually belongs to the
    // tenant?

    // Allocate IPs. This also updates the `InstanceNetworkConfig` to store the IPs
    let network_config =
        InstanceAddress::allocate(&mut txn, *instance.id(), &network_config).await?;

    // Persist the updated `InstanceNetworkConfig`
    // We need to retain version 1
    Instance::update_network_config(
        &mut txn,
        instance.id,
        network_config.version,
        &network_config.value,
        false,
    )
    .await?;

    // Allocate GUID for infiniband interfaces/ports.
    let ib_config =
        ib_partition::allocate_port_guid(&mut txn, *instance.id(), &ib_config, &machine).await?;

    // Persist the GUID for Infiniband configuration.
    // We need to retain version 1.
    Instance::update_ib_config(
        &mut txn,
        instance.id,
        ib_config.version,
        &ib_config.value,
        false,
    )
    .await?;

    // Machine will be rebooted once managed resource creation is successful.
    let snapshot = DbSnapshotLoader {}
        .load_instance_snapshot(&mut txn, instance.id, machine.current_state())
        .await?;

    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit allocate_instance", e))?;

    Ok(snapshot)
}

pub async fn circuit_id_to_function_id(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: uuid::Uuid,
    network_config: &InstanceNetworkConfig,
    circuit_id: String,
) -> CarbideResult<InterfaceFunctionId> {
    let segment = NetworkSegment::find_by_circuit_id(&mut *txn, &circuit_id).await?;

    network_config
        .interfaces
        .iter()
        .find_map(|x| {
            if x.network_segment_id == segment.id {
                Some(x.function_id.clone())
            } else {
                None
            }
        })
        .ok_or(DhcpError::InvalidCircuitId(instance_id, circuit_id))
        .map_err(CarbideError::from)
}
