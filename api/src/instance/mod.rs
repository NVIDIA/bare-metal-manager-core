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

use sqlx::PgPool;

use crate::{
    db::{
        instance::{config::network::load_instance_network_config, Instance, NewInstance},
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
        network_segment::NetworkSegment,
    },
    dhcp::allocation::DhcpError,
    model::{
        config_version::{ConfigVersion, Versioned},
        instance::{
            config::{network::InterfaceFunctionId, InstanceConfig},
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

    let new_instance = NewInstance {
        machine_id: request.machine_id,
        tenant_config: &tenant_config,
        ssh_keys: request.ssh_keys,
        network_config: network_config.as_ref(),
    };

    let machine_id = new_instance.machine_id.clone();
    let info = MachineTopology::find_latest_by_machine_ids(&mut txn, &[machine_id.clone()])
        .await?
        .remove(&machine_id)
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

    if info.topology().discovery_data.info.is_dpu() {
        return Err(CarbideError::InvalidArgument(format!(
            "Machine with UUID {} is a DPU and can not be converted into an instance",
            machine_id
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

    let instance = new_instance.persist(&mut txn).await?;
    // TODO: Should we check that the network segment actually belongs to the
    // tenant?

    InstanceAddress::allocate(&mut txn, *instance.id(), &network_config.value).await?;

    // Machine will be rebooted once managed resource creation is successful.
    let snapshot = DbSnapshotLoader::default()
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
    circuit_id: String,
) -> CarbideResult<InterfaceFunctionId> {
    let segment = NetworkSegment::find_by_circuit_id(&mut *txn, circuit_id.clone()).await?;
    let network_config = load_instance_network_config(&mut *txn, instance_id)
        .await?
        .value;

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
