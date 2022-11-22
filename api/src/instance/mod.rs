/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;

use rpc::MachineStateMachineInput;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    db::{
        instance::{Instance, NewInstance},
        instance_subnet::InstanceSubnet,
        machine::Machine,
        machine_interface::MachineInterface,
        machine_state::MachineState,
    },
    kubernetes::create_managed_resource,
    machine_state_controller::snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader},
    model::{
        config_version::{ConfigVersion, Versioned},
        instance::config::{network::InstanceNetworkConfig, tenant::TenantConfig, InstanceConfig},
        ConfigValidationError,
    },
    CarbideError,
};

/// User parameters for creating an instance
#[derive(Debug)]
pub struct InstanceAllocationRequest {
    // The Machine on top of which we create an Instance
    pub machine_id: Uuid,

    // Desired configuration of the instance
    pub config: InstanceConfig,

    // Public SSH keys which are trusted
    pub ssh_keys: Vec<String>,
}

// TODO: This part will be replaced when the new API which supports multiple
// instances comes in
impl TryFrom<rpc::Instance> for InstanceAllocationRequest {
    type Error = CarbideError;

    fn try_from(request: rpc::Instance) -> Result<Self, Self::Error> {
        if request.id.is_some() {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Instance",
            )));
        }

        let segment_id = request
            .segment_id
            .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
            .try_into()?;

        // TODO: Should we actually move IP allocation before this, so we can
        // store it as part of our internal `Config`?
        // Downside is we might leak the IP if we don't actual persist the result
        // But maybe it isn't actually allocated so far if both things happen
        // within the same transaction.
        let network_config = InstanceNetworkConfig::for_segment_id(segment_id);

        Ok(InstanceAllocationRequest {
            machine_id: request
                .machine_id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            config: InstanceConfig {
                tenant: Some(TenantConfig {
                    tenant_id: "".to_string(),
                    user_data: request.user_data,
                    custom_ipxe: request.custom_ipxe,
                }),
                network: network_config,
            },
            ssh_keys: request.ssh_keys,
        })
    }
}

/// Allocates an instance for a tenant
pub async fn allocate_instance(
    mut request: InstanceAllocationRequest,
    database: &PgPool,
) -> Result<Instance, CarbideError> {
    // Validate the configuration for the instance
    // Note that this basic validation can not cross-check references
    // like `machine_id` or any `network_segments`.
    request.config.validate()?;

    // TODO: This check can be removed once ManagedResource sync supports multiple interfaces
    if request.config.network.interfaces.len() > 1 {
        return Err(ConfigValidationError::invalid_value(
            "Multiple interfaces are not yet supported",
        )
        .into());
    }

    let mut txn = database.begin().await?;

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

    let machine_id = new_instance.machine_id;
    // check the state of the machine
    let machine_state = DbSnapshotLoader::default()
        .load_machine_snapshot(&mut txn, new_instance.machine_id)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;
    if machine_state.hardware_info.is_dpu() {
        return Err(CarbideError::InvalidArgument(format!(
            "Machine with UUID {} is a DPU and can not be converted into an instance",
            machine_id
        )));
    }

    let machine = Machine::find_one(&mut txn, machine_id)
        .await?
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!("Machine with UUID {} was not found", machine_id))
        })?;

    let machine_interface =
        MachineInterface::get_machine_interface_primary(machine_id, &mut txn).await?;

    // A new instance can be created only in Ready state.
    match machine.current_state(&mut txn).await? {
        MachineState::Ready => {
            // Blindly march forward to ready
            machine
                .advance(&mut txn, &MachineStateMachineInput::Assign)
                .await?;
        }
        rest => {
            return Err(CarbideError::InvalidArgument(format!(
                "Could not create instance on machine {} given machine state {:?}",
                machine_id, rest
            )));
        }
    }

    let instance = new_instance.persist(&mut txn).await?;

    let mut ip_details = HashMap::new();
    for iface in network_config.interfaces.iter() {
        // TODO: Should we check that the network segment actually belongs to the
        // tenant?

        // TODO 2: This can apparently also refer to a deleted network segment
        // Or the segment might even be deleted while the instance is created
        let subnet = InstanceSubnet::create(
            &mut txn,
            &machine_interface,
            iface.network_segment_id,
            *instance.id(),
            iface.function_id.clone(),
        )
        .await?;

        // TODO: This method should probably not be on `Instance` but more
        // on `InstanceSubnet`?
        let ip_addr = instance
            .assign_address(&mut txn, subnet, iface.network_segment_id)
            .await?;
        ip_details.insert(iface.function_id.clone(), ip_addr);
    }

    let dpu_machine_id = machine_interface
        .attached_dpu_machine_id()
        .ok_or_else(|| CarbideError::MissingArgument("DPU ID"))?;

    // TODO: This needs to be updated to take the information about all interfaces
    // Maybe use `InstanceNetworkConfig` and a Map from vfid to IPs as parameter?
    create_managed_resource(
        &mut txn,
        request.machine_id,
        dpu_machine_id,
        network_config,
        ip_details,
        instance.id,
    )
    .await?;

    // Machine will be rebooted once managed resource creation is successful.

    txn.commit().await.map_err(CarbideError::from)?;

    Ok(instance)
}
