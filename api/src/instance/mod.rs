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

use std::collections::{HashMap, HashSet};

use config_version::ConfigVersion;
use forge_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use sqlx::{PgPool, Postgres, Transaction};

use crate::api::Api;
use crate::db::vpc_prefix::VpcPrefix;
use crate::db::ObjectColumnFilter;
use crate::model::instance::config::network::NetworkDetails;
use crate::model::machine::NotAllocatableReason;
use crate::network_segment::allocate::Ipv4PrefixAllocator;
use crate::{
    cfg::file::HardwareHealthReportsConfig,
    db::{
        self,
        ib_partition::{self, IBPartition, IBPartitionSearchConfig},
        instance::{Instance, NewInstance},
        machine::{Machine, MachineSearchConfig},
        managed_host::LoadSnapshotOptions,
        network_segment::NetworkSegment,
        DatabaseError, ObjectFilter,
    },
    dhcp::allocation::DhcpError,
    model::{
        instance::config::{
            infiniband::InstanceInfinibandConfig,
            network::{InstanceNetworkConfig, InterfaceFunctionId},
            InstanceConfig,
        },
        machine::{machine_id::try_parse_machine_id, ManagedHostStateSnapshot},
        metadata::Metadata,
        tenant::TenantOrganizationId,
        ConfigValidationError,
    },
    CarbideError, CarbideResult,
};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::{instance::InstanceId, instance_type::InstanceTypeId, machine::MachineId};

/// User parameters for creating an instance
#[derive(Debug)]
pub struct InstanceAllocationRequest {
    /// The Machine on top of which we create an Instance
    pub machine_id: MachineId,

    /// The expected InstanceTypeId of the source
    /// machine for the instance.
    pub instance_type_id: Option<InstanceTypeId>,

    /// Desired ID for the new instance
    pub instance_id: InstanceId,

    /// Desired configuration of the instance
    pub config: InstanceConfig,

    pub metadata: Metadata,
}

impl TryFrom<rpc::InstanceAllocationRequest> for InstanceAllocationRequest {
    type Error = CarbideError;

    fn try_from(request: rpc::InstanceAllocationRequest) -> Result<Self, Self::Error> {
        let machine_id = try_parse_machine_id(
            &request
                .machine_id
                .ok_or(RpcDataConversionError::MissingArgument("machine_id"))?,
        )?;

        let instance_type_id = request
            .instance_type_id
            .map(|i| i.parse::<InstanceTypeId>())
            .transpose()
            .map_err(|e| {
                CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.to_string()))
            })?;

        let config = request
            .config
            .ok_or(RpcDataConversionError::MissingArgument("config"))?;

        let config = InstanceConfig::try_from(config)?;

        // If the Tenant provides an instance ID use this one
        // Otherwise create a random ID
        let instance_id = match request.instance_id {
            Some(id) => id.try_into()?,
            None => InstanceId::from(uuid::Uuid::new_v4()),
        };

        let metadata = match request.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::default(),
        };

        Ok(InstanceAllocationRequest {
            instance_id,
            instance_type_id,
            machine_id,
            config,
            metadata,
        })
    }
}

/// Allocate network segment and update network segment id with it.
pub async fn allocate_network(
    network_config: &mut InstanceNetworkConfig,
    txn: &mut sqlx::Transaction<'_, Postgres>,
    api: &Api,
) -> CarbideResult<()> {
    // Take ROW LEVEL lock on all the vpc_prefix taken.
    // This is needed so that last_used_prefix is not modified by multiple clients at same time.
    // Keep values in mut Hashmap and update last_used_prefix in the end of this function.
    // Also Validate:
    // 1. All vpc_prefix_ids should point to same vpc.
    // 2. Pointed vpc'organization id must be same as instance's tenant_org.
    // 3. If no vpc_prefix_id is mentioned, return.

    let vpc_prefix_ids: Vec<VpcPrefixId> = network_config
        .interfaces
        .iter()
        .filter_map(|x| {
            if let Some(NetworkDetails::VpcPrefixId(id)) = x.network_details {
                Some(id.into())
            } else {
                None
            }
        })
        .collect_vec();

    if vpc_prefix_ids.is_empty() {
        return Ok(());
    }

    let mut vpc_prefixes: HashMap<VpcPrefixId, VpcPrefix> =
        VpcPrefix::get_by_id_with_row_lock(txn, &vpc_prefix_ids)
            .await
            .map_err(CarbideError::from)?
            .iter()
            .map(|x| (x.id, x.clone()))
            .collect::<HashMap<VpcPrefixId, VpcPrefix>>();

    // This can be empty also if vpc_prefix_id is not configured at carbide.
    // In this case error 'Unknown VPC prefix id' will be thrown.
    if vpc_prefixes
        .values()
        .map(|x| x.vpc_id)
        .collect::<HashSet<_>>()
        .len()
        > 1
    {
        return Err(CarbideError::internal(format!(
            "Interface config contains interfaces from multiple vpcs {:?}.",
            vpc_prefixes
                .values()
                .map(|x| (x.id, x.vpc_id))
                .collect_vec()
        )));
    };

    // get all used prefixes under this vpc_prefix.
    for interface in &mut network_config.interfaces {
        if let Some(network_details) = &mut interface.network_details {
            match network_details {
                NetworkDetails::NetworkSegment(_) => {}
                NetworkDetails::VpcPrefixId(vpc_prefix_id) => {
                    let vpc_prefix_id = &VpcPrefixId::from(*vpc_prefix_id);
                    let (vpc_id, vpc_prefix, last_used_prefix) = {
                        if let Some(vpc) = vpc_prefixes.get(vpc_prefix_id) {
                            let prefix = match vpc.prefix {
                                ipnetwork::IpNetwork::V4(ipv4_network) => ipv4_network,
                                ipnetwork::IpNetwork::V6(_) => {
                                    return Err(CarbideError::internal(format!(
                                        "IPv6 prefix: {} with prefix id {} is not supported.",
                                        vpc.prefix, vpc_prefix_id
                                    )));
                                }
                            };

                            let last_used_prefix = if let Some(x) = vpc.last_used_prefix {
                                match x {
                                    ipnetwork::IpNetwork::V4(ipv4_network) => Some(ipv4_network),
                                    ipnetwork::IpNetwork::V6(_) => {
                                        return Err(CarbideError::internal(format!(
                                            "IPv6 prefix: {} with prefix id {} is not supported.",
                                            vpc.prefix, vpc_prefix_id
                                        )));
                                    }
                                }
                            } else {
                                None
                            };

                            (vpc.vpc_id, prefix, last_used_prefix)
                        } else {
                            return Err(CarbideError::internal(format!(
                                "Unknown VPC prefix id: {}",
                                vpc_prefix_id
                            )));
                        }
                    };

                    let (ns_id, prefix) =
                        Ipv4PrefixAllocator::new(*vpc_prefix_id, vpc_prefix, last_used_prefix, 31)
                            .allocate_network_segment(txn, api, vpc_id)
                            .await?;
                    interface.network_segment_id = Some(ns_id);
                    vpc_prefixes.entry(*vpc_prefix_id).and_modify(|x| {
                        x.last_used_prefix = Some(IpNetwork::V4(prefix));
                    });
                }
            }
        }
    }

    // Update last used prefixes here.
    for vpc_prefix in vpc_prefixes.values() {
        let Some(last_used_prefix) = vpc_prefix.last_used_prefix else {
            continue;
        };
        VpcPrefix::update_last_used_prefix(txn, &vpc_prefix.id, last_used_prefix)
            .await
            .map_err(CarbideError::from)?;
    }

    Ok(())
}

/// Allocates an instance for a tenant
pub async fn allocate_instance(
    mut request: InstanceAllocationRequest,
    database: &PgPool,
    hardware_health_reports: HardwareHealthReportsConfig,
    api: &Api,
) -> Result<ManagedHostStateSnapshot, CarbideError> {
    let mut txn = database
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin allocate_instance", e))?;

    // Grab a row-level lock on the requested machine
    let machines = Machine::find(
        &mut txn,
        ObjectFilter::List(&[request.machine_id.clone()]),
        MachineSearchConfig {
            for_update: true,
            ..MachineSearchConfig::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;

    if machines.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "Machine",
            id: request.machine_id.to_string(),
        });
    };

    // Allocate network segment here before validate if vpc_prefix_id is mentioned.
    allocate_network(&mut request.config.network, &mut txn, api).await?;

    // Validate the configuration for the instance
    // Note that this basic validation can not cross-check references
    // like `machine_id` or any `network_segments`.
    request.config.validate()?;

    let network_config_version = ConfigVersion::initial();
    let ib_config_version = ConfigVersion::initial();
    let storage_config_version = ConfigVersion::initial();
    let config_version = ConfigVersion::initial();

    tenant_consistent_check(
        &mut txn,
        &request.config.tenant.tenant_organization_id,
        &request.config.infiniband,
    )
    .await?;

    request.metadata.validate(true)?;

    let new_instance = NewInstance {
        instance_id: request.instance_id,
        instance_type_id: request.instance_type_id,
        machine_id: request.machine_id,
        config: &request.config,
        metadata: request.metadata,
        config_version,
        network_config_version,
        ib_config_version,
        storage_config_version,
    };

    let machine_id = new_instance.machine_id.clone();
    if !machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(format!(
            "Machine with UUID {} is of type {} and can not be converted into an instance",
            machine_id,
            machine_id.machine_type()
        )));
    }

    let mut mh_snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions::default().with_hw_health(hardware_health_reports),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    if let Err(e) = mh_snapshot.is_usable_as_instance() {
        tracing::error!(%machine_id, "Host can not be used as instance due to reason: {}", e);
        return Err(match e {
            NotAllocatableReason::InvalidState(s) => CarbideError::InvalidArgument(format!(
            "Could not create instance on machine {} given machine state {:?}",
            machine_id,
            s
        )),
            NotAllocatableReason::PendingInstanceCreation => CarbideError::InvalidArgument(format!(
            "Could not create instance on machine {}. Machine is already used by another Instance creation request.",
            machine_id,
        )),
            NotAllocatableReason::NoDpuSnapshots => CarbideError::internal(format!(
                "Machine {machine_id} has no DPU. Cannot allocate."
            )),
            NotAllocatableReason::MaintenanceMode  => CarbideError::MaintenanceMode,
            NotAllocatableReason::HealthAlert(_) => CarbideError::UnhealthyHost,
        });
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

    let updated_network_config = request
        .config
        .network
        .clone()
        // Add any host-inband network segments to the network config. This allows tenants to omit
        // explicit interface config for HostInband networks, because those NICs cannot be
        // configured through carbide in the first place.
        .with_inband_interfaces_from_machine(&mut txn, &mh_snapshot.host_snapshot.machine_id)
        .await?
        // Allocate IPs and add them to the network config
        .with_allocated_ips(&mut txn, instance.id, &mh_snapshot.host_snapshot)
        .await?;

    if updated_network_config.interfaces.is_empty() {
        return Err(CarbideError::InvalidConfiguration(
            ConfigValidationError::InvalidValue(
                "InstanceNetworkConfig.interfaces is empty".to_string(),
            ),
        ));
    }

    // Persist the updated `InstanceNetworkConfig`
    // We need to retain version 1
    Instance::update_network_config(
        &mut txn,
        instance.id,
        network_config_version,
        &updated_network_config,
        false,
    )
    .await?;

    // Allocate GUID for infiniband interfaces/ports.
    let updated_ib_config = ib_partition::allocate_port_guid(
        &mut txn,
        instance.id,
        &request.config.infiniband,
        &mh_snapshot.host_snapshot,
    )
    .await?;

    // Persist the GUID for Infiniband configuration.
    // We need to retain version 1.
    Instance::update_ib_config(
        &mut txn,
        instance.id,
        ib_config_version,
        &updated_ib_config,
        false,
    )
    .await?;

    Instance::update_storage_config(
        &mut txn,
        instance.id.into(),
        storage_config_version,
        &request.config.storage,
        false,
    )
    .await?;

    // Machine will be rebooted once managed resource creation is successful.
    mh_snapshot.instance = Some(
        Instance::find_by_machine_id(&mut txn, &machine_id)
            .await?
            .ok_or_else(|| {
                CarbideError::internal(format!(
                    "Newly created instance for {machine_id} was not found"
                ))
            })?,
    );

    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit allocate_instance", e))?;

    Ok(mh_snapshot)
}

pub async fn circuit_id_to_function_id(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    network_config: &InstanceNetworkConfig,
    circuit_id: String,
) -> CarbideResult<InterfaceFunctionId> {
    let segment = NetworkSegment::find_by_circuit_id(&mut *txn, &circuit_id).await?;

    network_config
        .interfaces
        .iter()
        .find_map(|x| {
            if let Some(network_segment_id) = x.network_segment_id {
                if network_segment_id == segment.id {
                    Some(x.function_id.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or(DhcpError::InvalidCircuitId(instance_id, circuit_id))
        .map_err(CarbideError::from)
}

/// check whether the tenant of instance is consistent with the tenant of the ib partition
pub async fn tenant_consistent_check(
    txn: &mut Transaction<'_, Postgres>,
    instance_tenant: &TenantOrganizationId,
    ib_config: &InstanceInfinibandConfig,
) -> CarbideResult<()> {
    for ib_instance_config in ib_config.ib_interfaces.iter() {
        let ib_partitions = IBPartition::find_by(
            txn,
            ObjectColumnFilter::One(ib_partition::IdColumn, &ib_instance_config.ib_partition_id),
            IBPartitionSearchConfig::default(),
        )
        .await?;
        let ib_partition = ib_partitions
            .first()
            .ok_or(ConfigValidationError::invalid_value(format!(
                "IB partition {} is not created",
                ib_instance_config.ib_partition_id
            )))?;

        if ib_partition.config.tenant_organization_id != *instance_tenant {
            return Err(CarbideError::InvalidArgument(format!(
                "The tenant {} of instance inconsistent with the tenant {} of ib partition",
                instance_tenant, ib_partition.config.tenant_organization_id
            )));
        }
    }
    Ok(())
}
