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
use sqlx::{PgConnection, PgPool};

use crate::cfg::file::HostHealthConfig;
use crate::db::ObjectColumnFilter;
use crate::db::vpc_prefix::VpcPrefix;
use crate::model::instance::config::network::NetworkDetails;
use crate::model::machine::NotAllocatableReason;
use crate::network_segment::allocate::Ipv4PrefixAllocator;
use crate::{
    CarbideError, CarbideResult,
    db::{
        self, DatabaseError, ObjectFilter,
        ib_partition::{self, IBPartition, IBPartitionSearchConfig},
        instance::{Instance, NewInstance},
        machine::MachineSearchConfig,
        managed_host::LoadSnapshotOptions,
        network_security_group,
    },
    model::{
        ConfigValidationError,
        instance::config::{
            InstanceConfig, infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
        },
        machine::{ManagedHostStateSnapshot, machine_id::try_parse_machine_id},
        metadata::Metadata,
        os::OperatingSystemVariant,
        storage::OsImage,
        tenant::TenantOrganizationId,
    },
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

    /// Allow allocation on unhealthy machines
    pub allow_unhealthy_machine: bool,
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
                CarbideError::from(RpcDataConversionError::InvalidInstanceTypeId(e.value()))
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
            None => Metadata::new_with_default_name(),
        };

        let allow_unhealthy_machine = request.allow_unhealthy_machine;

        Ok(InstanceAllocationRequest {
            instance_id,
            instance_type_id,
            machine_id,
            config,
            metadata,
            allow_unhealthy_machine,
        })
    }
}

/// Allocate network segment and update network segment id with it.
pub async fn allocate_network(
    network_config: &mut InstanceNetworkConfig,
    txn: &mut PgConnection,
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
        // If IP address is already allocated, ignore.
        // // This is the case of updating network config (adding/removing a VF)
        if !interface.ip_addrs.is_empty() {
            continue;
        }
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
                            .allocate_network_segment(txn, vpc_id)
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
    host_health_config: HostHealthConfig,
) -> Result<ManagedHostStateSnapshot, CarbideError> {
    /*
        let network_segment_physical_interface_count = request
            .config
            .network
            .interfaces
            .iter()
            .filter(|i| {
                matches!(i.function_id, InterfaceFunctionId::Physical {})
                    // if network_details is none, it has to be a network segment
                    && (i.network_details
                        .as_ref()
                        .is_none_or(|nd| matches!(nd, NetworkDetails::NetworkSegment { .. })))
            })
            .count();
        let vpc_id_physical_interface_count = request
            .config
            .network
            .interfaces
            .iter()
            .filter(|i| {
                matches!(i.function_id, InterfaceFunctionId::Physical {})
                    && i.network_details
                        .as_ref()
                        .is_none_or(|nd| matches!(nd, NetworkDetails::VpcPrefixId { .. }))
            })
            .count();

        match (
            network_segment_physical_interface_count,
            vpc_id_physical_interface_count,
        ) {
            (1, 0) => {}
            (0, _) => {}
            _ => {
                return Err(CarbideError::InvalidArgument(
                    "Only 1 interface is allowed when using network segments".to_string(),
                ));
            }
        }
    */
    let mut txn = database
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin allocate_instance", e))?;

    // Grab a row-level lock on the requested machine
    let machines = db::machine::find(
        &mut txn,
        ObjectFilter::List(&[request.machine_id]),
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

    // If an NSG is applied, we need to do a little more validation.
    if let Some(ref nsg_id) = request.config.network_security_group_id {
        // Query to check the validity of the NSG ID but to also grab
        // a row-level lock on it if it exists.
        if network_security_group::find_by_ids(
            &mut txn,
            &[nsg_id.clone()],
            Some(&request.config.tenant.tenant_organization_id),
            true,
        )
        .await?
        .pop()
        .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                nsg_id,
                request.config.tenant.tenant_organization_id.clone()
            )));
        }
    }

    // Validate the OS image ID if it exists
    let os_config = &request.config.os;
    if let OperatingSystemVariant::OsImage(os_image_id) = os_config.variant {
        if os_image_id.is_nil() {
            return Err(CarbideError::InvalidArgument(
                "Image ID is required for image based storage".to_string(),
            ));
        }
        if let Err(e) = OsImage::get(&mut txn, os_image_id).await {
            if let sqlx::Error::RowNotFound = e.source {
                return Err(CarbideError::FailedPrecondition(format!(
                    "Image OS `{}` does not exist",
                    os_image_id.clone()
                )));
            } else {
                return Err(CarbideError::internal(format!(
                    "Failed to get OS image error: {}",
                    e
                )));
            }
        }
    }
    // Allocate network segment here before validate if vpc_prefix_id is mentioned.
    allocate_network(&mut request.config.network, &mut txn).await?;

    // Validate the configuration for the instance
    // Note that this basic validation can not cross-check references
    // like `machine_id` or any `network_segments`.
    request.config.validate(true)?;

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

    let machine_id = new_instance.machine_id;
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
        LoadSnapshotOptions::default().with_host_health(host_health_config),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    if let Err(e) = mh_snapshot.is_usable_as_instance(request.allow_unhealthy_machine) {
        tracing::error!(%machine_id, "Host can not be used as instance due to reason: {}", e);
        return Err(match e {
            NotAllocatableReason::InvalidState(s) => CarbideError::InvalidArgument(format!(
                "Could not create instance on machine {} given machine state {:?}",
                machine_id, s
            )),
            NotAllocatableReason::PendingInstanceCreation => {
                CarbideError::InvalidArgument(format!(
                    "Could not create instance on machine {}. Machine is already used by another Instance creation request.",
                    machine_id,
                ))
            }
            NotAllocatableReason::NoDpuSnapshots => {
                CarbideError::internal(format!("Machine {machine_id} has no DPU. Cannot allocate."))
            }
            NotAllocatableReason::MaintenanceMode => CarbideError::MaintenanceMode,
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
        .with_inband_interfaces_from_machine(&mut txn, &mh_snapshot.host_snapshot.id)
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

/// check whether the tenant of instance is consistent with the tenant of the ib partition
pub async fn tenant_consistent_check(
    txn: &mut PgConnection,
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
