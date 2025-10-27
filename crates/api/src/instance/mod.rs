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

use ::rpc::errors::RpcDataConversionError;
use config_version::ConfigVersion;
use db::ib_partition::{self, IBPartitionSearchConfig};
use db::{self, ObjectColumnFilter, ObjectFilter, dpa_interface, network_security_group};
use forge_uuid::instance::InstanceId;
use forge_uuid::instance_type::InstanceTypeId;
use forge_uuid::machine::MachineId;
use forge_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::ConfigValidationError;
use model::hardware_info::InfinibandInterface;
use model::instance::NewInstance;
use model::instance::config::InstanceConfig;
use model::instance::config::infiniband::InstanceInfinibandConfig;
use model::instance::config::network::{
    InstanceNetworkConfig, InterfaceFunctionId, NetworkDetails,
};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    HostHealthConfig, LoadSnapshotOptions, Machine, ManagedHostStateSnapshot, NotAllocatableReason,
};
use model::metadata::Metadata;
use model::os::OperatingSystemVariant;
use model::tenant::TenantOrganizationId;
use model::vpc_prefix::VpcPrefix;
use sqlx::PgConnection;

use crate::api::Api;
use crate::network_segment::allocate::Ipv4PrefixAllocator;
use crate::{CarbideError, CarbideResult};

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
        let machine_id = request
            .machine_id
            .ok_or(RpcDataConversionError::MissingArgument("machine_id"))?;

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
        let instance_id = request
            .instance_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().into());

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

pub async fn allocate_dpa_vni(
    api: &Api,
    network_config: &InstanceNetworkConfig,
    txn: &mut PgConnection,
) -> CarbideResult<()> {
    let Some(network_segment_id) = network_config.interfaces[0].network_segment_id else {
        // Network segment allocation is done before persisting record in db. So if still
        // network segment is empty, return error.
        return Err(CarbideError::InvalidArgument(
            "Expected Network Segment".to_string(),
        ));
    };

    let vpc = db::vpc::find_by_segment(txn, network_segment_id)
        .await
        .map_err(CarbideError::from)?;

    db::vpc::allocate_dpa_vni(txn, vpc, &api.common_pools.dpa.pool_dpa_vni).await?;

    Ok(())
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
                Some(id)
            } else {
                None
            }
        })
        .collect_vec();

    if vpc_prefix_ids.is_empty() {
        return Ok(());
    }

    let mut vpc_prefixes: HashMap<VpcPrefixId, VpcPrefix> =
        db::vpc_prefix::get_by_id_with_row_lock(txn, &vpc_prefix_ids)
            .await?
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
                                "Unknown VPC prefix id: {vpc_prefix_id}"
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
        db::vpc_prefix::update_last_used_prefix(txn, &vpc_prefix.id, last_used_prefix).await?;
    }

    Ok(())
}

pub async fn allocate_ib_port_guid(
    ib_config: &InstanceInfinibandConfig,
    machine: &Machine,
) -> CarbideResult<InstanceInfinibandConfig> {
    let mut updated_ib_config = ib_config.clone();

    let ib_hw_info = machine
        .hardware_info
        .as_ref()
        .ok_or(CarbideError::MissingArgument("no hardware info"))?
        .infiniband_interfaces
        .as_ref();

    // the key of ib_hw_map is device name such as "MT28908 Family [ConnectX-6]".
    // the value of ib_hw_map is a sorted vector of InfinibandInterface by slot.
    let ib_hw_map = sort_ib_by_slot(ib_hw_info);

    let mut guids: Vec<String> = Vec::new();
    for request in &mut updated_ib_config.ib_interfaces {
        tracing::debug!(
            "request IB device:{}, device_instance:{}",
            request.device.clone(),
            request.device_instance
        );

        // TOTO: will support VF in the future. Currently, it will return err when the function_id is not PF.
        if let InterfaceFunctionId::Virtual { .. } = request.function_id {
            return Err(CarbideError::InvalidArgument(format!(
                "Not support VF {}",
                request.device
            )));
        }

        if let Some(sorted_ibs) = ib_hw_map.get(&request.device) {
            if let Some(ib) = sorted_ibs.get(request.device_instance as usize) {
                request.pf_guid = Some(ib.guid.clone());
                request.guid = Some(ib.guid.clone());
                guids.push(ib.guid.clone());
                tracing::debug!("select IB device GUID {}", ib.guid.clone());
            } else {
                return Err(CarbideError::InvalidArgument(format!(
                    "not enough ib device {}",
                    request.device
                )));
            }
        } else {
            return Err(CarbideError::InvalidArgument(format!(
                "no ib device {}",
                request.device
            )));
        }
    }

    // Do additional ib ports verification
    if !guids.is_empty() {
        if let Some(ib_interfaces_status) = &machine.infiniband_status_observation {
            for guid in guids.iter() {
                for ib_status in ib_interfaces_status.ib_interfaces.iter() {
                    if *guid == ib_status.guid && ib_status.lid == 0xffff_u16 {
                        return Err(CarbideError::InvalidArgument(format!(
                            "UFM detected inactive state for GUID: {guid}"
                        )));
                    }
                }
            }
        } else {
            return Err(CarbideError::InvalidArgument(
                "Infiniband status information is not found".to_string(),
            ));
        }
    }

    Ok(updated_ib_config)
}

/// sort ib device by slot and add devices with the same name are added to hashmap
pub fn sort_ib_by_slot(
    ib_hw_info_vec: &[InfinibandInterface],
) -> HashMap<String, Vec<InfinibandInterface>> {
    let mut ib_hw_map = HashMap::new();
    let mut sorted_ib_hw_info_vec = ib_hw_info_vec.to_owned();
    sorted_ib_hw_info_vec.sort_by_key(|x| match &x.pci_properties {
        Some(pci_properties) => pci_properties.slot.clone().unwrap_or_default(),
        None => "".to_owned(),
    });

    for ib in sorted_ib_hw_info_vec {
        if let Some(ref pci_properties) = ib.pci_properties {
            // description in pci_properties are the value of ID_MODEL_FROM_DATABASE, such as "MT28908 Family [ConnectX-6]"
            if let Some(device) = &pci_properties.description {
                let entry: &mut Vec<InfinibandInterface> =
                    ib_hw_map.entry(device.clone()).or_default();
                entry.push(ib);
            }
        }
    }

    ib_hw_map
}

/// Allocates an instance for a tenant
pub async fn allocate_instance(
    api: &Api,
    mut request: InstanceAllocationRequest,
    host_health_config: HostHealthConfig,
) -> Result<ManagedHostStateSnapshot, CarbideError> {
    let mut txn = api.txn_begin("allocate_instance").await?;

    // Grab a row-level lock on the requested machine
    let machines = db::machine::find(
        &mut txn,
        ObjectFilter::List(&[request.machine_id]),
        MachineSearchConfig {
            for_update: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;

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
            std::slice::from_ref(nsg_id),
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
        if let Err(e) = db::os_image::get(&mut txn, os_image_id).await {
            return if e.is_not_found() {
                Err(CarbideError::FailedPrecondition(format!(
                    "Image OS `{}` does not exist",
                    os_image_id.clone()
                )))
            } else {
                Err(CarbideError::internal(format!(
                    "Failed to get OS image error: {e}"
                )))
            };
        }
    }

    if api.runtime_config.is_dpa_enabled()
        && dpa_interface::is_machine_dpa_capable(&mut txn, request.machine_id).await?
    {
        allocate_dpa_vni(api, &request.config.network, &mut txn).await?;
    }

    // Allocate network segment here before validate if vpc_prefix_id is mentioned.
    allocate_network(&mut request.config.network, &mut txn).await?;

    // Validate the configuration for the instance
    // Note that this basic validation can not cross-check references
    // like `machine_id` or any `network_segments`.
    request.config.validate(
        true,
        api.runtime_config
            .vmaas_config
            .as_ref()
            .map(|vc| vc.allow_instance_vf)
            .unwrap_or(true),
    )?;

    let network_config_version = ConfigVersion::initial();
    let ib_config_version = ConfigVersion::initial();
    let storage_config_version = ConfigVersion::initial();
    let config_version = ConfigVersion::initial();

    validate_ib_partition_ownership(
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
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    if let Err(e) = mh_snapshot.is_usable_as_instance(request.allow_unhealthy_machine) {
        tracing::error!(%machine_id, "Host can not be used as instance due to reason: {}", e);
        return Err(match e {
            NotAllocatableReason::InvalidState(s) => CarbideError::InvalidArgument(format!(
                "Could not create instance on machine {machine_id} given machine state {s:?}"
            )),
            NotAllocatableReason::PendingInstanceCreation => {
                CarbideError::InvalidArgument(format!(
                    "Could not create instance on machine {machine_id}. Machine is already used by another Instance creation request.",
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
    let instance = db::instance::persist(new_instance, &mut txn).await?;
    // TODO: Should we check that the network segment actually belongs to the
    // tenant?

    // Add any host-inband network segments to the network config. This allows tenants to omit
    // explicit interface config for HostInband networks, because those NICs cannot be
    // configured through carbide in the first place.
    let updated_network_config = db::instance_network_config::with_inband_interfaces_from_machine(
        request.config.network,
        &mut txn,
        &mh_snapshot.host_snapshot.id,
    )
    .await?;

    // Allocate IPs and add them to the network config
    let updated_network_config = db::instance_network_config::with_allocated_ips(
        updated_network_config,
        &mut txn,
        instance.id,
        &mh_snapshot.host_snapshot,
    )
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
    db::instance::update_network_config(
        &mut txn,
        instance.id,
        network_config_version,
        &updated_network_config,
        false,
    )
    .await?;

    // Allocate GUID for infiniband interfaces/ports.
    let updated_ib_config =
        allocate_ib_port_guid(&request.config.infiniband, &mh_snapshot.host_snapshot).await?;

    // Persist the GUID for Infiniband configuration.
    // We need to retain version 1.
    db::instance::update_ib_config(
        &mut txn,
        instance.id,
        ib_config_version,
        &updated_ib_config,
        false,
    )
    .await?;

    db::instance::update_storage_config(
        &mut txn,
        instance.id.into(),
        storage_config_version,
        &request.config.storage,
        false,
    )
    .await?;

    // Machine will be rebooted once managed resource creation is successful.
    mh_snapshot.instance = Some(
        db::instance::find_by_machine_id(&mut txn, &machine_id)
            .await?
            .ok_or_else(|| {
                CarbideError::internal(format!(
                    "Newly created instance for {machine_id} was not found"
                ))
            })?,
    );

    txn.commit().await?;

    Ok(mh_snapshot)
}

/// check whether the tenant of instance is consistent with the tenant of the ib partition
pub async fn validate_ib_partition_ownership(
    txn: &mut PgConnection,
    instance_tenant: &TenantOrganizationId,
    ib_config: &InstanceInfinibandConfig,
) -> CarbideResult<()> {
    let partition_ids: HashSet<_> = ib_config
        .ib_interfaces
        .iter()
        .map(|iface| iface.ib_partition_id)
        .collect();

    for partition_id in partition_ids.iter() {
        let ib_partitions = db::ib_partition::find_by(
            txn,
            ObjectColumnFilter::One(ib_partition::IdColumn, partition_id),
            IBPartitionSearchConfig::default(),
        )
        .await?;
        let ib_partition = ib_partitions
            .first()
            .ok_or(ConfigValidationError::invalid_value(format!(
                "IB partition {partition_id} is not created"
            )))?;

        if ib_partition.config.tenant_organization_id != *instance_tenant {
            return Err(CarbideError::InvalidArgument(format!(
                "IB Partition {partition_id} is not owned by the tenant {instance_tenant}",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn test_sort_ib_by_slot() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../api-model/src/hardware_info/test_data/x86_info.json"
    ));

    let hw_info = serde_json::from_slice::<model::hardware_info::HardwareInfo>(data).unwrap();
    assert!(!hw_info.infiniband_interfaces.is_empty());

    let prev = sort_ib_by_slot(hw_info.infiniband_interfaces.as_ref());
    for _ in 0..10 {
        let cur = sort_ib_by_slot(hw_info.infiniband_interfaces.as_ref());
        for (key, value) in cur.into_iter() {
            assert_eq!(*prev.get(&key).unwrap(), value);
        }
    }
}
