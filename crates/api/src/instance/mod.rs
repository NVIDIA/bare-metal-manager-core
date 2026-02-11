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

use std::collections::{HashMap, HashSet};

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::vpc::VpcPrefixId;
use config_version::ConfigVersion;
use db::{
    self, ObjectColumnFilter, ObjectFilter, dpa_interface, extension_service, ib_partition,
    network_security_group,
};
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

    let vpc = db::vpc::find_by_segment(&mut *txn, network_segment_id)
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
                            let prefix = match vpc.config.prefix {
                                ipnetwork::IpNetwork::V4(ipv4_network) => ipv4_network,
                                ipnetwork::IpNetwork::V6(_) => {
                                    return Err(CarbideError::internal(format!(
                                        "IPv6 prefix: {} with prefix id {} is not supported.",
                                        vpc.config.prefix, vpc_prefix_id
                                    )));
                                }
                            };

                            let last_used_prefix = if let Some(x) = vpc.status.last_used_prefix {
                                match x {
                                    ipnetwork::IpNetwork::V4(ipv4_network) => Some(ipv4_network),
                                    ipnetwork::IpNetwork::V6(_) => {
                                        return Err(CarbideError::internal(format!(
                                            "IPv6 prefix: {} with prefix id {} is not supported.",
                                            vpc.config.prefix, vpc_prefix_id
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
                        x.status.last_used_prefix = Some(IpNetwork::V4(prefix));
                    });
                }
            }
        }
    }

    // Update last used prefixes here.
    for vpc_prefix in vpc_prefixes.values() {
        let Some(last_used_prefix) = vpc_prefix.status.last_used_prefix else {
            continue;
        };
        db::vpc_prefix::update_last_used_prefix(txn, &vpc_prefix.id, last_used_prefix).await?;
    }

    Ok(())
}

pub fn allocate_ib_port_guid(
    ib_config: &InstanceInfinibandConfig,
    machine: &Machine,
) -> CarbideResult<InstanceInfinibandConfig> {
    let mut updated_ib_config = ib_config.clone();

    let ib_hw_info = machine
        .hardware_info
        .as_ref()
        .ok_or(CarbideError::MissingArgument("no hardware info in machine"))?
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
                "Not support VF {} (machine {})",
                request.device, machine.id
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
                    "not enough ib device {} (machine {})",
                    request.device, machine.id
                )));
            }
        } else {
            return Err(CarbideError::InvalidArgument(format!(
                "no ib device {} (machine {})",
                request.device, machine.id
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
                            "UFM detected inactive state for GUID: {guid} (machine {})",
                            machine.id
                        )));
                    }
                }
            }
        } else {
            return Err(CarbideError::InvalidArgument(format!(
                "Infiniband status information is not found (machine {})",
                machine.id
            )));
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
/// This is a convenience wrapper around `batch_allocate_instances` for single instance allocation.
pub async fn allocate_instance(
    api: &Api,
    request: InstanceAllocationRequest,
    host_health_config: HostHealthConfig,
) -> Result<ManagedHostStateSnapshot, CarbideError> {
    let mut results = batch_allocate_instances(api, vec![request], host_health_config).await?;

    results
        .pop()
        .ok_or_else(|| CarbideError::internal("Instance allocation returned no result".to_string()))
}

/// Allocates multiple instances in a single transaction.
/// Rolls back entirely if any allocation fails.
///
/// ## Flow:
/// 1. Validate machine types and metadata (in-memory)
/// 2. Batch query machines (FOR UPDATE), load snapshots, validate usability
/// 3. Validate shared resources: NSG, extension services, OS images, IB partitions, DPA
/// 4. Network allocation + config validation (sequential)
/// 5. Batch persist instances, process configs (IPs, IB GUIDs), batch update
/// 6. Load final instances, assemble snapshots, commit
pub async fn batch_allocate_instances(
    api: &Api,
    requests: Vec<InstanceAllocationRequest>,
    host_health_config: HostHealthConfig,
) -> Result<Vec<ManagedHostStateSnapshot>, CarbideError> {
    if requests.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "Batch request must contain at least one instance".to_string(),
        ));
    }

    let request_count = requests.len();
    tracing::info!(
        instance_count = request_count,
        "Starting batch instance allocation"
    );

    // ==== Phase 1: Validate request parameters (in-memory validation) ====
    for request in &requests {
        // Validate machine type
        if !request.machine_id.machine_type().is_host() {
            return Err(CarbideError::InvalidArgument(format!(
                "Machine with UUID {} is of type {} and can not be converted into an instance",
                request.machine_id,
                request.machine_id.machine_type()
            )));
        }

        // Validate metadata (config validated after network allocation)
        request.metadata.validate(true)?;
    }

    // Start a single transaction for all allocations
    let mut txn = api.txn_begin().await?;

    // ==== Phase 2: Batch query machines (FOR UPDATE) ====
    let machine_ids: Vec<_> = requests.iter().map(|r| r.machine_id).collect();

    let machines = db::machine::find(
        &mut txn,
        ObjectFilter::List(&machine_ids),
        MachineSearchConfig {
            for_update: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;

    // Create a map for quick lookup
    let machine_map: std::collections::HashMap<_, _> =
        machines.into_iter().map(|m| (m.id, m)).collect();

    // Verify all machines were found
    for request in &requests {
        if !machine_map.contains_key(&request.machine_id) {
            return Err(CarbideError::NotFoundError {
                kind: "Machine",
                id: request.machine_id.to_string(),
            });
        }
    }

    // ==== Phase 3: Batch load managed host snapshots ====
    let mut snapshot_map = db::managed_host::load_by_machine_ids(
        &mut txn,
        &machine_ids,
        LoadSnapshotOptions::default().with_host_health(host_health_config),
    )
    .await?;

    // Verify all snapshots were loaded and validate usability
    for request in &requests {
        let machine_id = request.machine_id;
        let mh_snapshot = snapshot_map
            .get(&machine_id)
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
                NotAllocatableReason::NoDpuSnapshots => CarbideError::internal(format!(
                    "Machine {machine_id} has no DPU. Cannot allocate."
                )),
                NotAllocatableReason::MaintenanceMode => CarbideError::MaintenanceMode,
                NotAllocatableReason::HealthAlert(_) => CarbideError::UnhealthyHost,
            });
        }
    }

    // ==== Phase 4: Validate shared resources ====

    // Collect all unique NSG IDs with their tenant org IDs for validation
    let nsg_validations: HashSet<_> = requests
        .iter()
        .filter_map(|r| {
            r.config
                .network_security_group_id
                .as_ref()
                .map(|nsg_id| (nsg_id, &r.config.tenant.tenant_organization_id))
        })
        .collect();

    // Validate each unique NSG
    for (nsg_id, tenant_org_id) in &nsg_validations {
        if network_security_group::find_by_ids(
            &mut txn,
            std::slice::from_ref(nsg_id),
            Some(tenant_org_id),
            true,
        )
        .await?
        .pop()
        .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                nsg_id, tenant_org_id
            )));
        }
    }

    // Collect all unique extension service configs for validation
    let all_service_configs: Vec<_> = requests
        .iter()
        .flat_map(|r| r.config.extension_services.service_configs.iter())
        .collect();

    if !all_service_configs.is_empty() {
        // Validate no duplicate service IDs within each request
        for request in &requests {
            let service_ids: Vec<_> = request
                .config
                .extension_services
                .service_configs
                .iter()
                .map(|s| s.service_id)
                .collect();
            let unique_service_ids: HashSet<_> = service_ids.iter().collect();
            if service_ids.len() != unique_service_ids.len() {
                return Err(CarbideError::InvalidArgument(format!(
                    "Duplicate extension services in configuration. Only one version of each service is allowed. (machine {})",
                    request.machine_id
                )));
            }
        }

        // Collect all unique service IDs across all requests
        let unique_service_ids: Vec<_> = all_service_configs
            .iter()
            .map(|s| s.service_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Batch query all extension services
        let services =
            extension_service::find_versions_by_service_ids(&mut txn, &unique_service_ids, true)
                .await?;

        // Validate each service config
        for service in all_service_configs {
            if !services.contains_key(&service.service_id) {
                return Err(CarbideError::FailedPrecondition(format!(
                    "Extension service {} does not exist",
                    service.service_id,
                )));
            }
            if !services
                .get(&service.service_id)
                .unwrap()
                .contains(&service.version)
            {
                return Err(CarbideError::FailedPrecondition(format!(
                    "Extension service {} version {} does not exist or is deleted",
                    service.service_id, service.version,
                )));
            }
        }
    }

    // Collect all unique OS image IDs for validation
    let os_image_ids: HashSet<_> = requests
        .iter()
        .filter_map(|r| {
            if let OperatingSystemVariant::OsImage(os_image_id) = r.config.os.variant {
                Some(os_image_id)
            } else {
                None
            }
        })
        .collect();

    // Validate each unique OS image
    for os_image_id in &os_image_ids {
        if os_image_id.is_nil() {
            return Err(CarbideError::InvalidArgument(
                "Image ID is required for image based storage".to_string(),
            ));
        }
        if let Err(e) = db::os_image::get(&mut txn, *os_image_id).await {
            return if e.is_not_found() {
                Err(CarbideError::FailedPrecondition(format!(
                    "Image OS `{}` does not exist",
                    os_image_id
                )))
            } else {
                Err(CarbideError::internal(format!(
                    "Failed to get OS image error: {e}"
                )))
            };
        }
    }

    // Validate IB partition ownership for all requests
    let ib_partition_validations: Vec<_> = requests
        .iter()
        .flat_map(|r| {
            r.config.infiniband.ib_interfaces.iter().map(|iface| {
                (
                    iface.ib_partition_id,
                    &r.config.tenant.tenant_organization_id,
                )
            })
        })
        .collect();

    batch_validate_ib_partition_ownership(&mut txn, &ib_partition_validations).await?;

    // Batch check which machines are DPA capable (if DPA is enabled)
    let dpa_capable_machines: HashSet<MachineId> = if api.runtime_config.is_dpa_enabled() {
        dpa_interface::batch_is_machine_dpa_capable(&mut txn, &machine_ids).await?
    } else {
        HashSet::new()
    };

    // Batch query inband segments for all machines
    let inband_segments_map =
        db::instance_network_config::batch_get_inband_segments_by_machine_ids(
            &mut txn,
            &machine_ids,
        )
        .await?;

    // ==== Phase 5: Network allocation (sequential due to vpc_prefix tracking) ====
    let mut processed_requests: Vec<(InstanceAllocationRequest, ManagedHostStateSnapshot)> =
        Vec::with_capacity(request_count);

    for mut request in requests {
        let machine_id = request.machine_id;
        let mh_snapshot = snapshot_map
            .remove(&machine_id)
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

        // Allocate DPA VNI if needed
        if dpa_capable_machines.contains(&machine_id) {
            allocate_dpa_vni(api, &request.config.network, &mut txn).await?;
        }

        // Allocate network
        allocate_network(&mut request.config.network, &mut txn).await?;

        // Validate config (after network allocation sets network_segment_id)
        request.config.validate(
            true,
            api.runtime_config
                .vmaas_config
                .as_ref()
                .map(|vc| vc.allow_instance_vf)
                .unwrap_or(true),
        )?;

        processed_requests.push((request, mh_snapshot));
    }

    // ==== Phase 6: Batch persist instances ====
    let network_config_version = ConfigVersion::initial();
    let ib_config_version = ConfigVersion::initial();
    let extension_services_config_version = ConfigVersion::initial();
    let config_version = ConfigVersion::initial();
    let nvl_config_version = ConfigVersion::initial();

    let new_instances: Vec<NewInstance<'_>> = processed_requests
        .iter()
        .map(|(request, _)| NewInstance {
            instance_id: request.instance_id,
            instance_type_id: request.instance_type_id.clone(),
            machine_id: request.machine_id,
            config: &request.config,
            metadata: request.metadata.clone(),
            config_version,
            network_config_version,
            ib_config_version,
            extension_services_config_version,
            nvlink_config_version: nvl_config_version,
        })
        .collect();

    let _persisted_instances = db::instance::batch_persist(new_instances, &mut txn).await?;

    // ==== Phase 7: Process configs (IPs, inband interfaces, IB GUIDs) ====
    // These need to be done per-instance but we collect results for batch update
    // Tuple format: (instance_id, expected_version, config)
    let mut network_config_updates: Vec<(
        carbide_uuid::instance::InstanceId,
        ConfigVersion,
        model::instance::config::network::InstanceNetworkConfig,
    )> = Vec::with_capacity(request_count);
    let mut ib_config_updates: Vec<(
        carbide_uuid::instance::InstanceId,
        ConfigVersion,
        model::instance::config::infiniband::InstanceInfinibandConfig,
    )> = Vec::with_capacity(request_count);
    let mut nvlink_config_updates: Vec<(
        carbide_uuid::instance::InstanceId,
        ConfigVersion,
        model::instance::config::nvlink::InstanceNvLinkConfig,
    )> = Vec::with_capacity(request_count);

    for (request, mh_snapshot) in &processed_requests {
        let instance_id = request.instance_id;

        // Add host-inband network segments (using pre-queried batch data)
        let inband_segment_ids = inband_segments_map
            .get(&mh_snapshot.host_snapshot.id)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let updated_network_config = db::instance_network_config::add_inband_interfaces_to_config(
            request.config.network.clone(),
            inband_segment_ids,
        );

        // Allocate IPs
        let updated_network_config = db::instance_network_config::with_allocated_ips(
            updated_network_config,
            &mut txn,
            instance_id,
            &mh_snapshot.host_snapshot,
        )
        .await?;

        if updated_network_config.interfaces.is_empty() {
            return Err(CarbideError::InvalidConfiguration(
                ConfigValidationError::InvalidValue(format!(
                    "InstanceNetworkConfig.interfaces is empty (machine {})",
                    request.machine_id
                )),
            ));
        }

        network_config_updates.push((instance_id, network_config_version, updated_network_config));

        // Allocate IB GUID
        let updated_ib_config =
            allocate_ib_port_guid(&request.config.infiniband, &mh_snapshot.host_snapshot)?;
        ib_config_updates.push((instance_id, ib_config_version, updated_ib_config));

        // NVLink config
        nvlink_config_updates.push((
            instance_id,
            nvl_config_version,
            request.config.nvlink.clone(),
        ));
    }

    // ==== Phase 8: Batch update configs ====
    // increment_version = false: during initial creation, we don't increment
    let network_refs: Vec<_> = network_config_updates
        .iter()
        .map(|(id, ver, cfg)| (*id, *ver, cfg))
        .collect();
    db::instance::batch_update_network_config(&mut txn, &network_refs, false).await?;

    let ib_refs: Vec<_> = ib_config_updates
        .iter()
        .map(|(id, ver, cfg)| (*id, *ver, cfg))
        .collect();
    db::instance::batch_update_ib_config(&mut txn, &ib_refs, false).await?;

    let nvlink_refs: Vec<_> = nvlink_config_updates
        .iter()
        .map(|(id, ver, cfg)| (*id, *ver, cfg))
        .collect();
    db::instance::batch_update_nvlink_config(&mut txn, &nvlink_refs, false).await?;

    // ==== Phase 9: Load final instances ====
    let machine_id_refs: Vec<&MachineId> = processed_requests
        .iter()
        .map(|(r, _)| &r.machine_id)
        .collect();
    let final_instances = db::instance::find_by_machine_ids(&mut txn, &machine_id_refs).await?;
    let mut final_instance_map: HashMap<_, _> = final_instances
        .into_iter()
        .map(|i| (i.machine_id, i))
        .collect();

    // ==== Phase 10: Assemble final snapshots ====
    let mut snapshots = Vec::with_capacity(request_count);
    for (request, mut mh_snapshot) in processed_requests {
        let machine_id = request.machine_id;
        mh_snapshot.instance = Some(final_instance_map.remove(&machine_id).ok_or_else(|| {
            CarbideError::internal(format!(
                "Newly created instance for {machine_id} was not found"
            ))
        })?);
        snapshots.push(mh_snapshot);
    }

    // ==== Phase 11: Commit ====
    txn.commit().await?;

    tracing::info!(
        instance_count = snapshots.len(),
        "Successfully completed batch instance allocation"
    );

    Ok(snapshots)
}

/// Batch validate IB partition ownership for multiple (partition_id, tenant_id) pairs
pub async fn batch_validate_ib_partition_ownership(
    txn: &mut PgConnection,
    validations: &[(IBPartitionId, &TenantOrganizationId)],
) -> CarbideResult<()> {
    if validations.is_empty() {
        return Ok(());
    }

    // Batch query all unique partitions
    let unique_partition_ids: Vec<_> = validations
        .iter()
        .map(|(id, _)| *id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let partitions = db::ib_partition::find_by(
        txn,
        ObjectColumnFilter::List(ib_partition::IdColumn, &unique_partition_ids),
    )
    .await?;

    let partition_map: HashMap<_, _> = partitions.into_iter().map(|p| (p.id, p)).collect();

    // Validate each partition ownership
    for (partition_id, expected_tenant) in validations {
        let partition = partition_map.get(partition_id).ok_or_else(|| {
            ConfigValidationError::invalid_value(format!(
                "IB partition {partition_id} is not created"
            ))
        })?;

        if &partition.config.tenant_organization_id != *expected_tenant {
            return Err(CarbideError::InvalidArgument(format!(
                "IB Partition {partition_id} is not owned by the tenant {expected_tenant}",
            )));
        }
    }
    Ok(())
}

/// Check whether the tenant of instance is consistent with the tenant of the ib partition
pub async fn validate_ib_partition_ownership(
    txn: &mut PgConnection,
    instance_tenant: &TenantOrganizationId,
    ib_config: &InstanceInfinibandConfig,
) -> CarbideResult<()> {
    let validations: Vec<_> = ib_config
        .ib_interfaces
        .iter()
        .map(|iface| (iface.ib_partition_id, instance_tenant))
        .collect();
    batch_validate_ib_partition_ownership(txn, &validations).await
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
