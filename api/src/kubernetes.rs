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
use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use forge_credentials::CredentialKey;
use ipnetwork::IpNetwork;
use kube::{
    api::{Api, DeleteParams, PostParams, ResourceExt},
    Client,
};
use serde::{Deserialize, Serialize};
use sqlx::Postgres;
use uuid::Uuid;

use crate::db::constants::FORGE_KUBE_NAMESPACE;
use crate::db::dpu_machine::DpuMachine;
use crate::db::instance_address::InstanceAddress;
use crate::db::network_prefix::NetworkPrefix;
use crate::model::config_version::ConfigVersion;
use crate::model::instance::config::network::{InstanceNetworkConfig, InterfaceFunctionId};
use crate::model::machine::machine_id::MachineId;
use crate::model::machine::DPU_PHYSICAL_NETWORK_INTERFACE;
use crate::vpc_resources::{
    leaf, managed_resource, resource_group, BlueFieldInterface, VpcResource, VpcResourceStatus,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafData {
    pub leaf: leaf::Leaf,
    pub dpu_machine_id: MachineId,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateLeafData {
    pub dpu_machine_id: MachineId,
    host_admin_i_ps: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManagedResourceData {
    machine_id: MachineId,
    dpu_machine_id: MachineId,
    instance_id: uuid::Uuid,
    network_config_version: ConfigVersion,
    network_config: InstanceNetworkConfig,
    ip_details: Option<HashMap<Uuid, IpAddr>>, // NetworkSegment => IpAddr
    managed_resources: Vec<managed_resource::ManagedResource>,
}

/// Generates the kubernetes name of a Leaf CRD - based on the Forge dpu_machine_id
pub fn leaf_name(dpu_machine_id: &MachineId) -> String {
    format!("{}.leaf", dpu_machine_id,)
}

/// Generates the kubernetes name of a ManagedResource CRD - based on the Forge instance_id and function_id
fn managed_resource_name(instance_id: uuid::Uuid, function_id: &InterfaceFunctionId) -> String {
    format!("{}.{}", instance_id, function_id.kube_representation(),)
}

/// Generates the kubernetes name of a Network Prefix - based on the Forge network_prefix_id
fn resource_group_name(prefix_id: uuid::Uuid) -> String {
    prefix_id.to_string()
}

pub async fn create_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    dpu_machine_id: &MachineId,
    network_config: InstanceNetworkConfig,
    instance_id: uuid::Uuid,
    vpc_api: &Arc<dyn VpcApi>,
) -> Result<Poll<()>, VpcApiError> {
    let mut managed_resources = Vec::new();

    let ip_details: HashMap<Uuid, IpAddr, RandomState> = HashMap::from_iter(
        InstanceAddress::get_allocated_address(txn, instance_id)
            .await
            .map_err(|e| VpcApiError::GenericError(e.into()))?
            .into_iter()
            .map(|x| (x.segment_id, x.address.ip())),
    );

    for iface in &network_config.interfaces {
        // find_by_segmentcan CAN return max two prefixes, one for ipv4 and another for ipv6
        // Ipv4 is needed for now.
        let prefix = NetworkPrefix::find_by_segment(
            &mut *txn,
            crate::db::UuidKeyedObjectFilter::One(iface.network_segment_id),
        )
        .await
        .map_err(|e| VpcApiError::GenericError(e.into()))?
        .into_iter()
        .filter(|x| x.prefix.is_ipv4())
        .last()
        .ok_or_else(|| {
            VpcApiError::GenericError(eyre::eyre!(
                "Counldn't find IPV4 NetworkPrefix for segment {}",
                iface.network_segment_id
            ))
        })?;

        let host_interface = Some(
            BlueFieldInterface::new(iface.function_id.clone()).leaf_interface_id(dpu_machine_id),
        );

        let host_interface_ip = ip_details
            .get(&iface.network_segment_id)
            .map(|ip| ip.to_string());
        let managed_resource_spec = managed_resource::ManagedResourceSpec {
            state: None,
            dpu_i_ps: None,
            host_interface,
            host_interface_access: Some("FabricAccessDirect".to_string()),
            host_interface_ip,
            host_interface_mac: None,
            resource_group: Some(prefix.id.to_string()),
            r#type: None,
        };
        managed_resources.push(managed_resource::ManagedResource::new(
            &managed_resource_name(instance_id, &iface.function_id),
            managed_resource_spec,
        ));
    }

    log::info!(
        "ManagedResource sent to kubernetes with data: {:?}",
        managed_resources,
    );

    vpc_api
        .try_create_managed_resources(managed_resources)
        .await
}

/// Error type for interacting with VPC
#[derive(Debug, thiserror::Error)]
pub enum VpcApiError {
    #[error("Kube API returned {0:?}")]
    KubeError(Box<kube::Error>),
    #[error("Kube returned malformed IP {0}")]
    MalformedIpError(String),
    #[error(
        "A VPC object with the same name {0} but different {1} already exists. \
    The object will not be deleted automatically. \
    Please review the configuration and delete the object manually"
    )]
    ObjectExistsWithDifferentSpec(String, String),
    #[error("VPC API simulation is out of loopback IPs")]
    VpiApiSimLoopbackIpsExhausted,
    #[error("Unable to process: {0}")]
    GenericError(eyre::Report),
    #[error(
        "Leaf with name {0} has an invalid existing configuration and \
        and therefore new Host Admin IPs can't be configured"
    )]
    InvalidLeafSpecForHostAdminIpUpdate(String),
    #[error("Leaf with identifier {0} was not found")]
    LeafNotFound(String),
}

/// The result of trying to delete an object in VPC
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VpcApiDeletionResult {
    /// The deletion of an object is confirmed by kubernetes, but the object
    /// had not been deleted yet.
    DeletionInProgress,
    /// The object is fully deleted.
    Deleted,
}

/// The result of trying to create a ResourceGroup
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcApiCreateResourceGroupResult {
    /// The Circuit ID which was assigned by VPC
    pub circuit_id: String,
}

/// Interactions with forge-vpc
///
/// Functions in this API will be called by the Forge state machines.
/// Therefore all these functions should be "non blocking" - they should not wait
/// for any kubernetes objects to change state, but just try to modify objects
/// or poll their state.
#[async_trait::async_trait]
pub trait VpcApi: Send + Sync + 'static + std::fmt::Debug {
    /// Trys to create a resource group on Forge VPC
    ///
    /// Will return
    /// - Ok(Poll::Ready(result)) if the creation succeeded
    /// - Ok(Poll::Pending) if the creation is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the creation attempt failed
    async fn try_create_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
        prefix: IpNetwork,
        gateway: Option<IpNetwork>,
        vlan_id: Option<i16>,
        vni: Option<i32>,
    ) -> Result<Poll<VpcApiCreateResourceGroupResult>, VpcApiError>;

    /// Trys to delete a resource group on Forge VPC
    ///
    /// Will return
    /// - Ok(Poll::Ready(())) if the deletion has succeeded
    /// - Ok(Poll::Pending) if the deletion is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the deletion attempt failed
    async fn try_delete_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError>;

    /// Trys to create a leaf on Forge VPC
    ///
    /// Will return
    /// - Ok(Poll::Ready(result)) if the creation succeeded
    /// - Ok(Poll::Pending) if the creation is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the creation attempt failed
    async fn try_create_leaf(&self, dpu: DpuMachine) -> Result<Poll<IpAddr>, VpcApiError>;

    /// Updates a Leaf CRD with the admin IP that was allocated for the
    /// host that is attached to the DPU
    async fn try_update_leaf(
        &self,
        dpu_machine_id: &MachineId,
        host_admin_ip: Ipv4Addr,
    ) -> Result<Poll<()>, VpcApiError>;

    /// Trys to delete a leaf on Forge VPC
    ///
    /// Will return
    /// - Ok(Poll::Ready(())) if the deletion has succeeded
    /// - Ok(Poll::Pending) if the deletion is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the deletion attempt failed
    async fn try_delete_leaf(&self, dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError>;

    /// Trys to create managed resources on Forge VPC
    ///
    /// Will return
    /// - Ok(Poll::Ready(result)) if the creation succeeded
    /// - Ok(Poll::Pending) if the creation is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the creation attempt failed
    async fn try_create_managed_resources(
        &self,
        managed_resources: Vec<managed_resource::ManagedResource>,
    ) -> Result<Poll<()>, VpcApiError>;

    /// Trys to delete all managed resources that are associated with an instance
    ///
    /// Will return
    /// - Ok(Poll::Ready(())) if the deletion of all resources has succeeded
    /// - Ok(Poll::Pending) if the deletion is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the deletion attempt failed
    async fn try_delete_managed_resources(
        &self,
        instance_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError>;

    /// Trys to reconfigure VPC on admin network once all managed resources are deleted.
    /// As soon as managed resources are deleted, VPC starts reconfiguring network.
    /// This function only monitors leafs to check if network is reconfigured.
    ///
    /// Will return
    /// - Ok(Poll::Ready(())) if the deletion of all resources has succeeded
    /// - Ok(Poll::Pending) if the deletion is in progress. The method should
    ///   be called again later to retrieve the final result.
    /// - Err if the deletion attempt failed
    async fn try_monitor_leaf(&self, dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError>;
}

/// Implementation of the VPC API which makes "real kubernetes API calls"
pub struct VpcApiImpl {
    client: Client,
    dhcp_servers: Vec<String>,
}

impl VpcApiImpl {
    pub fn new(client: Client, dhcp_servers: Vec<String>) -> Self {
        Self {
            client,
            dhcp_servers,
        }
    }
}

impl std::fmt::Debug for VpcApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpcApiImpl").finish()
    }
}

#[async_trait::async_trait]
impl VpcApi for VpcApiImpl {
    async fn try_create_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
        prefix: IpNetwork,
        gateway: Option<IpNetwork>,
        vlan_id: Option<i16>,
        vni: Option<i32>,
    ) -> Result<Poll<VpcApiCreateResourceGroupResult>, VpcApiError> {
        let gateway = gateway.map(|x| x.ip().to_string());

        let resource_name = resource_group_name(network_prefix_id);
        let resource_group_spec = resource_group::ResourceGroupSpec {
            dhcp_server: None,
            dhcp_servers: Some(self.dhcp_servers.clone()),
            fabric_ip_pool: None,
            network: Some(resource_group::ResourceGroupNetwork {
                gateway,
                ip: Some(prefix.ip().to_string()),
                prefix_length: Some(prefix.prefix() as _),
            }),
            network_implementation_type: None,
            overlay_ip_pool: None,
            tenant_identifier: Some(resource_name.clone()),
            forge_managed_vlan_id: vlan_id.map(|x| x as i32), // grpc min size is 32-bits
            forge_managed_vni: vni,
        };
        let resource_group =
            resource_group::ResourceGroup::new(&resource_name, resource_group_spec);

        let resource: Api<resource_group::ResourceGroup> =
            Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);

        // We determined by testing in the real k8s environment that creating a resource
        // is not idempotent. Performing a `create` call for a resource that already exists
        // will yield a HTTP 409 AlreadyExists error.
        // Since the previous controller iteration might have created the object and
        // we just have to get the status, we have to perform a `get` call before
        // create.
        let fetch_existing_result = resource.get(&resource_name).await;
        tracing::info!(
            "Fetching a potential existing ResourceGroup with name {} yielded: {:?}",
            resource_name,
            fetch_existing_result
        );
        match fetch_existing_result {
            Ok(existing_resource) => {
                // This comparison exists because the VPC definitions don't implement PartialEq :'(
                let diff_dhcp_servers =
                    existing_resource.spec.dhcp_servers != resource_group.spec.dhcp_servers;
                let e_net = existing_resource.spec.network.as_ref();
                let s_net = resource_group.spec.network.as_ref();
                let (diff_gateway, diff_ip, diff_prefix_len) = match (e_net, s_net) {
                    (None, None) => (false, false, false),
                    (None, Some(_)) | (Some(_), None) => (true, true, true),
                    (Some(e_net), Some(s_net)) => (
                        e_net.gateway != s_net.gateway,
                        e_net.ip != s_net.ip,
                        e_net.prefix_length != s_net.prefix_length,
                    ),
                };
                if diff_dhcp_servers || diff_gateway || diff_ip || diff_prefix_len {
                    let diff = if diff_dhcp_servers {
                        format!(
                            "dhcp_servers (existing:'{:?}', spec:'{:?}')",
                            existing_resource.spec.dhcp_servers, resource_group.spec.dhcp_servers
                        )
                    } else if diff_gateway {
                        format!(
                            "gateway (existing:'{:?}', spec:'{:?}')",
                            e_net.map(|x| &x.gateway),
                            s_net.map(|x| &x.gateway)
                        )
                    } else if diff_ip {
                        format!(
                            "ip (existing:'{:?}', spec:'{:?}')",
                            e_net.map(|x| &x.ip),
                            s_net.map(|x| &x.ip)
                        )
                    } else if diff_prefix_len {
                        format!(
                            "prefix_length (existing:'{:?}', spec:'{:?}')",
                            e_net.map(|x| x.prefix_length),
                            s_net.map(|x| x.prefix_length)
                        )
                    } else {
                        unreachable!();
                    };
                    return Err(VpcApiError::ObjectExistsWithDifferentSpec(
                        resource_name,
                        diff,
                    ));
                }

                return Ok(resource_group_creation_result_from_state(
                    &existing_resource,
                ));
            }
            Err(e) => {
                tracing::info!("Trying to fetch a potential existing object failed. Creating a new ResourceGroup. Error: {:?}", e);
            }
        }

        let result = resource
            .create(&PostParams::default(), &resource_group)
            .await
            .map_err(|e| VpcApiError::KubeError(Box::new(e)))?;
        log::info!(
            "ResourceGroup creation request succeeded. Resource is {:?}",
            result
        );

        Ok(resource_group_creation_result_from_state(&result))
    }

    async fn try_delete_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        let resource_name = resource_group_name(network_prefix_id);
        try_delete_k8s_resource::<resource_group::ResourceGroup>(
            &self.client,
            "resource group",
            &resource_name,
        )
        .await
    }

    async fn try_create_leaf(&self, dpu: DpuMachine) -> Result<Poll<IpAddr>, VpcApiError> {
        let leaf_name = leaf_name(dpu.machine_id());
        let spec = leaf_spec_from_dpu_machine(&dpu);

        let api: Api<leaf::Leaf> = Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);

        let fetch_existing_result = api.get(&leaf_name).await;
        tracing::info!(
            "Fetching a potential existing leaf with name {} yielded: {:?}",
            leaf_name,
            fetch_existing_result
        );

        match fetch_existing_result {
            Ok(existing_leaf) => {
                // This comparison exists because the VPC definitions don't implement PartialEq :'(
                // TODO: We don't check equality for `leaf_control`
                let diff_admin_ips = existing_leaf.spec.host_admin_i_ps != spec.host_admin_i_ps;
                let diff_interfaces = existing_leaf.spec.host_interfaces != spec.host_interfaces;
                if diff_admin_ips || diff_interfaces {
                    let diff = if diff_admin_ips {
                        "admin_ips"
                    } else {
                        "host_interfaces"
                    };
                    return Err(VpcApiError::ObjectExistsWithDifferentSpec(
                        leaf_name,
                        diff.to_string(),
                    ));
                }

                return leaf_creation_result_from_state(&existing_leaf);
            }
            Err(_) => {
                log::info!("Creating leaf with name {}", leaf_name);
            }
        }

        let leaf_spec = leaf::Leaf::new(&leaf_name, spec);

        log::info!("Leafspec sent to kubernetes: {:?}", leaf_spec);
        let result = api
            .create(&PostParams::default(), &leaf_spec)
            .await
            .map_err(|e| VpcApiError::KubeError(Box::new(e)))?;

        return leaf_creation_result_from_state(&result);
    }

    async fn try_delete_leaf(&self, dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        let leaf_name = leaf_name(dpu_machine_id);

        try_delete_k8s_resource::<leaf::Leaf>(&self.client, "leaf", &leaf_name).await
    }

    async fn try_create_managed_resources(
        &self,
        managed_resources: Vec<managed_resource::ManagedResource>,
    ) -> Result<Poll<()>, VpcApiError> {
        let mut created = false;
        let mut at_least_one_not_ready = false;

        let api: Api<managed_resource::ManagedResource> =
            Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);

        for spec in &managed_resources {
            let spec_name = spec.name().to_string();
            match api.get(&spec_name).await {
                Err(_) => {
                    let result = api.create(&PostParams::default(), spec).await;
                    if let Err(err) = result {
                        return Err(VpcApiError::KubeError(Box::new(err)));
                    }
                    created = true;
                }
                Ok(result) => match result.status() {
                    Some(status) => {
                        if !status.is_ready() {
                            at_least_one_not_ready = true;
                        }
                    }
                    None => {
                        at_least_one_not_ready = true;
                    }
                },
            }
        }

        if created || at_least_one_not_ready {
            return Ok(Poll::Pending);
        }

        Ok(Poll::Ready(()))
    }

    async fn try_update_leaf(
        &self,
        dpu_machine_id: &MachineId,
        host_admin_ip: Ipv4Addr,
    ) -> Result<Poll<()>, VpcApiError> {
        let leaf_name = leaf_name(dpu_machine_id);

        let api: Api<leaf::Leaf> = Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);
        let mut leaf = api
            .get(&leaf_name)
            .await
            .map_err(|e| VpcApiError::KubeError(Box::new(e)))?;

        let admin_ips =
            leaf.spec.host_admin_i_ps.as_mut().ok_or_else(|| {
                VpcApiError::InvalidLeafSpecForHostAdminIpUpdate(leaf_name.clone())
            })?;

        // Update the admin IP
        // If a previous IP is configured and it equals the IP we are trying to set,
        // then there is nothing else to do.
        // TODO: Should we error if there was previously a different host admin IP assigned?
        if let Some(old_ip) = admin_ips.insert(
            DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
            host_admin_ip.to_string(),
        ) {
            if old_ip == host_admin_ip.to_string() {
                tracing::info!(
                    "Leaf {} IP {} is already up to date. Skipping update",
                    leaf_name,
                    old_ip
                );
                return Ok(Poll::Ready(()));
            }
        }

        tracing::info!("Updating Leaf to new spec - {leaf:?}");

        let _updated_leaf = api
            .replace(&leaf_name, &PostParams::default(), &leaf)
            .await
            .map_err(|e| VpcApiError::KubeError(Box::new(e)))?;

        // TODO: We don't wait here for a ready status
        // Maybe we should, but currently the system just waits for the next
        // calls from the host in order to continue

        Ok(Poll::Ready(()))
    }

    async fn try_delete_managed_resources(
        &self,
        instance_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        let api: Api<managed_resource::ManagedResource> =
            Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);

        // We try deleting each interface once before reporting the state
        // That means we would at least already enqueue all the delete operations
        // to kubernetes in one handler iteration, and not wait to delete the
        // 2nd managed resource only after the first succeeded
        let mut all_ready = true;
        let mut first_error = None;
        for function_id in InterfaceFunctionId::iter_all() {
            let resource_id = managed_resource_name(instance_id, &function_id);

            let result = api.delete(&resource_id, &DeleteParams::default()).await;
            tracing::info!(
                "Result of deleting managed_resource {} is: {:?}",
                resource_id,
                result
            );

            match result {
                Ok(result) if result.is_left() => {
                    // Delete was accepted but hasn't finished
                    all_ready = false;
                }
                Ok(_) => {
                    // This branch should mean the object was deleted
                    // Note: In testing this never showed up - we get from a `Left` (Pending)
                    // to a 404 error
                    // TODO: If the status isn't a 200 (deleted) or 400 (not found),
                    // we should probably not use deleted as a result
                }
                Err(kube::Error::Api(api_error)) if api_error.code == 404 => {
                    // Object not found means it is deleted
                }
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(VpcApiError::KubeError(Box::new(e)));
                    }
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err);
        }
        if !all_ready {
            return Ok(Poll::Pending);
        }
        Ok(Poll::Ready(()))
    }

    async fn try_monitor_leaf(&self, dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        let leaf_name = leaf_name(dpu_machine_id);

        let api: Api<leaf::Leaf> = Api::namespaced(self.client.clone(), FORGE_KUBE_NAMESPACE);

        let fetch_existing_result = api.get(&leaf_name).await;
        tracing::info!(
            "Fetching a potential existing leaf to monitor with name {} yielded: {:?}",
            leaf_name,
            fetch_existing_result
        );

        match fetch_existing_result {
            Ok(existing_leaf) => {
                return leaf_creation_result_from_state(&existing_leaf).map(|_| Poll::Ready(()));
            }
            Err(err) => {
                log::error!("Attached leaf {} with dpu id: {} not found. Machine should move to Broken state.", leaf_name, dpu_machine_id);
                return Err(VpcApiError::KubeError(err.into()));
            }
        }
    }
}

/// Tries to delete a kubernetes CRD
///
/// Returns
/// - `Ok(Poll::Ready(()))` if deletion is done
/// - `Ok(Poll::Pending)` if deletion is requested, but not finished
/// - `Err(e)` if deletion failed
async fn try_delete_k8s_resource<
    'a,
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
>(
    client: &'a Client,
    resource_type: &'static str,
    resource_id: &'a str,
) -> Result<Poll<()>, VpcApiError>
where
    <K as kube::Resource>::DynamicType: Default,
{
    let resource: Api<K> = Api::namespaced(client.clone(), FORGE_KUBE_NAMESPACE);
    let result = resource.delete(resource_id, &DeleteParams::default()).await;
    tracing::info!(
        "Result of deleting {} {} is: {:?}",
        resource_type,
        resource_id,
        result
    );

    match result {
        Ok(result) if result.is_left() => Ok(Poll::Pending),
        Ok(_) => {
            // Note: In testing this never showed up - we get from a `Left` (Pending)
            // to a 404 error
            // TODO: If the status isn't a 200 (deleted) or 400 (not found),
            // we should probably not use deleted as a result
            Ok(Poll::Ready(()))
        }
        Err(kube::Error::Api(api_error)) if api_error.code == 404 => {
            // Object not found means it is deleted
            Ok(Poll::Ready(()))
        }
        Err(e) => Err(VpcApiError::KubeError(Box::new(e))),
    }
}

fn leaf_spec_from_dpu_machine(dpu: &DpuMachine) -> leaf::LeafSpec {
    leaf::LeafSpec {
        control: Some(leaf::LeafControl {
            maintenance_mode: Some(false),
            management_ip: Some(dpu.address().ip().to_string()),
            ssh_credential_kv_path: Some(
                CredentialKey::DpuSsh {
                    machine_id: dpu.machine_id().to_string(),
                }
                .to_key_str(),
            ),
            //it's also required for us to pass an HBN kv path but apparently that's not setup in schema yet.
            vendor: Some("DPU".to_string()),
        }),
        host_admin_i_ps: Some(BTreeMap::from([(
            DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
            "".to_string(),
        )])),
        host_interfaces: Some(crate::vpc_resources::host_interfaces(dpu.machine_id())),
        forge_managed_lookback_ip: dpu.loopback_ip().map(|x| x.to_string()),
    }
}

fn resource_group_creation_result_from_state(
    state: &resource_group::ResourceGroup,
) -> Poll<VpcApiCreateResourceGroupResult> {
    match state.status() {
        Some(status) if status.is_ready() => {
            let circuit_id = status
                .dhcp_circ_id
                .clone()
                .expect("Status confirmed that the circuit ID is set");
            Poll::Ready(VpcApiCreateResourceGroupResult { circuit_id })
        }
        _ => Poll::Pending,
    }
}

fn leaf_creation_result_from_state(state: &leaf::Leaf) -> Result<Poll<IpAddr>, VpcApiError> {
    match state.status() {
        Some(status) if status.is_ready() => {
            let Some(ip_addr) = status.loopback_ip.as_ref() else {
                // This is validated in is_ready. It can not be err.
                return Err(VpcApiError::MalformedIpError("Unknown".to_string()));
            };
            let loopback_ip = IpAddr::from_str(ip_addr)
                .map_err(|_| VpcApiError::MalformedIpError(ip_addr.to_string()))?;
            Ok(Poll::Ready(loopback_ip))
        }
        _ => Ok(Poll::Pending),
    }
}

/// Simulation of the VPC API for a docker-compose environment
#[derive(Debug, Default)]
pub struct VpcApiSim {
    state: Arc<Mutex<VpcApiSimState>>,
    config: VpcApiSimConfig,
}

impl VpcApiSim {
    pub fn with_config(config: VpcApiSimConfig) -> Self {
        Self {
            state: Default::default(),
            config,
        }
    }

    pub fn num_leafs(&self) -> usize {
        self.state.lock().unwrap().leafs.len()
    }
}

#[derive(Debug)]
pub struct VpcApiSimConfig {
    pub required_creation_attempts: usize,
    pub required_deletion_attempts: usize,
    /// The IP address space that is used to allocate Leaf loopback IPs
    /// The Sim will hand out loopback IPs starting at this address.
    /// Additional addresses will be in the same /24, which means the first
    /// 3 bytes are shared with the start address, and the last byte will increase
    /// up to 255
    pub leaf_loopback_ip_start_address: [u8; 4],
}

impl Default for VpcApiSimConfig {
    fn default() -> Self {
        Self {
            required_creation_attempts: 2,
            required_deletion_attempts: 2,
            leaf_loopback_ip_start_address: [172, 20, 0, 2],
        }
    }
}

#[derive(Debug, Default)]
struct VpcApiSimState {
    resource_groups: HashMap<String, VpcApiSimResourceGroupState>,
    leafs: HashMap<String, VpcApiSimLeafState>,
    /// Enumerates which IPs we've already allocated for leafs
    /// At the start it will be none
    used_loopback_ip_suffixes: HashSet<u8>,
}

#[derive(Debug)]
struct VpcApiSimResourceGroupState {
    creation_attempts: usize,
    deletion_attempts: usize,
    spec: VpcApiSimResourceGroup,
    circuit_id: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct VpcApiSimResourceGroup {
    network_prefix_id: uuid::Uuid,
    prefix: IpNetwork,
    gateway: Option<IpNetwork>,
    vlan_id: Option<i16>,
    vni: Option<i32>,
}

#[derive(Debug)]
struct VpcApiSimLeafState {
    creation_attempts: usize,
    deletion_attempts: usize,
    spec: leaf::LeafSpec,
    loopback_ip: Ipv4Addr,
}

#[async_trait::async_trait]
impl VpcApi for VpcApiSim {
    async fn try_create_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
        prefix: IpNetwork,
        gateway: Option<IpNetwork>,
        vlan_id: Option<i16>,
        vni: Option<i32>,
    ) -> Result<Poll<VpcApiCreateResourceGroupResult>, VpcApiError> {
        let name = resource_group_name(network_prefix_id);
        let group = VpcApiSimResourceGroup {
            network_prefix_id,
            prefix,
            gateway,
            vlan_id,
            vni,
        };

        let mut guard = self.state.lock().unwrap();

        if let Some(entry) = guard.resource_groups.get_mut(&name) {
            if entry.spec != group {
                return Err(VpcApiError::ObjectExistsWithDifferentSpec(
                    name,
                    "VpcApiSimResourceGroup".to_string(),
                ));
            }
            entry.creation_attempts += 1;
            if entry.creation_attempts >= self.config.required_creation_attempts {
                Ok(Poll::Ready(VpcApiCreateResourceGroupResult {
                    circuit_id: entry.circuit_id.clone(),
                }))
            } else {
                Ok(Poll::Pending)
            }
        } else {
            let circuit_id = name.clone() + "Circuit";
            guard.resource_groups.insert(
                name,
                VpcApiSimResourceGroupState {
                    spec: group,
                    creation_attempts: 1,
                    deletion_attempts: 0,
                    circuit_id: circuit_id.clone(),
                },
            );
            if self.config.required_creation_attempts == 1 {
                Ok(Poll::Ready(VpcApiCreateResourceGroupResult { circuit_id }))
            } else {
                // We mimic the behavior of real VPC - the status isn't immediately available
                Ok(Poll::Pending)
            }
        }
    }

    async fn try_delete_resource_group(
        &self,
        network_prefix_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        let name = resource_group_name(network_prefix_id);
        let mut guard = self.state.lock().unwrap();
        if let Some(entry) = guard.resource_groups.get_mut(&name) {
            entry.deletion_attempts += 1;
            if entry.deletion_attempts >= self.config.required_deletion_attempts {
                guard.resource_groups.remove(&name);
                Ok(Poll::Ready(()))
            } else {
                Ok(Poll::Pending)
            }
        } else {
            Ok(Poll::Ready(()))
        }
    }

    async fn try_create_leaf(&self, dpu: DpuMachine) -> Result<Poll<IpAddr>, VpcApiError> {
        let leaf_name = leaf_name(dpu.machine_id());
        let spec = leaf_spec_from_dpu_machine(&dpu);

        let mut guard = self.state.lock().unwrap();

        if let Some(entry) = guard.leafs.get_mut(&leaf_name) {
            let diff_admin_ips = entry.spec.host_admin_i_ps != spec.host_admin_i_ps;
            let diff_interfaces = entry.spec.host_interfaces != spec.host_interfaces;
            if diff_admin_ips || diff_interfaces {
                let diff = if diff_admin_ips {
                    "admin_ips"
                } else {
                    "interfaces"
                };
                return Err(VpcApiError::ObjectExistsWithDifferentSpec(
                    leaf_name,
                    diff.to_string(),
                ));
            }
            entry.creation_attempts += 1;
            if entry.creation_attempts >= self.config.required_creation_attempts {
                tracing::info!(
                    "Finalized creating leaf after {} creation attempts with name {} found for DPU {}",
                    entry.creation_attempts,
                    leaf_name,
                    dpu.machine_id()
                );
                Ok(Poll::Ready(entry.loopback_ip.into()))
            } else {
                Ok(Poll::Pending)
            }
        } else {
            let loopback_ip: Ipv4Addr = match dpu.loopback_ip() {
                Some(l_ip) => {
                    // Forge has already assigned it
                    l_ip
                }
                None => {
                    // VPC needs to assign it
                    // Find a free loopback IP
                    let mut ip = self.config.leaf_loopback_ip_start_address;
                    loop {
                        if !guard.used_loopback_ip_suffixes.contains(&ip[3]) {
                            break;
                        }
                        if ip[3] == 255 {
                            return Err(VpcApiError::VpiApiSimLoopbackIpsExhausted);
                        }
                        ip[3] += 1;
                    }
                    guard.used_loopback_ip_suffixes.insert(ip[3]);
                    Ipv4Addr::from(ip)
                }
            };
            tracing::info!(
                "Started creating leaf with name {} found for DPU {}",
                leaf_name,
                dpu.machine_id()
            );
            guard.leafs.insert(
                leaf_name.clone(),
                VpcApiSimLeafState {
                    spec,
                    loopback_ip,
                    creation_attempts: 1,
                    deletion_attempts: 0,
                },
            );
            if self.config.required_creation_attempts == 1 {
                tracing::info!(
                    "Finalized creating leaf immediately with name {} found for DPU {}",
                    leaf_name,
                    dpu.machine_id()
                );
                Ok(Poll::Ready(loopback_ip.into()))
            } else {
                // We mimic the behavior of real VPC - the status isn't immediately available
                Ok(Poll::Pending)
            }
        }
    }

    async fn try_delete_leaf(&self, dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        let leaf_name = leaf_name(dpu_machine_id);

        let mut guard = self.state.lock().unwrap();
        if let Some(entry) = guard.leafs.get_mut(&leaf_name) {
            entry.deletion_attempts += 1;
            tracing::info!(
                "Leaf with name {} found for DPU {}. Deletion attempts: {}",
                leaf_name,
                dpu_machine_id,
                entry.deletion_attempts
            );
            if entry.deletion_attempts >= self.config.required_deletion_attempts {
                let loopback_ip = entry.loopback_ip;
                guard.leafs.remove(&leaf_name);
                guard
                    .used_loopback_ip_suffixes
                    .remove(&(loopback_ip.octets()[3]));
                tracing::info!(
                    "Leaf with name {} found for DPU {}. Deleted",
                    leaf_name,
                    dpu_machine_id
                );
                Ok(Poll::Ready(()))
            } else {
                Ok(Poll::Pending)
            }
        } else {
            tracing::info!(
                "Leaf with name {} not found for DPU {}. Returning",
                leaf_name,
                dpu_machine_id
            );
            Ok(Poll::Ready(()))
        }
    }

    async fn try_create_managed_resources(
        &self,
        _managed_resources: Vec<managed_resource::ManagedResource>,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_update_leaf(
        &self,
        dpu_machine_id: &MachineId,
        host_admin_ip: Ipv4Addr,
    ) -> Result<Poll<()>, VpcApiError> {
        let leaf_name = leaf_name(dpu_machine_id);

        let mut guard = self.state.lock().unwrap();

        let leaf = guard
            .leafs
            .get_mut(&leaf_name)
            .ok_or_else(|| VpcApiError::LeafNotFound(leaf_name.clone()))?;

        let admin_ips =
            leaf.spec.host_admin_i_ps.as_mut().ok_or_else(|| {
                VpcApiError::InvalidLeafSpecForHostAdminIpUpdate(leaf_name.clone())
            })?;

        admin_ips.insert(
            DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
            host_admin_ip.to_string(),
        );

        Ok(Poll::Ready(()))
    }

    async fn try_delete_managed_resources(
        &self,
        _instance_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        return Ok(Poll::Ready(()));
    }

    async fn try_monitor_leaf(&self, _dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        return Ok(Poll::Ready(()));
    }
}
