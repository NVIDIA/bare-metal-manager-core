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
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use kube::api::ListParams;
use kube::runtime::wait::{await_condition, Condition};
use kube::{
    api::{Api, DeleteParams, PostParams, ResourceExt},
    Client,
};
use rpc::{InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation};
use serde::{Deserialize, Serialize};
use sqlx::{self, PgPool};
use sqlx::{Acquire, PgConnection, Postgres};
use sqlxmq::{job, CurrentJob, JobRegistry, OwnedHandle};
use uuid::Uuid;

use crate::bg::{CurrentState, Status, TaskState};
use crate::db::constants::FORGE_KUBE_NAMESPACE;
use crate::db::network_prefix::NetworkPrefix;
use crate::db::vpc_resource_leaf::VpcResourceLeaf;
use crate::ipmi::{MachinePowerRequest, Operation};
use crate::model::config_version::{ConfigVersion, Versioned};
use crate::model::instance::config::network::{InstanceNetworkConfig, InterfaceFunctionId};
use crate::model::machine::DPU_PHYSICAL_NETWORK_INTERFACE;
use crate::vpc_resources::{
    leaf, managed_resource, resource_group, BlueFieldInterface, VpcResource, VpcResourceStatus,
};
use crate::{CarbideError, CarbideResult};
use ipnetwork::Ipv4Network;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafData {
    pub leaf: leaf::Leaf,
    pub dpu_machine_id: uuid::Uuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateLeafData {
    pub dpu_machine_id: uuid::Uuid,
    host_admin_i_ps: Option<BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManagedResourceData {
    machine_id: uuid::Uuid,
    dpu_machine_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    network_config_version: ConfigVersion,
    network_config: InstanceNetworkConfig,
    ip_details: Option<HashMap<Uuid, IpAddr>>, // NetworkSegment => IpAddr
    managed_resources: Vec<managed_resource::ManagedResource>,
}

impl ManagedResourceData {
    fn new(
        machine_id: uuid::Uuid,
        dpu_machine_id: uuid::Uuid,
        instance_id: uuid::Uuid,
        network_config: Versioned<InstanceNetworkConfig>,
        ip_details: Option<HashMap<Uuid, IpAddr>>, // NetworkSegment => IpAddr
        managed_resources: Vec<managed_resource::ManagedResource>,
    ) -> Self {
        ManagedResourceData {
            machine_id,
            dpu_machine_id,
            instance_id,
            network_config_version: network_config.version,
            network_config: network_config.config,
            ip_details,
            managed_resources,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VpcResourceActions {
    CreateLeaf(LeafData),
    DeleteLeaf(LeafData),
    UpdateLeaf(UpdateLeafData),
    CreateResourceGroup(resource_group::ResourceGroup),
    UpdateResourceGroup(resource_group::ResourceGroup),
    DeleteResourceGroup(resource_group::ResourceGroup),
    CreateManagedResource(ManagedResourceData),
    UpdateManagedResource(ManagedResourceData),
    DeleteManagedResource(ManagedResourceData),
}

#[derive(Debug)]
pub struct Db(sqlx::PgPool);

impl Db {
    pub async fn new(url: &str) -> CarbideResult<Self> {
        Ok(Db(sqlx::PgPool::connect(url).await?))
    }
}

impl VpcResourceActions {
    async fn enqueue(&self, pool: &mut PgConnection) -> CarbideResult<Uuid> {
        let json = serde_json::to_string(self)?;

        log::info!("Job definition {}", &json);

        // TODO retry_backoff should be configurable in CLI

        vpc_reconcile_handler
            .builder()
            .set_retry_backoff(std::time::Duration::from_secs(5))
            .set_channel_name("vpc_reconcile_handler")
            .set_json(&json)?
            .spawn(pool)
            .await
            .map_err(CarbideError::from)
    }

    pub async fn reconcile(&self, pool: &mut PgConnection) -> CarbideResult<Uuid> {
        let jid = self.enqueue(pool).await?;
        Ok(jid)
    }
}

async fn _leaf_resource_status(spec: leaf::Leaf) -> CarbideResult<leaf::LeafStatus> {
    let client = Client::try_default().await?;
    let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), FORGE_KUBE_NAMESPACE);
    let leaf_to_status = leafs.get_status(spec.name().as_ref()).await?;

    match leaf_to_status.status {
        None => Err(CarbideError::GenericError("None".to_string())),
        Some(x) => Ok(x),
    }
}

async fn update_status(current_job: &CurrentJob, checkpoint: u32, msg: String, state: TaskState) {
    if let TaskState::Error(..) = &state {
        log::error!("Error status: {}, checkpoint: {}", msg, checkpoint);
    } else {
        log::info!("Current status: {}, checkpoint: {}", msg, checkpoint);
    }

    match Status::update(
        current_job.pool(),
        current_job.id(),
        CurrentState {
            checkpoint,
            msg,
            state,
        },
    )
    .await
    {
        Ok(_) => (),
        Err(x) => {
            log::error!("Status update failed. Error: {:?}", x)
        }
    }
}

async fn create_resource_group_handler(
    mut current_job: CurrentJob,
    spec: resource_group::ResourceGroup,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();
    let start_time = Instant::now();
    log::info!("Creating resource_group with name {}.", spec_name);

    update_status(
        &current_job,
        0,
        format!("Creating resource group with name {}", spec_name),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<resource_group::ResourceGroup> =
        Api::namespaced(client, FORGE_KUBE_NAMESPACE);
    let result = resource.create(&PostParams::default(), &spec).await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                2,
                format!(
                    "ResourceGroup created {} on vpc, elapsed {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Ongoing,
            )
            .await;
            let waiter = await_condition(
                resource.clone(),
                spec_name.as_str(),
                ConditionReadyMatcher {
                    matched_name: spec_name.clone(),
                },
            );
            let _ = tokio::time::timeout(std::time::Duration::from_secs(60 * 5), waiter)
                .await
                .map_err(|_elapsed_error| {
                    CarbideError::TokioTimeoutError("creating resource group".to_string())
                })?;

            update_status(
                &current_job,
                3,
                format!(
                    "ResourceGroup updated {} on vpc, elapsed {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Ongoing,
            )
            .await;
            let new_rg = resource.get_status(&spec.name()).await?;
            if let Some(status) = new_rg.status.as_ref() {
                if let Some(dhcp_circuit_id) = status.dhcp_circ_id.as_ref() {
                    let mut txn = current_job.pool().begin().await?;
                    NetworkPrefix::update_circuit_id(
                        &mut txn,
                        Uuid::try_from(spec_name.as_str())?,
                        dhcp_circuit_id.to_owned(),
                    )
                    .await?;
                    txn.commit().await?;
                }
            }

            update_status(
                &current_job,
                4,
                format!(
                    "ResourceGroup created {} and vlan id updated, elapsed {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Finished,
            )
            .await;
            let _ = current_job.complete().await.map_err(CarbideError::from);
            Ok(())
        }
        Err(err) => {
            update_status(
                &current_job,
                5,
                format!(
                    "ResourceGroup creation {} failed. Error: {:?}, elapsed {:?}",
                    spec.name(),
                    err,
                    start_time.elapsed(),
                ),
                TaskState::Error(err.to_string()),
            )
            .await;
            Err(CarbideError::GenericError(err.to_string()))
        }
    }
}

async fn delete_resource_group_handler(
    mut current_job: CurrentJob,
    spec: resource_group::ResourceGroup,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();
    let start_time = Instant::now();

    update_status(
        &current_job,
        0,
        format!("Deleting resource group with name {}", spec_name),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<resource_group::ResourceGroup> =
        Api::namespaced(client, FORGE_KUBE_NAMESPACE);
    let result = resource.delete(&spec_name, &DeleteParams::default()).await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                1,
                format!(
                    "ResourceGroup deletion {} is successful, elapsed {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Finished,
            )
            .await;
            let _ = current_job.complete().await.map_err(CarbideError::from);
            Ok(())
        }
        Err(err) => {
            update_status(
                &current_job,
                2,
                format!(
                    "ResourceGroup deletion {} failed. Error: {:?}, elapsed {:?}",
                    spec.name(),
                    err,
                    start_time.elapsed()
                ),
                TaskState::Error(err.to_string()),
            )
            .await;
            Err(CarbideError::GenericError(err.to_string()))
        }
    }
}

async fn create_managed_resource_handler(
    mut current_job: CurrentJob,
    data: ManagedResourceData,
    client: Client,
    handler_args: &VpcReconcileHandlerArguments,
) -> CarbideResult<()> {
    let start_time = Instant::now();

    update_status(
        &current_job,
        0,
        format!(
            "Creating managed_resource for instance {}",
            data.instance_id
        ),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<managed_resource::ManagedResource> =
        Api::namespaced(client.clone(), FORGE_KUBE_NAMESPACE);

    let mut spec_names = Vec::new();
    let mut waiters = FuturesUnordered::new();
    for spec in &data.managed_resources {
        let spec_name = spec.name().to_string();
        if resource.get(&spec_name).await.is_err() {
            let result = resource.create(&PostParams::default(), spec).await;
            if let Err(err) = result {
                update_status(
                    &current_job,
                    1,
                    format!(
                        "ManagedResource creation {} failed. Error: {:?} Duration: {:?}",
                        spec.name(),
                        err,
                        start_time.elapsed(),
                    ),
                    TaskState::Error(err.to_string()),
                )
                .await;
                return Err(CarbideError::GenericError(err.to_string()));
            }

            spec_names.push(spec_name);
        }
    }

    spec_names.iter().for_each(|name| {
        waiters.push(await_condition(
            resource.clone(),
            name.as_str(),
            ConditionReadyMatcher {
                matched_name: name.to_owned(),
            },
        ));
    });

    update_status(
        &current_job,
        2,
        format!(
            "ManagedResource created for instance {} after {:?}.",
            data.instance_id,
            start_time.elapsed()
        ),
        TaskState::Ongoing,
    )
    .await;

    let sleep = tokio::time::sleep(tokio::time::Duration::from_secs(60 * 10));
    tokio::pin!(sleep);

    for _ in &spec_names {
        tokio::select! {
            _ = waiters.next() => {}
            _ = &mut sleep => {
                let err_msg =
                    format!(
                        "Timeout while waiting for ManagedResource creation for instance: {}, elapsed: {:?}",
                        data.instance_id,
                        start_time.elapsed());
                update_status(
                    &current_job,
                    3,
                    err_msg.clone(),
                    TaskState::Error("Timeout".to_string()),
                )
                .await;
                return Err(CarbideError::TokioTimeoutError(err_msg));
            }
        }
    }

    // TODO: The MAC address is missing
    // It doesn't seem available in the k8s ManagedResource spec
    let mut iface_observations: Vec<InstanceInterfaceStatusObservation> =
        Vec::with_capacity(data.network_config.interfaces.len());
    for iface in data.network_config.interfaces.iter() {
        let address = match &data.ip_details {
            Some(details) => details.get(&iface.network_segment_id),
            None => None,
        };

        let address = match address {
            Some(address) => address,
            None => {
                let error = format!(
                    "Failed to retrieve Ip Address for instance {} and function ID {:?}",
                    data.instance_id, iface.function_id
                );
                update_status(
                    &current_job,
                    10,
                    error.clone(),
                    TaskState::Error(error.clone()),
                )
                .await;
                return Err(CarbideError::GenericError(error));
            }
        };

        iface_observations.push(InstanceInterfaceStatusObservation {
            function_type: rpc::InterfaceFunctionType::from(iface.function_id.function_type())
                as i32,
            virtual_function_id: match iface.function_id {
                InterfaceFunctionId::PhysicalFunctionId {} => None,
                InterfaceFunctionId::VirtualFunctionId { id } => Some(id as u32),
            },
            mac_address: None,
            addresses: vec![address.to_string()],
        });
    }

    handler_args
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            InstanceNetworkStatusObservation {
                instance_id: Some(data.instance_id.into()),
                config_version: data.network_config_version.to_version_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: iface_observations,
            },
        ))
        .await
        .map_err(|status| CarbideError::GenericError(status.to_string()))?;

    update_status(
        &current_job,
        4,
        format!(
            "ManagedResource created for instance {} on vpc after {:?}.",
            data.instance_id,
            start_time.elapsed()
        ),
        TaskState::Ongoing,
    )
    .await;

    let task_id = power_reset_machine(data.machine_id, current_job.pool().clone()).await?;
    update_status(
        &current_job,
        5,
        format!(
            "Machine reset task spawned for machine_id {} with task: {} after duration {:?}",
            data.machine_id,
            task_id,
            start_time.elapsed(),
        ),
        TaskState::Finished,
    )
    .await;
    let _ = current_job.complete().await.map_err(CarbideError::from);
    Ok(())
}

async fn find_leaf_with_host_interface(
    mac: &String,
    client: Client,
) -> CarbideResult<Option<String>> {
    let leaf_api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
    let leafs = leaf_api.list(&ListParams::default()).await?;

    for leaf in leafs {
        if let Some(host_interfaces) = leaf.spec.host_interfaces.as_ref() {
            if host_interfaces.contains_key(mac) {
                if let Some(name) = leaf.vpc_resource_name() {
                    return Ok(Some(name.to_owned()));
                }
            }
        }
    }

    Ok(None)
}

async fn find_leaf_with_dpu_id(
    dpu_machine_id: uuid::Uuid,
    client: Client,
) -> CarbideResult<Option<String>> {
    let host_interface = BlueFieldInterface::new(InterfaceFunctionId::PhysicalFunctionId {})
        .leaf_interface_id(&dpu_machine_id);
    let leaf_name = find_leaf_with_host_interface(&host_interface, client.clone()).await?;
    Ok(leaf_name)
}

async fn wait_for_hbn_to_configure(
    leaf_name: Option<String>,
    client: Client,
    current_job: &CurrentJob,
    start_time: &Instant,
) -> CarbideResult<()> {
    if let Some(leaf_name) = leaf_name {
        let api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
        let waiter = await_condition(
            api,
            leaf_name.as_str(),
            ConditionReadyMatcher {
                matched_name: leaf_name.clone(),
            },
        );

        if let Err(err) = tokio::time::timeout(std::time::Duration::from_secs(60 * 5), waiter).await
        {
            let err_msg = format!(
                "deleting managedresource timeout for leaf {}, Error: {}",
                leaf_name, err
            );

            update_status(
                current_job,
                10,
                "Waiting for HBN to configure failed.".to_string(),
                TaskState::Error(err_msg.clone()),
            )
            .await;
            return Err(CarbideError::TokioTimeoutError(err_msg));
        }

        update_status(
            current_job,
            11,
            format!(
                "hbn leaf: {} is configured with admin network, elapsed: {:?}.",
                leaf_name,
                start_time.elapsed(),
            ),
            TaskState::Ongoing,
        )
        .await;
    }

    Ok(())
}

async fn delete_managed_resource_handler(
    mut current_job: CurrentJob,
    data: ManagedResourceData,
    client: Client,
) -> CarbideResult<()> {
    let start_time = Instant::now();
    log::info!(
        "Deleting managed_resources for instance {}.",
        data.instance_id
    );

    update_status(
        &current_job,
        0,
        format!(
            "Deleting managed_resource for instance {} elapsed: {:?}",
            data.instance_id,
            start_time.elapsed()
        ),
        TaskState::Ongoing,
    )
    .await;

    let resource_api: Api<managed_resource::ManagedResource> =
        Api::namespaced(client.clone(), FORGE_KUBE_NAMESPACE);

    let leaf_name = find_leaf_with_dpu_id(data.dpu_machine_id, client.clone()).await?;

    for spec in data.managed_resources {
        let spec_name = spec.name().to_string();
        if resource_api.get(&spec_name).await.is_ok() {
            let result = resource_api
                .delete(&spec_name, &DeleteParams::default())
                .await;

            if let Err(err) = result {
                update_status(
                    &current_job,
                    5,
                    format!(
                        "ManagedResource deletion {} failed. Error: {:?}",
                        spec.name(),
                        err
                    ),
                    TaskState::Error(err.to_string()),
                )
                .await;
                return Err(CarbideError::GenericError(err.to_string()));
            }

            log::info!(
                "ManagedResource deletion {} is successful, elapsed: {:?}.",
                spec_name,
                start_time.elapsed()
            );
        } else {
            log::info!("ManagedResource {} is already deleted.", spec_name);
        }
    }
    update_status(
        &current_job,
        1,
        format!(
            "ManagedResources for instance {} are deleted, elapsed: {:?}.",
            data.instance_id,
            start_time.elapsed(),
        ),
        TaskState::Ongoing,
    )
    .await;

    // In case leaf is not found (although it should never happen), machine will stuck in
    // boot loop. This is only possible due to misconfiguration. Do not return failure
    // as MR is already deleted.
    // TODO: Machine should be moved to FAILED state.
    wait_for_hbn_to_configure(leaf_name, client.clone(), &current_job, &start_time).await?;

    // Reboot host
    let task_id = power_reset_machine(data.machine_id, current_job.pool().clone()).await?;
    update_status(
        &current_job,
        3,
        format!(
            "Machine reset task spawned for machine_id {}, task: {}, elapsed: {:?}",
            data.machine_id,
            task_id,
            start_time.elapsed(),
        ),
        TaskState::Finished,
    )
    .await;
    let _ = current_job.complete().await.map_err(CarbideError::from);
    Ok(())
}

#[derive(Clone)]
pub struct VpcReconcileHandlerArguments {
    kube_enabled: bool,
    api: Arc<dyn rpc::forge::forge_server::Forge>,
}

#[job(channel_name = "vpc_reconcile_handler")]
pub async fn vpc_reconcile_handler(
    mut current_job: CurrentJob,
    handler_args: VpcReconcileHandlerArguments,
) -> CarbideResult<()> {
    log::debug!("Kubernetes integration is: {}", handler_args.kube_enabled);

    let start_time = Instant::now();

    // Retrieve job payload as JSON
    let data: Option<String> = current_job.json()?;

    log::debug!("JOB DEFINITION: {:?}", &data);

    // Parse payload as JSON into VpcResource
    update_status(&current_job, 1, "Started".to_string(), TaskState::Started).await;

    let vpc_resource: VpcResourceActions = serde_json::from_str(&(data.unwrap()))?;
    // Set back ground task to ongoing
    update_status(
        &current_job,
        2,
        "Json parsing ok.".to_string(),
        TaskState::Ongoing,
    )
    .await;

    log::info!("Kubernetes integration is: {}", handler_args.kube_enabled);

    if handler_args.kube_enabled {
        let client = Client::try_default().await?;
        let namespace = FORGE_KUBE_NAMESPACE;

        match vpc_resource {
            VpcResourceActions::CreateLeaf(leaf_data) => {
                let spec_name = leaf_name(leaf_data.dpu_machine_id);
                let spec = leaf_data.leaf;
                assert_eq!(
                    Some(&spec_name),
                    spec.metadata.name.as_ref(),
                    "Leaf space name mismatch"
                );

                let mut vpc_txn = current_job.pool().begin().await?;

                let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);

                // Kube CRD names are strings, so we have to convert from string to uuid::Uuid
                let mut vpc_db_resource =
                    VpcResourceLeaf::find(&mut vpc_txn, leaf_data.dpu_machine_id).await?;

                let result = leafs.create(&PostParams::default(), &spec).await;
                match result {
                    Ok(new_leaf) => {
                        log::info!("Created VPC Object {} ({:?})", new_leaf.name(), new_leaf);

                        update_status(
                            &current_job,
                            2,
                            format!(
                                "VPC Leaf object created, waiting for status object, elapsed: {:?}",
                                start_time.elapsed()
                            ),
                            TaskState::Ongoing,
                        )
                        .await;

                        let api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                        let waiter = await_condition(
                            api,
                            spec_name.as_str(),
                            ConditionReadyMatcher {
                                matched_name: spec_name.clone(),
                            },
                        );
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(60 * 10), waiter)
                                .await
                                .map_err(|_elapsed_error| {
                                    CarbideError::TokioTimeoutError(
                                        "creating vpc leaf object".to_string(),
                                    )
                                })?;
                        let newly_created_leaf = leafs.get_status(&spec.name()).await?;

                        let mut last_txn = current_job.pool().begin().await?;

                        log::info!("VPC Status Object: {:?}", newly_created_leaf.status);

                        update_status(
                            &current_job,
                            2,
                            format!(
                                "VPC Leaf status object retrieved, elapsed {:?}",
                                start_time.elapsed()
                            ),
                            TaskState::Ongoing,
                        )
                        .await;

                        if let Some(status) = newly_created_leaf.status.as_ref() {
                            if let Some(address_str) = status.loopback_ip.as_ref() {
                                if let Ok(ip_address) = IpAddr::from_str(address_str.as_str()) {
                                    vpc_db_resource
                                        .update_loopback_ip_address(&mut last_txn, ip_address)
                                        .await?;
                                } else {
                                    todo!("can't parse loopback IP as a valid IP Address this is bad -- wtf kube :P")
                                }
                            } else {
                                todo!("no loopback IP this is bad -- we waited for it to be ready so it can't not have this")
                            }
                        } else {
                            todo!("no status this is bad -- we waited for it to be ready so it can't not have this")
                        }

                        last_txn.commit().await?;

                        update_status(
                            &current_job,
                            3,
                            format!(
                                "{} Creation completed, elapsed {:?}",
                                new_leaf.name(),
                                start_time.elapsed()
                            ),
                            TaskState::Finished,
                        )
                        .await;

                        let _ = current_job.complete().await.map_err(CarbideError::from);
                        log::info!("Jobs done - {}", &current_job.id())
                    }

                    Err(error) => {
                        log::error!("error : {error:?}");
                        update_status(
                            &current_job,
                            6,
                            format!(
                                "Unable to create resource, elapsed: {:?}",
                                start_time.elapsed()
                            ),
                            TaskState::Error(error.to_string()),
                        )
                        .await;
                    }
                };
            }
            VpcResourceActions::DeleteLeaf(leaf_data) => {
                let mut state_txn = current_job.pool().begin().await?;
                let vpc_db_resource =
                    VpcResourceLeaf::find(&mut state_txn, leaf_data.dpu_machine_id).await?;
                let spec_name = leaf_name(leaf_data.dpu_machine_id);

                vpc_db_resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Submit)
                    .await?;
                state_txn.commit().await?;

                update_status(
                    &current_job,
                    4,
                    format!(
                        "VPC Resource {} deleted, elapsed {:?}",
                        spec_name,
                        start_time.elapsed()
                    ),
                    TaskState::Finished,
                )
                .await;
                let _ = current_job.complete().await.map_err(CarbideError::from);
            }
            VpcResourceActions::UpdateLeaf(leaf_data) => {
                let spec_name = leaf_name(leaf_data.dpu_machine_id);

                let leaf_api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                let mut updated_leaf = leaf_api.get(&spec_name).await?;
                updated_leaf.spec.host_admin_i_ps = leaf_data.host_admin_i_ps;

                log::info!("UpdateLeaf - {updated_leaf:?}");

                let result = leaf_api
                    .replace(&spec_name, &PostParams::default(), &updated_leaf)
                    .await;

                match result {
                    Ok(updated_leaf) => {
                        update_status(
                            &current_job,
                            3,
                            format!(
                                "Updating leaf in VPC {:?}, elapsed {:?}",
                                updated_leaf,
                                start_time.elapsed()
                            ),
                            TaskState::Finished,
                        )
                        .await;

                        log::info!("Updated leaf: {updated_leaf:?}");
                        let _ = current_job.complete().await.map_err(CarbideError::from);
                    }
                    Err(error) => {
                        log::error!("Error updating leaf: {error}");
                        update_status(
                            &current_job,
                            6,
                            format!(
                                "Unable to update resource, elapsed: {:?}",
                                start_time.elapsed()
                            ),
                            TaskState::Error(error.to_string()),
                        )
                        .await;
                    }
                }
            }
            VpcResourceActions::CreateResourceGroup(spec) => {
                create_resource_group_handler(current_job, spec, client).await?;
            }
            VpcResourceActions::UpdateResourceGroup(_spec) => {
                return Err(CarbideError::NotImplemented);
            }
            VpcResourceActions::DeleteResourceGroup(spec) => {
                delete_resource_group_handler(current_job, spec, client).await?;
            }
            VpcResourceActions::CreateManagedResource(spec) => {
                create_managed_resource_handler(current_job, spec, client, &handler_args).await?;
            }
            VpcResourceActions::UpdateManagedResource(_spec) => {
                return Err(CarbideError::NotImplemented);
            }
            VpcResourceActions::DeleteManagedResource(spec) => {
                delete_managed_resource_handler(current_job, spec, client).await?;
            }
        }
    }
    Ok(())
}
/*
kind: Leaf
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1","kind":"Leaf","metadata":{"annotations":{},"name":"rno1-m03-b19-cpu-05","namespace":"forge-system"},"spec":{"control":{"managementIP":"10.180.222.48","vendor":"cumulus"},"hostAdminIPs":{"pf0hpf":"10.180.124.8"},"hostInterfaces":{"rno1-m03-b19-cpu-05-en0":"pf0hpf","rno1-m03-b19-cpu-05-en1":"pf1hpf"}}}
  creationTimestamp: "2022-08-05T18:41:17Z"
  finalizers:
  - leaf.networkfabric.vpc.forge/finalizer
  generation: 6
  name: rno1-m03-b19-cpu-05
  namespace: forge-system
  resourceVersion: "31052364"
  uid: 19fb9c6a-8e6b-4484-af11-f304469e9090
spec:
  control:
    managementIP: 10.180.222.48
    vendor: cumulus
  hostAdminIPs:
    pf0hpf: 10.180.124.8
  hostInterfaces:
    rno1-m03-b19-cpu-05-en0: pf0hpf
    rno1-m03-b19-cpu-05-en1: pf1hpf
status:
  asn: 4240186200
  conditions:
  - lastTransitionTime: "2022-09-02T17:33:15Z"
    status: "True"
    type: Liveness
  hostAdminDHCPServer: 10.180.32.74
  hostAdminIPs:
    pf0hpf: 10.180.124.8
  loopbackIP: 10.180.96.235
*/

pub struct ConditionReadyMatcher {
    pub matched_name: String,
}

impl<R> Condition<R> for ConditionReadyMatcher
where
    R: VpcResource,
{
    fn matches_object(&self, obj: Option<&R>) -> bool {
        if let Some(vpc_resource) = obj.as_ref() {
            if let Some(name) = vpc_resource.vpc_resource_name() {
                if name.as_str() == self.matched_name.as_str() {
                    if let Some(status) = vpc_resource.status() {
                        return status.is_ready();
                    }
                }
            }
        }
        false
    }
}

fn _managed_resource_status_matcher(
    matched_rg_name: &str,
) -> impl Condition<resource_group::ResourceGroup> + '_ {
    ConditionReadyMatcher {
        matched_name: matched_rg_name.to_string(),
    }
}

pub async fn bgkubernetes_handler(
    kube_enabled: bool,
    api: Arc<dyn rpc::forge::forge_server::Forge>,
    pool: PgPool,
) -> CarbideResult<OwnedHandle> {
    log::info!("Starting Kubernetes handler.");
    let mut registry = JobRegistry::new(&[vpc_reconcile_handler]);
    registry.set_context(VpcReconcileHandlerArguments { kube_enabled, api });

    if kube_enabled {
        let client = Client::try_default().await?;
        let api_version = client.apiserver_version().await?;

        log::info!(
            "Kube API reachable. Kube Version info: {}",
            serde_json::json!(api_version)
        );
    }

    // This function should return ownedhandle. If ownedhandle is dropped, it will stop main event loop also.
    registry
        .runner(&pool)
        .set_concurrency(10, 20)
        .set_channel_names(&["vpc_reconcile_handler"])
        .run()
        .await
        .map_err(CarbideError::from)
}

/// Generates the kubernetes name of a Leaf CRD - based on the Forge dpu_machine_id
pub fn leaf_name(dpu_machine_id: uuid::Uuid) -> String {
    format!("{}.leaf", dpu_machine_id,)
}

/// Generates the kubernetes name of a ManagedResource CRD - based on the Forge instance_id and function_id
fn managed_resource_name(instance_id: uuid::Uuid, function_id: &InterfaceFunctionId) -> String {
    format!("{}.{}", instance_id, function_id.kube_representation(),)
}

pub async fn create_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: uuid::Uuid,
    dpu_machine_id: uuid::Uuid,
    network_config: Versioned<InstanceNetworkConfig>,
    ip_details: HashMap<Uuid, IpAddr>,
    instance_id: uuid::Uuid,
) -> CarbideResult<()> {
    let mut managed_resources = Vec::new();

    for iface in &network_config.interfaces {
        // find_by_segmentcan CAN return max two prefixes, one for ipv4 and another for ipv6
        // Ipv4 is needed for now.
        let prefix = NetworkPrefix::find_by_segment(
            &mut *txn,
            crate::db::UuidKeyedObjectFilter::One(iface.network_segment_id),
        )
        .await?
        .into_iter()
        .filter(|x| x.prefix.is_ipv4())
        .last()
        .ok_or_else(|| {
            CarbideError::GenericError(format!(
                "Counldn't find IPV4 NetworkPrefix for segment {}",
                iface.network_segment_id
            ))
        })?;

        let host_interface = Some(
            BlueFieldInterface::new(iface.function_id.clone()).leaf_interface_id(&dpu_machine_id),
        );

        let host_interface_ip = ip_details
            .get(&iface.network_segment_id)
            .map(|ip| ip.to_string());
        let managed_resource_spec = managed_resource::ManagedResourceSpec {
            state: None,
            dpu_i_ps: None,
            host_interface,
            host_interface_access: None,
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

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    VpcResourceActions::CreateManagedResource(ManagedResourceData::new(
        machine_id,
        dpu_machine_id,
        instance_id,
        network_config,
        Some(ip_details),
        managed_resources,
    ))
    .reconcile(db_conn)
    .await?;

    Ok(())
}

pub async fn delete_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: uuid::Uuid,
    dpu_machine_id: uuid::Uuid,
    network_config: Versioned<InstanceNetworkConfig>,
    instance_id: uuid::Uuid,
) -> CarbideResult<()> {
    let mut managed_resources = Vec::new();

    for iface in &network_config.interfaces {
        let managed_resource_spec = managed_resource::ManagedResourceSpec {
            state: None,
            dpu_i_ps: None,
            host_interface: None,
            host_interface_access: None,
            host_interface_ip: None,
            host_interface_mac: None,
            resource_group: None,
            r#type: None,
        };

        managed_resources.push(managed_resource::ManagedResource::new(
            &managed_resource_name(instance_id, &iface.function_id),
            managed_resource_spec,
        ));
    }
    log::info!(
        "DeleteManagedResource sent to kubernetes with data: {:?}, machine_id: {}",
        managed_resources,
        machine_id
    );

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    VpcResourceActions::DeleteManagedResource(ManagedResourceData::new(
        machine_id,
        dpu_machine_id,
        instance_id,
        network_config,
        None,
        managed_resources,
    ))
    .reconcile(db_conn)
    .await?;

    Ok(())
}

pub async fn create_resource_group(
    prefix: &NetworkPrefix,
    db_conn: &mut PgConnection,
    dhcp_server: Option<String>,
) -> CarbideResult<()> {
    let gateway = prefix.gateway.map(|x| x.ip().to_string());

    let (ip, prefix_length) = (
        Some(prefix.prefix.ip().to_string()),
        Some(prefix.prefix.prefix() as i32),
    );

    let resource_group_network = resource_group::ResourceGroupSpec {
        dhcp_server,
        fabric_ip_pool: None,
        network: Some(resource_group::ResourceGroupNetwork {
            gateway,
            ip,
            prefix_length,
        }),
        network_implementation_type: None,
        overlay_ip_pool: None,
        tenant_identifier: None,
    };

    let resource_group =
        resource_group::ResourceGroup::new(&prefix.id.to_string(), resource_group_network);

    log::info!("ResourceGroup sent to kubernetes: {:?}", resource_group);

    VpcResourceActions::CreateResourceGroup(resource_group)
        .reconcile(db_conn)
        .await?;

    Ok(())
}

pub async fn delete_resource_group(
    prefix: &NetworkPrefix,
    db_conn: &mut PgConnection,
) -> CarbideResult<()> {
    let gateway = prefix.gateway.map(|x| x.ip().to_string());

    let (ip, prefix_length) = (
        Some(prefix.prefix.ip().to_string()),
        Some(prefix.prefix.prefix() as i32),
    );

    let resource_group_network = resource_group::ResourceGroupSpec {
        dhcp_server: None,
        fabric_ip_pool: None,
        network: Some(resource_group::ResourceGroupNetwork {
            gateway,
            ip,
            prefix_length,
        }),
        network_implementation_type: None,
        overlay_ip_pool: None,
        tenant_identifier: None,
    };

    let resource_group =
        resource_group::ResourceGroup::new(&prefix.id.to_string(), resource_group_network);

    log::info!(
        "ResourceGroupDelete sent to kubernetes: {:?}",
        resource_group
    );

    VpcResourceActions::DeleteResourceGroup(resource_group)
        .reconcile(db_conn)
        .await?;

    Ok(())
}

// This function will create a background task under IPMI handler to reset machine.
// It will not reset machine immediately.
pub async fn power_reset_machine(machine_id: Uuid, pool: PgPool) -> CarbideResult<Uuid> {
    log::info!("Sending power reset command for machine: {}", machine_id);
    let mpr = MachinePowerRequest::new(machine_id, Operation::Reset, true);
    mpr.invoke_power_command(pool).await
}

pub async fn update_leaf(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    resource_leaf: VpcResourceLeaf,
    record: rpc::forge::DhcpRecord,
) -> CarbideResult<()> {
    let dpu_machine_id = *resource_leaf.id();

    let host_admin_ip_network = Ipv4Network::from_str(record.address.as_str())
        .map_err(|err| CarbideError::GenericError(err.to_string()))?;
    let host_admin_ip_address_string = host_admin_ip_network.ip().to_string();

    let host_admin_i_ps = Some(BTreeMap::from([(
        DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
        host_admin_ip_address_string,
    )]));

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;

    VpcResourceActions::UpdateLeaf(UpdateLeafData {
        dpu_machine_id,
        host_admin_i_ps,
    })
    .reconcile(db_conn)
    .await?;

    Ok(())
}
