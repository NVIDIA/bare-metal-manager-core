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
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use kube::api::ListParams;
use kube::runtime::wait::{await_condition, Condition};
use kube::{
    api::{Api, DeleteParams, PostParams, ResourceExt},
    Client,
};
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
use crate::model::instance::config::network::InterfaceFunctionId;
use crate::vpc_resources::{
    leaf, managed_resource, resource_group, BlueFieldInterface, VpcResource, VpcResourceStatus,
};
use crate::{CarbideError, CarbideResult};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManagedResourceData {
    machine_id: uuid::Uuid,
    mr: managed_resource::ManagedResource,
}

impl ManagedResourceData {
    pub fn new(machine_id: uuid::Uuid, mr: managed_resource::ManagedResource) -> Self {
        ManagedResourceData { machine_id, mr }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VpcResourceActions {
    CreateLeaf(leaf::Leaf),
    DeleteLeaf(leaf::Leaf),
    UpdateLeaf(leaf::Leaf),
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
    log::info!("Current status: {}, checkpoint: {}", msg, checkpoint);
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
                if let Some(network_fabric) = status.fabric_network_configuration.as_ref() {
                    if let Some(vlanid) = network_fabric.vlan_id {
                        let mut txn = current_job.pool().begin().await?;
                        NetworkPrefix::update_vlan_id(
                            &mut txn,
                            Uuid::try_from(spec_name.as_str())?,
                            vlanid,
                        )
                        .await?;
                        txn.commit().await?;
                    }
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
) -> CarbideResult<()> {
    let spec = data.mr;
    let spec_name = spec.name().to_string();
    let start_time = Instant::now();
    log::info!("Creating resource_group with name {}.", spec_name);

    update_status(
        &current_job,
        0,
        format!("Creating managed_resource with name {}", spec_name),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<managed_resource::ManagedResource> =
        Api::namespaced(client.clone(), FORGE_KUBE_NAMESPACE);
    let result = resource.create(&PostParams::default(), &spec).await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                1,
                format!(
                    "ManagedResource creation {} is successful after {:?}.",
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
                    CarbideError::TokioTimeoutError("creating managed resource group".to_string())
                })?;

            update_status(
                &current_job,
                2,
                format!(
                    "ManagedResource created {} on vpc after {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Ongoing,
            )
            .await;

            let task_id = power_reset_machine(data.machine_id, current_job.pool().clone()).await?;
            update_status(
                &current_job,
                3,
                format!(
                    "Machine reset task spawned for machine_id {} with task: {} after duration {:?}",
                    data.machine_id, task_id, start_time.elapsed(),
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
                4,
                format!(
                    "ManagedResource creation {} failed. Error: {:?} Duration: {:?}",
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

async fn delete_managed_resource_handler(
    mut current_job: CurrentJob,
    data: ManagedResourceData,
    client: Client,
) -> CarbideResult<()> {
    let spec = data.mr;
    let spec_name = spec.name().to_string();
    let start_time = Instant::now();
    log::info!("Deleting resource_group with name {}.", spec_name);

    update_status(
        &current_job,
        0,
        format!(
            "Deleting managed_resource with name {} elapsed: {:?}",
            spec_name,
            start_time.elapsed()
        ),
        TaskState::Ongoing,
    )
    .await;

    let resource_api: Api<managed_resource::ManagedResource> =
        Api::namespaced(client.clone(), FORGE_KUBE_NAMESPACE);
    let managed_resource = resource_api.get(&spec_name).await?;
    let mac = managed_resource
        .spec
        .host_interface
        .ok_or(CarbideError::NotFoundError(data.machine_id))?;
    let leaf_name = find_leaf_with_host_interface(&mac, client.clone()).await?;
    let result = resource_api
        .delete(&spec_name, &DeleteParams::default())
        .await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                1,
                format!(
                    "ManagedResource deletion {} is successful, elapsed: {:?}.",
                    spec.name(),
                    start_time.elapsed()
                ),
                TaskState::Ongoing,
            )
            .await;

            // In case leaf is not found (although it should never happen), machine will stuck in
            // boot loop. This is only possible due to misconfiguration. Do not return failure
            // as MR is already deleted.
            // TODO: Machine should be moved to FAILED state.
            if let Some(leaf_name) = leaf_name {
                let api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                let waiter = await_condition(
                    api,
                    spec_name.as_str(),
                    ConditionReadyMatcher {
                        matched_name: leaf_name.clone(),
                    },
                );
                let _ = tokio::time::timeout(std::time::Duration::from_secs(60 * 5), waiter)
                    .await
                    .map_err(|_elapsed_error| {
                        CarbideError::TokioTimeoutError(
                            "deleting managed resource group".to_string(),
                        )
                    })?;
                update_status(
                    &current_job,
                    2,
                    format!(
                        "ManagedResource deletion {} successful and hbn is configured with admin network, elapsed: {:?}.",
                        spec.name(),
                        start_time.elapsed(),
                    ),
                    TaskState::Ongoing,
                )
                .await;
            }

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
        Err(err) => {
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
            Err(CarbideError::GenericError(err.to_string()))
        }
    }
}

#[job(channel_name = "vpc_reconcile_handler")]
pub async fn vpc_reconcile_handler(
    mut current_job: CurrentJob,
    url: String,
    kube_enabled: bool,
) -> CarbideResult<()> {
    log::debug!("Kubernetes integration is: {}", kube_enabled);

    let state_pool = Db::new(&url).await?.0;
    let status_pool = Db::new(&url).await?.0;
    let start_time = Instant::now();

    let _vpc_status_db_connection = status_pool.acquire().await?;

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

    log::info!("Kubernetes integration is: {}", kube_enabled);

    if kube_enabled {
        let client = Client::try_default().await?;
        let namespace = FORGE_KUBE_NAMESPACE;

        match vpc_resource {
            VpcResourceActions::CreateLeaf(spec) => {
                let mut vpc_txn = state_pool.begin().await?;
                //let status_txn = state_pool.begin().await?;

                let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);

                let spec_name = spec.name().to_string();
                // Kube CRD names are strings, so we have to convert from string to uuid::Uuid
                let vpc_id = Uuid::from_str(spec_name.as_str())?;

                let mut vpc_db_resource = VpcResourceLeaf::find(&mut vpc_txn, vpc_id).await?;

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
            VpcResourceActions::DeleteLeaf(spec) => {
                let mut state_txn = state_pool.begin().await?;
                let vpc_id = Uuid::from_str(&spec.name())?;
                let vpc_db_resource = VpcResourceLeaf::find(&mut state_txn, vpc_id).await?;

                vpc_db_resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Submit)
                    .await?;
                state_txn.commit().await?;

                update_status(
                    &current_job,
                    4,
                    format!(
                        "VPC Resource {} deleted, elapsed {:?}",
                        spec.name(),
                        start_time.elapsed()
                    ),
                    TaskState::Finished,
                )
                .await;
                let _ = current_job.complete().await.map_err(CarbideError::from);
            }
            VpcResourceActions::UpdateLeaf(mut new_spec) => {
                let spec_name = new_spec.name().to_string();

                log::info!("UpdateLeaf spec - {spec_name} {new_spec:?}");

                let leaf_api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                let original_leaf = leaf_api.get(&spec_name).await?;

                log::info!("leaf_to_find leaf - {original_leaf:?}");

                let resource_version = original_leaf.resource_version();

                // Updates must contain the most recent observed version
                new_spec.metadata.resource_version = resource_version;

                log::info!("UpdateLeaf new_spec - {new_spec:?}");

                let result = leaf_api
                    .replace(&spec_name, &PostParams::default(), &new_spec)
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
                create_managed_resource_handler(current_job, spec, client).await?;
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

pub async fn bgkubernetes_handler(url: String, kube_enabled: bool) -> CarbideResult<OwnedHandle> {
    log::info!("Starting Kubernetes handler.");
    let mut registry = JobRegistry::new(&[vpc_reconcile_handler]);

    registry.set_context(url.clone());
    registry.set_context(kube_enabled);

    //let new_pool = pool;
    let new_pool = Db::new(url.clone().as_ref()).await?.0;

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
        .runner(&new_pool)
        .set_concurrency(10, 20)
        .set_channel_names(&["vpc_reconcile_handler"])
        .run()
        .await
        .map_err(CarbideError::from)
}

pub async fn create_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,
    dpu_machine_id: uuid::Uuid,
    managed_resource_name: String,
    host_interface_ip: Option<String>,
) -> CarbideResult<()> {
    // find_by_segmentcan return max two prefixes, one for ipv4 and another for ipv6
    // Ipv4 is needed for now.
    let prefix = NetworkPrefix::find_by_segment(
        &mut *txn,
        crate::db::UuidKeyedObjectFilter::One(segment_id),
    )
    .await?
    .into_iter()
    .filter(|x| x.prefix.is_ipv4())
    .last()
    .ok_or_else(|| {
        CarbideError::GenericError(format!(
            "Counldn't find IPV4 NetworkPrefix for segment {}",
            segment_id
        ))
    })?;

    // This only handles PF for now.
    let host_interface = Some(
        BlueFieldInterface::new(InterfaceFunctionId::PhysicalFunctionId {})
            .leaf_interface_id(&dpu_machine_id),
    );

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

    let managed_resource =
        managed_resource::ManagedResource::new(&managed_resource_name, managed_resource_spec);

    log::info!(
        "ManagedResource sent to kubernetes with data: {:?}",
        managed_resource,
    );

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    VpcResourceActions::CreateManagedResource(ManagedResourceData::new(
        machine_id,
        managed_resource,
    ))
    .reconcile(db_conn)
    .await?;

    Ok(())
}

pub async fn delete_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: uuid::Uuid,
    managed_resource_name: String,
) -> CarbideResult<()> {
    // find_by_segmentcan return max two prefixes, one for ipv4 and another for ipv6
    // Ipv4 is needed for now.
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

    let managed_resource =
        managed_resource::ManagedResource::new(&managed_resource_name, managed_resource_spec);

    log::info!(
        "DeleteManagedResource sent to kubernetes with data: {:?}, machine_id: {}",
        managed_resource,
        machine_id
    );

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    VpcResourceActions::DeleteManagedResource(ManagedResourceData::new(
        machine_id,
        managed_resource,
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
