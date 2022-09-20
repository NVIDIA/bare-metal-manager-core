use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

use chrono::DateTime;
use itertools::Itertools;
use kube::runtime::wait::{await_condition, Condition};
use kube::{
    api::{Api, PostParams, ResourceExt},
    Client,
};
use serde::{Deserialize, Serialize};
use sqlx;
use sqlx::PgConnection;
use sqlxmq::{job, CurrentJob, JobRegistry, OwnedHandle};
use uuid::Uuid;

use crate::bg::{CurrentState, Status, TaskState};
use crate::db::constants::FORGE_KUBE_NAMESPACE;
use crate::db::vpc_resource_leaf::VpcResourceLeaf;
use crate::vpc_resources::{leaf, managed_resource, resource_group};
use crate::{CarbideError, CarbideResult};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VpcResourceActions {
    CreateLeaf(leaf::Leaf),
    DeleteLeaf(leaf::Leaf),
    UpdateLeaf(leaf::Leaf),
    CreateResourceGroup(resource_group::ResourceGroup),
    UpdateResourceGroup(resource_group::ResourceGroup),
    DeleteResourceGroup(resource_group::ResourceGroup),
    CreateManagedResource(managed_resource::ManagedResource),
    UpdateManagedResource(managed_resource::ManagedResource),
    DeleteManagedResource(managed_resource::ManagedResource),
    StatusLeaf(leaf::Leaf, VpcResourceLeaf),
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

#[job(channel_name = "vpc_reconcile_handler")]
pub async fn vpc_reconcile_handler(
    mut current_job: CurrentJob,
    url: String,
    kube_enabled: bool,
) -> CarbideResult<()> {
    log::debug!("Kubernetes integration is: {}", kube_enabled);

    let state_pool = Db::new(&url).await?.0;
    let status_pool = Db::new(&url).await?.0;
    // Setup new pool for updating VPCResourceStateMachine
    //let state_pool = &current_job.pool().clone();
    let mut status_txn = state_pool.begin().await?;

    // Prepare transactions state handling
    //let mut state_txn = state_pool.begin().await?;

    update_status(&current_job, 1, "Started".to_string(), TaskState::Started).await;

    let _vpc_status_db_connection = status_pool.acquire().await?;

    // Retrieve job payload as JSON
    let data: Option<String> = current_job.json()?;

    log::debug!("JOB DEFINITION: {:?}", &data);

    // Parse payload as JSON into VpcResource
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
                let mut state_txn = state_pool.begin().await?;
                let mut vpc_txn = state_pool.begin().await?;
                //let status_txn = state_pool.begin().await?;

                let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);

                let spec_name = spec.name().to_string();
                // Kube CRD names are strings, so we have to convert from string to uuid::Uuid
                let vpc_id = Uuid::from_str(spec_name.as_str())?;

                let mut vpc_db_resource = VpcResourceLeaf::find(&mut vpc_txn, vpc_id).await?;

                // Set transaction to Advance VpcResourceStateMachine to Submitting
                vpc_db_resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Submit)
                    .await?;

                state_txn.commit().await?; // advance transaction

                let mut new_txn = state_pool.begin().await?;

                let result = leafs.create(&PostParams::default(), &spec).await;
                match result {
                    Ok(new_leaf) => {
                        // After job is marked as complete move VpcResourceStateMachine to accepted
                        // and commit transaction
                        vpc_db_resource
                            .advance(&mut status_txn, &rpc::VpcResourceStateMachineInput::Accept)
                            .await?;
                        new_txn.commit().await?;
                        let mut last_txn = state_pool.begin().await?;

                        log::info!("Created VPC Object {} ({:?})", new_leaf.name(), new_leaf);

                        update_status(
                            &current_job,
                            2,
                            "VPC Leaf object created, waiting for status object".to_string(),
                            TaskState::Ongoing,
                        )
                        .await;

                        let api: Api<leaf::Leaf> = Api::all(client);
                        let waiter = await_condition(
                            api,
                            spec_name.as_str(),
                            leaf_status_matcher(spec_name.as_str()),
                        );
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(60 * 5), waiter)
                                .await
                                .map(|result| result.map_err(CarbideError::from))?;
                        let newly_created_leaf = leafs.get_status(&spec.name()).await?;

                        log::info!("VPC Status Object: {:?}", newly_created_leaf.status);
                        update_status(
                            &current_job,
                            2,
                            "VPC Leaf status object retrieved".to_string(),
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
                            format!("{} Creation completed", new_leaf.name()),
                            TaskState::Finished,
                        )
                        .await;

                        let _ = current_job.complete().await.map_err(CarbideError::from);
                    }
                    Err(error) => {
                        update_status(
                            &current_job,
                            6,
                            "Unable to create resource".to_string(),
                            TaskState::Error(error.to_string()),
                        )
                        .await;
                        // If error move VpcResourceStateMachine to Fail and commit txn
                        vpc_db_resource
                            .advance(&mut new_txn, &rpc::VpcResourceStateMachineInput::Fail)
                            .await?;
                        new_txn.commit().await?;
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
                    format!("VPC Resource {} deleted", spec.name()),
                    TaskState::Finished,
                )
                .await;
                let _ = current_job.complete().await.map_err(CarbideError::from);
            }
            VpcResourceActions::UpdateLeaf(spec) => {
                let spec_name = spec.name().to_string();

                log::info!("UpdateLeaf spec - {spec_name} {spec:?}");

                let mut new_spec = spec;

                let api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                let leaf_to_find = api.get(&spec_name).await?;

                log::info!("leaf_to_find leaf - {leaf_to_find:?}");

                let mut state_txn = state_pool.begin().await?;

                let vpc_id = Uuid::from_str(&spec_name)?;
                let vpc_db_resource = VpcResourceLeaf::find(&mut state_txn, vpc_id).await?;

                let resource_version = leaf_to_find.metadata.resource_version;

                //TODO: make it so that we don't have to manage resource lifetimes out here
                vpc_db_resource
                    .advance(
                        &mut state_txn,
                        &rpc::VpcResourceStateMachineInput::Initialize,
                    )
                    .await?;
                vpc_db_resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Submit)
                    .await?;

                // Updates must contain the most recent observed version
                new_spec.metadata.resource_version = resource_version;

                log::info!("UpdateLeaf new_spec - {new_spec:?}");

                let result = api
                    .replace(&spec_name, &PostParams::default(), &new_spec)
                    .await?;

                update_status(
                    &current_job,
                    3,
                    format!("Leaf Updated {result:?}"),
                    TaskState::Finished,
                )
                .await;

                let _ = current_job.complete().await.map_err(CarbideError::from);
            }
            VpcResourceActions::CreateResourceGroup(_spec) => {
                todo!()
            }
            VpcResourceActions::UpdateResourceGroup(_spec) => {
                todo!()
            }
            VpcResourceActions::DeleteResourceGroup(_spec) => {
                todo!()
            }
            VpcResourceActions::CreateManagedResource(_spec) => {
                todo!()
            }
            VpcResourceActions::UpdateManagedResource(_spec) => {
                todo!()
            }
            VpcResourceActions::DeleteManagedResource(_spec) => {}
            VpcResourceActions::StatusLeaf(spec, resource) => {
                let mut state_txn = state_pool.begin().await?;

                update_status(
                    &current_job,
                    1,
                    format!("Started status job for VPC Leaf {}", spec.name()).to_string(),
                    TaskState::Started,
                )
                .await;

                let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);
                let mut leaf_to_status = leafs.get_status(spec.name().as_ref()).await?;

                update_status(
                    &current_job,
                    2,
                    format!("Waiting for status from VPC Leaf {}", spec.name()).to_string(),
                    TaskState::Ongoing,
                )
                .await;

                resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Wait)
                    .await?;
                state_txn.commit().await?;

                let mut new_txn = state_pool.begin().await?;

                loop {
                    if leaf_to_status.status.is_some() {
                        log::info!("Status CRD for LeafSpec {}", spec.name());
                        break;
                    }
                    log::info!(
                        "Received status for LeafSpec {} ---- {:?}",
                        spec.name(),
                        leaf_to_status.status
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    leaf_to_status = leafs.get_status(spec.name().as_ref()).await?;
                }

                /*            while leaf_to_status.status.is_none() {
                                log::debug!("Waiting for status from VPC Resource: {}", spec.name());
                                tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

                                update_status(
                                    &current_job,
                                    6,
                                    "Unable to create resource".to_string(),
                                    TaskState::Error("Timeout reached".to_string()),
                                )
                                .await;
                                // If error move VpcResourceStateMachine to Fail and commit txn
                                resource
                                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Fail)
                                    .await?;

                                state_txn.begin().await?;
                                let _ = current_job.complete().await.map_err(CarbideError::from);
                            }
                */
                log::debug!("Status for VPC Resource: {} received", spec.name());
                log::debug!(
                    "Status for VPC Resource is -------------- {:?}",
                    spec.status
                );
                resource
                    .advance(&mut new_txn, &rpc::VpcResourceStateMachineInput::VpcSuccess)
                    .await?;
                new_txn.commit().await?;
                //resource.advance()
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

fn leaf_status_matcher(matched_leaf_name: &str) -> impl Condition<leaf::Leaf> + '_ {
    move |obj: Option<&leaf::Leaf>| {
        if let Some(leaf) = obj.as_ref() {
            if let Some(name) = leaf.metadata.name.as_ref() {
                if name == matched_leaf_name {
                    // we have the right leaf, now we can check the condition
                    if let Some(status) = leaf.status.as_ref() {
                        if let Some(conditions) = status.conditions.as_ref() {
                            let latest_condition = conditions
                                .iter()
                                .sorted_by_key(|condition_to_be_sorted| {
                                    if let Some(time_stamp) =
                                        condition_to_be_sorted.last_transition_time.as_ref()
                                    {
                                        if let Ok(duration) = chrono::DateTime::parse_from_rfc3339(
                                            time_stamp.as_str(),
                                        ) {
                                            duration
                                                .signed_duration_since(
                                                    DateTime::<chrono::Utc>::from(
                                                        SystemTime::UNIX_EPOCH,
                                                    ),
                                                )
                                                .num_milliseconds()
                                                as u64
                                        } else {
                                            0
                                        }
                                    } else {
                                        0
                                    }
                                })
                                .last();

                            // now that we have the most recent timestamp,
                            // validate that it is "ready" and that the host_admin_IP field is populated with something.
                            if let Some(condition) = latest_condition {
                                if let Some(condition_status) = condition.status.as_ref() {
                                    if condition_status.to_lowercase().as_str() != "true" {
                                        return false;
                                    }

                                    return status.host_admin_i_ps.is_some();
                                }
                            }
                        }
                    }
                }
            }
        }
        false
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
        .run()
        .await
        .map_err(CarbideError::from)
}
