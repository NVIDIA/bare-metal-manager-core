use std::str::FromStr;

use kube::{
    api::{Api, PostParams, ResourceExt},
    Client,
};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx;
use sqlx::PgConnection;
use sqlxmq::{CurrentJob, job, JobRegistry, OwnedHandle};
use uuid::Uuid;

use crate::{CarbideError, CarbideResult};
use crate::bg::{CurrentState, Status, TaskState};
use crate::db::vpc_resource_leaf::VpcResourceLeaf;
use crate::vpc_resources::{leaf, managed_resource, resource_group};

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

        info!("Job definition {}", &json);

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
    let namespace = "forge-system";

    let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);
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
            error!("Status update failed. Error: {:?}", x)
        }
    }
}

#[job(channel_name = "vpc_reconcile_handler")]
pub async fn vpc_reconcile_handler(
    mut current_job: CurrentJob,
    url: String,
    kube_enabled: bool,
) -> CarbideResult<()> {
    debug!("Kubernetes integration is: {}", kube_enabled);

    let state_pool = Db::new(&url).await?.0;
    let status_pool = Db::new(&url).await?.0;
    // Setup new pool for updating VPCResourceStateMachine
    //let state_pool = &current_job.pool().clone();
    let mut status_txn = state_pool.begin().await?;

    // Prepare transactions state handling
    //let mut state_txn = state_pool.begin().await?;

    update_status(&current_job, 1, "Started".to_string(), TaskState::Started).await;

    let mut vpc_status_db_connection = status_pool.acquire().await?;

    // Retrieve job payload as JSON
    let data: Option<String> = current_job.json()?;

    debug!("JOB DEFINITION: {:?}", &data);

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

    info!("Kubernetes integration is: {}", kube_enabled);

    if kube_enabled {
        let client = Client::try_default().await?;
        let namespace = "forge-system";

        match vpc_resource {
            VpcResourceActions::CreateLeaf(spec) => {
                let mut state_txn = state_pool.begin().await?;
                let mut vpc_txn = state_pool.begin().await?;
                //let status_txn = state_pool.begin().await?;

                let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);

                // Kube CRD names are strings, so we have to convert from string to uuid::Uuid
                let vpc_id = uuid::Uuid::from_str(&spec.name())?;

                let vpc_db_resource = VpcResourceLeaf::find(&mut vpc_txn, vpc_id).await?;

                // Set transaction to Advance VpcResourceStateMachine to Submitting
                vpc_db_resource
                    .advance(&mut state_txn, &rpc::VpcResourceStateMachineInput::Submit)
                    .await?;

                state_txn.commit().await?; // advance transaction

                let mut new_txn = state_pool.begin().await?;

                let result = leafs.create(&PostParams::default(), &spec).await;
                match result {
                    Ok(s) => {
                        update_status(
                            &current_job,
                            4,
                            format!("{} Created", s.name()),
                            TaskState::Finished,
                        )
                            .await;

                        let _ = current_job.complete().await.map_err(CarbideError::from);
                        // After job is marked as complete move VpcResourceStateMachine to accepted
                        // and commit transaction
                        vpc_db_resource
                            .advance(&mut status_txn, &rpc::VpcResourceStateMachineInput::Accept)
                            .await?;
                        new_txn.commit().await?;
                        // Spawn another background job to watch status
                        VpcResourceActions::StatusLeaf(s, vpc_db_resource)
                            .reconcile(vpc_status_db_connection.as_mut())
                            .await?;
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
                let vpc_id = uuid::Uuid::from_str(&spec.name())?;
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
            VpcResourceActions::UpdateLeaf(_spec) => {
                todo!()
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
                        info!("Status CRD for LeafSpec {}", spec.name());
                        break;
                    }
                    info!(
                        "Received status for LeafSpec {} ---- {:?}",
                        spec.name(),
                        leaf_to_status.status
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    leaf_to_status = leafs.get_status(spec.name().as_ref()).await?;
                }

                /*            while leaf_to_status.status.is_none() {
                                debug!("Waiting for status from VPC Resource: {}", spec.name());
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
                debug!("Status for VPC Resource: {} received", spec.name());
                debug!(
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

pub async fn bgkubernetes_handler(url: String, kube_enabled: bool) -> CarbideResult<OwnedHandle> {
    info!("Starting Kubernetes handler.");
    let mut registry = JobRegistry::new(&[vpc_reconcile_handler]);

    registry.set_context(url.clone());
    registry.set_context(kube_enabled);

    //let new_pool = pool;
    let new_pool = Db::new(url.clone().as_ref()).await?.0;

    if kube_enabled {
        let client = Client::try_default().await?;
        let api_version = client.apiserver_version().await?;

        info!(
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
