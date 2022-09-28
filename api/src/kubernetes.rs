use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

use chrono::DateTime;
use itertools::Itertools;
use kube::runtime::wait::{await_condition, Condition};
use kube::{
    api::{Api, DeleteParams, PostParams, ResourceExt},
    Client,
};
use serde::{Deserialize, Serialize};
use sqlx;
use sqlx::{Acquire, PgConnection, Postgres};
use sqlxmq::{job, CurrentJob, JobRegistry, OwnedHandle};
use uuid::Uuid;

use crate::bg::{CurrentState, Status, TaskState};
use crate::db::constants::FORGE_KUBE_NAMESPACE;
use crate::db::network_prefix::NetworkPrefix;
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
}

#[derive(Debug, Clone)]
pub enum Operation {
    Create,
    Update,
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
            .set_retry_backoff(std::time::Duration::from_secs(60))
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

async fn create_resource_group_handler(
    mut current_job: CurrentJob,
    spec: resource_group::ResourceGroup,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();
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
                1,
                format!("ResourceGroup creation {} is successful.", spec.name()),
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
                    "ResourceGroup creation {} failed. Error: {}",
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

async fn delete_resource_group_handler(
    mut current_job: CurrentJob,
    spec: resource_group::ResourceGroup,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();

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
                format!("ResourceGroup deletion {} is successful.", spec.name()),
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
                    "ResourceGroup deletion {} failed. Error: {}",
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

async fn create_managed_resource_handler(
    mut current_job: CurrentJob,
    spec: managed_resource::ManagedResource,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();
    log::info!("Creating resource_group with name {}.", spec_name);

    update_status(
        &current_job,
        0,
        format!("Creating managed_resource with name {}", spec_name),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<managed_resource::ManagedResource> =
        Api::namespaced(client, FORGE_KUBE_NAMESPACE);
    let result = resource.create(&PostParams::default(), &spec).await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                1,
                format!("ManagedResource creation {} is successful.", spec.name()),
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
                    "ManagedResource creation {} failed. Error: {}",
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

async fn delete_managed_resource_handler(
    mut current_job: CurrentJob,
    spec: managed_resource::ManagedResource,
    client: Client,
) -> CarbideResult<()> {
    let spec_name = spec.name().to_string();
    log::info!("Deleting resource_group with name {}.", spec_name);

    update_status(
        &current_job,
        0,
        format!("Deleting managed_resource with name {}", spec_name),
        TaskState::Ongoing,
    )
    .await;

    let resource: Api<managed_resource::ManagedResource> =
        Api::namespaced(client, FORGE_KUBE_NAMESPACE);
    let result = resource.delete(&spec_name, &DeleteParams::default()).await;

    match result {
        Ok(_) => {
            update_status(
                &current_job,
                1,
                format!("ManagedResource deletion {} is successful.", spec.name()),
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
                    "ManagedResource deletion {} failed. Error: {}",
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
                            "VPC Leaf object created, waiting for status object".to_string(),
                            TaskState::Ongoing,
                        )
                        .await;

                        let api: Api<leaf::Leaf> = Api::namespaced(client, FORGE_KUBE_NAMESPACE);
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

                        let mut last_txn = current_job.pool().begin().await?;

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
                        log::info!("Jobs done - {}", &current_job.id())
                    }

                    Err(error) => {
                        log::error!("error : {error:?}");
                        update_status(
                            &current_job,
                            6,
                            "Unable to create resource".to_string(),
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
                    format!("VPC Resource {} deleted", spec.name()),
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
                            format!("Updating leaf in VPC {:?}", updated_leaf),
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
                            "Unable to update resource".to_string(),
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
                todo!()
            }
            VpcResourceActions::DeleteResourceGroup(spec) => {
                delete_resource_group_handler(current_job, spec, client).await?;
            }
            VpcResourceActions::CreateManagedResource(spec) => {
                create_managed_resource_handler(current_job, spec, client).await?;
            }
            VpcResourceActions::UpdateManagedResource(mut new_spec) => {
                let spec_name = new_spec.name().to_string();

                log::info!("UpdateManagedResource spec - {spec_name} {new_spec:?}");

                let mr_api: Api<managed_resource::ManagedResource> =
                    Api::namespaced(client, FORGE_KUBE_NAMESPACE);
                let original_mr = mr_api.get(&spec_name).await?;

                log::info!("leaf_to_find leaf - {original_mr:?}");

                let resource_version = original_mr.resource_version();

                // Updates must contain the most recent observed version
                new_spec.metadata.resource_version = resource_version;

                log::info!("ManagedResource new_spec - {new_spec:?}");

                let result = mr_api
                    .replace(&spec_name, &PostParams::default(), &new_spec)
                    .await;

                match result {
                    Ok(updated_leaf) => {
                        update_status(
                            &current_job,
                            3,
                            format!("Updated leaf in VPC {:?}", updated_leaf),
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
                            "Unable to update resource".to_string(),
                            TaskState::Error(error.to_string()),
                        )
                        .await;
                    }
                }
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

pub async fn create_or_update_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    segment_id: uuid::Uuid,
    host_interface: Option<String>,
    managed_resource_name: String,
    host_interface_ip: Option<String>,
    operation: Operation,
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
        "ManagedResource sent to kubernetes with data: {:?}, Opeartion: {:?}",
        managed_resource,
        operation
    );

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    match operation {
        Operation::Create => {
            VpcResourceActions::CreateManagedResource(managed_resource)
                .reconcile(db_conn)
                .await?;
        }
        Operation::Update => {
            VpcResourceActions::UpdateManagedResource(managed_resource)
                .reconcile(db_conn)
                .await?;
        }
    };

    Ok(())
}

pub async fn delete_managed_resource(
    txn: &mut sqlx::Transaction<'_, Postgres>,
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
        "DeleteManagedResource sent to kubernetes with data: {:?}",
        managed_resource
    );

    let db_conn = txn.acquire().await.map_err(CarbideError::from)?;
    VpcResourceActions::DeleteManagedResource(managed_resource)
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
