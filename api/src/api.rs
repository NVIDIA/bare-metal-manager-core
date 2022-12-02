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
use std::convert::TryFrom;
use std::env;
use std::sync::Arc;

use color_eyre::Report;
use lru::LruCache;
use mac_address::MacAddress;
use once_cell::sync::Lazy;
use sqlx::Acquire;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder;

use crate::{
    auth::CarbideAuth,
    cfg,
    credentials::UpdateCredentials,
    db::{
        auth::SshKeyValidationRequest,
        domain::Domain,
        domain::NewDomain,
        dpu_machine::DpuMachine,
        instance::{
            config::network::load_instance_network_config,
            status::network::update_instance_network_status_observation, DeleteInstance, Instance,
        },
        instance_type::{DeactivateInstanceType, NewInstanceType, UpdateInstanceType},
        ipmi::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_state::MachineState,
        machine_topology::MachineTopology,
        network_prefix::NetworkPrefix,
        network_segment::{NetworkSegment, NewNetworkSegment},
        resource_record::DnsQuestion,
        tags::{Tag, TagAssociation, TagCreate, TagDelete, TagsList},
        vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc},
        UuidKeyedObjectFilter,
    },
    dhcp_discover::RecordCacheEntry,
    instance::{allocate_instance, InstanceAllocationRequest},
    ipmi::{ipmi_handler, MachinePowerRequest, RealIpmiCommandHandler},
    kubernetes::{
        bgkubernetes_handler, create_resource_group, delete_managed_resource, delete_resource_group,
    },
    machine_state_controller::{
        controller::MachineStateController,
        snapshot_loader::{DbSnapshotLoader, InstanceSnapshotLoader},
        state_handler::RealMachineStateHandler,
    },
    model::{
        hardware_info::HardwareInfo, instance::status::network::InstanceNetworkStatusObservation,
    },
    CarbideError,
};
pub use ::rpc::forge as rpc;
use ::rpc::forge::InstanceList;
use ::rpc::forge::{MachineCredentialsUpdateRequest, MachineCredentialsUpdateResponse};
use ::rpc::MachineStateMachineInput;
use forge_credentials::CredentialProvider;

use self::rpc::forge_server::Forge;

pub struct ExternalConfig {
    pub dhcp_server: Option<String>,
}
pub static CONFIG: Lazy<RwLock<ExternalConfig>> =
    Lazy::new(|| RwLock::new(ExternalConfig { dhcp_server: None }));

pub struct Api<C: CredentialProvider> {
    database_connection: sqlx::PgPool,
    credential_provider: Arc<C>,
    dhcp_discovery_cache: Mutex<LruCache<MacAddress, RecordCacheEntry>>,
}

#[tonic::async_trait]
impl<C> Forge for Api<C>
where
    C: CredentialProvider + 'static,
{
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewDomain::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?);
        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::Domain { id, name, .. } = request.into_inner();

        // TODO(jdg): Move this out into a function and share it with delete
        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::not_found(
                    "No domain object found matching requested UUID".to_string(),
                ));
            }
        };

        let mut domains = Domain::find(&mut txn, uuid).await?;

        let mut dom = match domains.len() {
            0 => return Err(Status::not_found("domain not found")),
            1 => domains.remove(0),
            _ => {
                return Err(Status::internal(
                    "Found more than one domain with the specified UUID",
                ))
            }
        };

        dom.name = name;
        let response = Ok(dom
            .update(&mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_domain(
        &self,
        request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::DomainDeletion { id, .. } = request.into_inner();

        // load from find from domain.rs
        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("No UUID provided".to_string()));
            }
        };

        let mut domains = Domain::find(&mut txn, uuid).await?;

        let dom = match domains.len() {
            0 => return Err(Status::not_found("domain not found")),
            1 => domains.remove(0),
            _ => {
                return Err(Status::internal(
                    "Found more than one domain with the specified UUID",
                ))
            }
        };

        // TODO: This needs to validate that nothing references the domain anymore
        // (like NetworkSegments)

        let response = Ok(dom
            .delete(&mut txn)
            .await
            .map(|_| rpc::DomainDeletionResult {})
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_domain(
        &self,
        request: Request<rpc::DomainSearchQuery>,
    ) -> Result<Response<rpc::DomainList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::DomainSearchQuery { id, name, .. } = request.into_inner();
        let domains = match (id, name) {
            (Some(id), _) => {
                let id = id;
                let uuid = match uuid::Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Invalid UUID supplied: {}",
                            err
                        )));
                    }
                };
                Domain::find(&mut txn, uuid).await
            }
            (None, Some(name)) => Domain::find_by_name(&mut txn, name).await,
            (None, None) => Domain::find(&mut txn, UuidKeyedObjectFilter::All).await,
        };

        let result = domains
            .map(|domain| rpc::DomainList {
                domains: domain.into_iter().map(rpc::Domain::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_vpc(
        &self,
        request: Request<rpc::VpcCreationRequest>,
    ) -> Result<Response<rpc::Vpc>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewVpc::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::Vpc::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_vpc(
        &self,
        request: Request<rpc::VpcUpdateRequest>,
    ) -> Result<Response<rpc::VpcUpdateResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        UpdateVpc::try_from(request.into_inner())?
            .update(&mut txn)
            .await?;

        txn.commit().await.map_err(CarbideError::from)?;

        Ok(Response::new(rpc::VpcUpdateResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_vpc(
        &self,
        request: Request<rpc::VpcDeletionRequest>,
    ) -> Result<Response<rpc::VpcDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        // TODO: This needs to validate that nothing references the VPC anymore
        // (like NetworkSegments)

        let response = Ok(DeleteVpc::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map(rpc::VpcDeletionResult::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

        let vpcs = match (id, name) {
            (Some(id), _) => {
                let id = id;
                let uuid = match uuid::Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Supplied invalid UUID: {}",
                            err
                        )));
                    }
                };
                Vpc::find(&mut txn, uuid).await
            }
            (None, Some(name)) => Vpc::find_by_name(&mut txn, name).await,
            (None, None) => Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await,
        };

        let result = vpcs
            .map(|vpc| rpc::VpcList {
                vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_network_segments(
        &self,
        request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        log::debug!("Fetching database transaction");

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::NetworkSegmentQuery { id, .. } = request.into_inner();

        let uuid_filter = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => UuidKeyedObjectFilter::All,
        };

        let results = NetworkSegment::find(&mut txn, uuid_filter).await?;
        let mut network_segments = Vec::with_capacity(results.len());

        for result in results {
            network_segments.push(result.try_into()?);
        }
        Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentCreationRequest>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = NewNetworkSegment::try_from(request.into_inner())?
            .persist(&mut txn)
            .await;

        let dhcp_server = CONFIG.read().await.dhcp_server.clone();
        let db_conn = txn.acquire().await.map_err(CarbideError::from)?;

        if let Ok(segment) = response.as_ref() {
            for prefix in &segment.prefixes {
                create_resource_group(prefix, db_conn, dhcp_server.clone()).await?;
            }
        }

        let response = Ok(Response::new(response?.try_into()?));
        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn update_network_segment(
        &self,
        _request: Request<rpc::NetworkSegmentUpdateRequest>,
    ) -> Result<Response<rpc::NetworkSegmentUpdateResult>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentDeletionRequest>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::NetworkSegmentDeletionRequest { id, .. } = request.into_inner();

        let uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("No UUID provided".to_string()));
            }
        };

        let mut segments = NetworkSegment::find(&mut txn, uuid).await?;

        let segment = match segments.len() {
            1 => segments.remove(0),
            _ => return Err(Status::not_found("network segment not found")),
        };

        let prefixes =
            NetworkPrefix::find_by_segment(&mut txn, UuidKeyedObjectFilter::One(*segment.id()))
                .await?;

        let response = Ok(segment
            .delete(&mut txn)
            .await
            .map(|_| rpc::NetworkSegmentDeletionResult {})
            .map(Response::new)?);

        let db_conn = txn.acquire().await.map_err(CarbideError::from)?;

        for prefix in &prefixes {
            delete_resource_group(prefix, db_conn).await?;
        }

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn network_segments_for_vpc(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::VpcSearchQuery { id, .. } = request.into_inner();

        let _uuid = match id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Did not supply a valid VPC_ID UUID: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("A VPC_ID UUID is required"));
            }
        };

        let results = NetworkSegment::for_vpc(&mut txn, _uuid).await?;

        let mut network_segments = Vec::with_capacity(results.len());

        for result in results {
            network_segments.push(result.try_into()?);
        }

        Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn allocate_instance(
        &self,
        request: Request<rpc::InstanceAllocationRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        let request = InstanceAllocationRequest::try_from(request.into_inner())?;
        let instance_snapshot = allocate_instance(request, &self.database_connection).await?;

        let _ =
            log_instance_debug_data(&self.database_connection, instance_snapshot.instance_id).await;
        Ok(Response::new(
            rpc::Instance::try_from(instance_snapshot).map_err(CarbideError::from)?,
        ))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_instances(
        &self,
        request: Request<rpc::InstanceSearchQuery>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::InstanceSearchQuery { id, .. } = request.into_inner();
        // TODO: We load more information here than necessary - Instance::find()
        // and InstanceSnapshotLoader do redundant jobs
        let raw_instances = match id {
            Some(id) => {
                let id = id;
                let uuid = match uuid::Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Invalid UUID supplied: {}",
                            err
                        )));
                    }
                };
                Instance::find(&mut txn, uuid).await
            }
            None => Instance::find(&mut txn, UuidKeyedObjectFilter::All).await,
        }?;

        let loader = DbSnapshotLoader::default();
        let mut instances = Vec::with_capacity(raw_instances.len());
        for instance in raw_instances {
            let snapshot = loader
                .load_instance_snapshot(&mut txn, instance.id)
                .await
                .map_err(CarbideError::from)?;
            instances.push(rpc::Instance::try_from(snapshot).map_err(CarbideError::from)?);
        }

        Ok(Response::new(InstanceList { instances }))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_instance_by_machine_id(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<InstanceList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;
        let instance_id = Instance::find_id_by_machine_id(&mut txn, uuid)
            .await
            .map_err(CarbideError::from)?;

        let instance_id = match instance_id {
            Some(id) => id,
            None => return Ok(Response::new(rpc::InstanceList::default())),
        };

        let snapshot = DbSnapshotLoader::default()
            .load_instance_snapshot(&mut txn, instance_id)
            .await
            .map_err(CarbideError::from)?;
        let response = Response::new(rpc::InstanceList {
            instances: vec![snapshot.try_into().map_err(CarbideError::from)?],
        });

        txn.commit().await.map_err(CarbideError::from)?;

        Ok(response)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn release_instance(
        &self,
        request: Request<rpc::InstanceReleaseRequest>,
    ) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let delete_instance = DeleteInstance::try_from(request.into_inner())?;
        let instance_network_config =
            load_instance_network_config(&mut txn, delete_instance.instance_id)
                .await
                .map_err(CarbideError::from)?;

        let instance = delete_instance.delete(&mut txn).await?;

        // Change state to Decommissioned
        let machine = match Machine::find_one(&mut txn, instance.machine_id).await? {
            None => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    instance.machine_id
                )));
            }
            Some(m) => m,
        };

        // After deleted instance, machine should be moved to Decommissioned state.
        match machine.current_state(&mut txn).await? {
            MachineState::Assigned => {
                machine
                    .advance(&mut txn, &MachineStateMachineInput::Unassign)
                    .await?;
            }
            rest => {
                return Err(Status::invalid_argument(format!(
                    "Could not create instance given machine state {:?}",
                    rest
                )));
            }
        };

        let dpu = DpuMachine::find_by_host_machine_id(&mut txn, &instance.machine_id).await?;
        delete_managed_resource(
            &mut txn,
            instance.machine_id,
            dpu.machine_id().to_owned(),
            instance_network_config,
            instance.id,
        )
        .await?;
        txn.commit().await.map_err(CarbideError::from)?;

        // Machine will be rebooted once managed resource deletion successful.

        Ok(Response::new(rpc::InstanceReleaseResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn record_observed_instance_network_status(
        &self,
        request: Request<rpc::InstanceNetworkStatusObservation>,
    ) -> Result<Response<rpc::ObservedInstanceNetworkStatusRecordResult>, tonic::Status> {
        let request = request.into_inner();
        let instance_id = uuid::Uuid::try_from(
            request
                .instance_id
                .clone()
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?,
        )
        .map_err(CarbideError::from)?;

        let observation =
            InstanceNetworkStatusObservation::try_from(request).map_err(CarbideError::from)?;
        observation
            .validate()
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;
        update_instance_network_status_observation(&mut txn, instance_id, &observation)
            .await
            .map_err(CarbideError::from)?;
        txn.commit().await.map_err(CarbideError::from)?;

        let _ = log_instance_debug_data(&self.database_connection, instance_id).await;

        Ok(Response::new(
            rpc::ObservedInstanceNetworkStatusRecordResult {},
        ))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn lookup_record(
        &self,
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::dns_message::DnsQuestion {
            q_name,
            q_type,
            q_class,
        } = request.into_inner();

        let question = match q_name.clone() {
            Some(q_name) => DnsQuestion {
                query_name: Some(q_name),
                query_type: q_type,
                query_class: q_class,
            },
            None => {
                return Err(Status::invalid_argument(
                    "A valid q_name, q_type and q_class are required",
                ));
            }
        };

        let results = DnsQuestion::find_record(&mut txn, question)
            .await
            .map(|dnsrr| rpc::dns_message::DnsResponse {
                rcode: dnsrr.response_code,
                rrs: dnsrr
                    .resource_records
                    .into_iter()
                    .map(|r| r.into())
                    .collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(results)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn invoke_instance_power(
        &self,
        request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let machine_power_request = MachinePowerRequest::try_from(request.into_inner())?;

        let instance =
            Instance::find_by_machine_id(&mut txn, machine_power_request.machine_id).await?;
        if instance.is_none() {
            return Err(Status::invalid_argument(format!(
                "Supplied invalid UUID: {}",
                machine_power_request.machine_id
            )));
        }

        machine_power_request
            .set_custom_pxe_on_next_boot(&mut txn)
            .await?;
        txn.commit().await.map_err(CarbideError::from)?;

        let _ = machine_power_request
            .invoke_power_command(self.database_connection.clone())
            .await?;

        Ok(Response::new(rpc::InstancePowerResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        let machine_discovery_info = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let interface_id = match &machine_discovery_info.machine_interface_id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Did not supply a valid discovery machine_interface_id. Value was: {}. Err: {}",
                        id,
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument("An interface UUID is required"));
            }
        };

        let interface = MachineInterface::find_one(&mut txn, interface_id).await?;

        let machine = Machine::create(&mut txn, interface)
            .await
            .map(rpc::Machine::from)?;

        let uuid = match &machine.id {
            Some(id) => match uuid::Uuid::try_from(id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Created machine did not return an proper UUID : {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Status::invalid_argument(
                    "No ID was associated with the machine",
                ));
            }
        };

        let discovery_data = machine_discovery_info
            .discovery_data
            .map(|data| match data {
                rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
            })
            .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;

        let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;
        MachineTopology::create(&mut txn, &uuid, &hardware_info).await?;

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: machine.id,
        }));

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn cleanup_machine_completed(
        &self,
        request: Request<rpc::MachineCleanupInfo>,
    ) -> Result<Response<rpc::MachineCleanupResult>, Status> {
        let response = Ok(Response::new(rpc::MachineCleanupResult {}));
        log::info!("MachineCleanupInfo {:?}", request);

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn done(&self, request: Request<rpc::Uuid>) -> Result<Response<rpc::Machine>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let machine_interface_id =
            uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let interface = MachineInterface::find_one(&mut txn, machine_interface_id).await?;

        let maybe_machine = match interface.machine_id {
            Some(machine_id) => Machine::find_one(&mut txn, machine_id).await?,
            None => {
                return Err(Status::invalid_argument(format!(
                    "Machine interface has no machine id UUID: {}",
                    machine_interface_id
                )));
            }
        };

        let response = match maybe_machine {
            None => Err(CarbideError::NotFoundError(machine_interface_id).into()),
            Some(machine) => Ok(rpc::Machine::from(machine)),
        }
        .map(Response::new);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        crate::dhcp_discover::discover_dhcp(
            &self.database_connection,
            &self.dhcp_discovery_cache,
            request,
        )
        .await
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_machine(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::Machine>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let response = match Machine::find_one(&mut txn, uuid).await? {
            None => Err(CarbideError::NotFoundError(uuid).into()),
            Some(machine) => Ok(rpc::Machine::from(machine)),
        }
        .map(Response::new);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::MachineSearchQuery { id, fqdn, .. } = request.into_inner();
        let machines = match (id, fqdn) {
            (Some(id), _) => {
                let id = id;
                let uuid = match uuid::Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Invalid UUID supplied: {}",
                            err
                        )));
                    }
                };
                Machine::find(&mut txn, uuid).await
            }
            (None, Some(fqdn)) => Machine::find_by_fqdn(&mut txn, fqdn).await,
            (None, None) => Machine::find(&mut txn, UuidKeyedObjectFilter::All).await,
        };

        let result = machines
            .map(|machine| rpc::MachineList {
                machines: machine.into_iter().map(rpc::Machine::from).collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let rpc::InterfaceSearchQuery { id, .. } = request.into_inner();

        let response = match id {
            Some(id) if id.value.chars().count() > 0 => match uuid::Uuid::try_from(id) {
                Ok(uuid) => Ok(rpc::InterfaceList {
                    interfaces: vec![MachineInterface::find_one(&mut txn, uuid).await?.into()],
                }),
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into()),
            },
            _ => Err(
                CarbideError::GenericError("Could not find an ID in the request".to_string())
                    .into(),
            ),
        };

        response.map(Response::new)
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_instance_type(
        &self,
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(NewInstanceType::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_instance_type(
        &self,
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(UpdateInstanceType::try_from(request.into_inner())?
            .update(&mut txn)
            .await
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_instance_type(
        &self,
        request: Request<rpc::InstanceTypeDeletion>,
    ) -> Result<Response<rpc::InstanceTypeDeletionResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(DeactivateInstanceType::try_from(request.into_inner())?
            .deactivate(&mut txn)
            .await
            .map(rpc::InstanceTypeDeletionResult::from)
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn create_tag(
        &self,
        request: Request<rpc::TagCreate>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagCreate::try_from(request.into_inner())?
            .create(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn delete_tag(
        &self,
        request: Request<rpc::TagDelete>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagDelete::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn list_tags(
        &self,
        _request: Request<rpc::TagVoid>,
    ) -> Result<Response<rpc::TagsListResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(Tag::list_all(&mut txn).await.map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn assign_tag(
        &self,
        request: Request<rpc::TagAssign>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn remove_tag(
        &self,
        request: Request<rpc::TagRemove>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .remove(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn set_tags(
        &self,
        request: Request<rpc::TagsList>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(TagsList::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn validate_user_ssh_key(
        &self,
        request: Request<rpc::SshKeyValidationRequest>,
    ) -> Result<Response<rpc::SshKeyValidationResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(SshKeyValidationRequest::try_from(request.into_inner())?
            .verify_user(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataGetRequest>,
    ) -> Result<Response<rpc::BmcMetaDataGetResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(BmcMetaDataGetRequest::try_from(request.into_inner())?
            .get_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataUpdateRequest>,
    ) -> Result<Response<rpc::BmcMetaDataUpdateResponse>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(BmcMetaDataUpdateRequest::try_from(request.into_inner())?
            .update_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(CarbideError::from)?;

        response
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn update_machine_credentials(
        &self,
        request: Request<MachineCredentialsUpdateRequest>,
    ) -> Result<Response<MachineCredentialsUpdateResponse>, Status> {
        Ok(UpdateCredentials::try_from(request.into_inner())?
            .update(self.credential_provider.as_ref())
            .await
            .map(Response::new)?)
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn update_security_group_policy(
        &self,
        _request: Request<rpc::SecurityGroupPolicy>,
    ) -> Result<Response<rpc::SecurityGroupPolicy>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn delete_security_group_policy(
        &self,
        _request: Request<rpc::SecurityGroupPolicyDeletion>,
    ) -> Result<Response<()>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn bind_security_group(
        &self,
        _request: Request<rpc::SecurityGroupBind>,
    ) -> Result<Response<()>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn unbind_security_group(
        &self,
        _request: Request<rpc::SecurityGroupBind>,
    ) -> Result<Response<()>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn list_security_group_policies(
        &self,
        _request: Request<rpc::SecurityGroupPolicyQuery>,
    ) -> Result<Response<rpc::SecurityGroupPolicyList>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?_request.get_ref()))]
    async fn list_security_group_binds(
        &self,
        _request: Request<rpc::SecurityGroupBindQuery>,
    ) -> Result<Response<rpc::SecurityGroupBindList>, Status> {
        return Err(Status::unimplemented("not implemented"));
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_pxe_instructions(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::PxeInstructions>, Status> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let machine_id = uuid::Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

        let instance = Instance::find_by_machine_id(&mut txn, machine_id)
            .await?
            .ok_or(CarbideError::FindOneReturnedNoResultsError(machine_id))?;

        let pxe_script = if instance.use_custom_pxe_on_boot {
            Instance::use_custom_ipxe_on_next_boot(machine_id, false, &mut txn).await?;
            instance.tenant_config.custom_ipxe
        } else {
            "exit".to_string()
        };

        txn.commit().await.map_err(CarbideError::from)?;

        Ok(Response::new(rpc::PxeInstructions { pxe_script }))
    }
}
async fn update_external_config() {
    let dhcp_server =
        env::var("CARBIDE_DHCP_SERVER").expect("Env variable CARBIDE_DHCP_SERVER is not defined.");
    CONFIG.write().await.dhcp_server = Some(dhcp_server);
}

impl<C> Api<C>
where
    C: CredentialProvider + 'static,
{
    pub fn new(credential_provider: Arc<C>, database_connection: sqlx::PgPool) -> Self {
        Self {
            database_connection,
            credential_provider,
            dhcp_discovery_cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn run(
        daemon_config: &cfg::Daemon,
        credential_provider: Arc<C>,
    ) -> Result<(), Report> {
        log::info!("Starting API server on {:?}", daemon_config.listen[0]);

        let database_connection = sqlx::Pool::connect(&daemon_config.datastore).await?;
        let conn_clone = database_connection.clone();

        let api_service = Arc::new(Self::new(
            credential_provider.clone(),
            database_connection.clone(),
        ));

        let mut authenticator = CarbideAuth::new();

        // FIXME: Don't ship with this enabled. Should it be a config option?
        authenticator.set_permissive_mode(true);

        // Example code just to show usage. Do not actually use this!
        /*
        authenticator.add_jwt_key(
            auth::Algorithm::RS256,
            auth::KeySpec::KeyID(String::from("wow this is a great key ID!")),
            auth::DecodingKey::from_base64_secret("dWggb2g=").unwrap(),
        );
        */

        update_external_config().await;

        let auth_layer = tower_http::auth::RequireAuthorizationLayer::custom(authenticator);

        let reflection_service = Builder::configure()
            .register_encoded_file_descriptor_set(::rpc::REFLECTION_SERVICE_DESCRIPTOR)
            .build()?;

        // handle should be stored in a variable. If is is dropped by compiler, main event will be dropped.
        let _handle = ipmi_handler(
            conn_clone,
            RealIpmiCommandHandler {},
            credential_provider.clone(),
        )
        .await?;

        let _kube_handle = bgkubernetes_handler(
            daemon_config.datastore.to_owned(),
            daemon_config.kubernetes,
            api_service.clone(),
        )
        .await?;

        let _state_controller_handle = MachineStateController::builder()
            .database(database_connection)
            .snapshot_loader(Box::new(DbSnapshotLoader::default()))
            .state_handler(Arc::new(RealMachineStateHandler::default()))
            .build()
            .expect("Unable to build MachineStateController");

        tonic::transport::Server::builder()
            //            .tls_config(ServerTlsConfig::new().identity( Identity::from_pem(&cert, &key) ))?
            .layer(auth_layer)
            .add_service(rpc::forge_server::ForgeServer::from_arc(api_service))
            .add_service(reflection_service)
            .serve(daemon_config.listen[0])
            .await?;

        Ok(())
    }
}

/// TO BE REMOVED
/// This is temporary here to see whether the new "API" - which would consume the
/// data from `InstanceSnapshot` and `InstanceStatus` - would return the right thnings.
async fn log_instance_debug_data(
    pool: &sqlx::PgPool,
    instance_id: uuid::Uuid,
) -> Result<(), CarbideError> {
    let mut txn = pool.begin().await.map_err(CarbideError::from)?;

    let snapshot = DbSnapshotLoader::default()
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;
    let status = snapshot.derive_status();

    tracing::info!(
        "Instance state report: Snapshot: {:?}, Status: {:?}",
        snapshot,
        status
    );
    Ok(())
}
