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
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use color_eyre::Report;
use futures_util::future::BoxFuture;
use http::header::USER_AGENT;
use http::{header::AUTHORIZATION, StatusCode};
use hyper::server::conn::Http;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use opentelemetry::metrics::Meter;
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor,
};
use tonic::body::BoxBody;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder;
use tower_http::auth::{AsyncAuthorizeRequest, AsyncRequireAuthorizationLayer};
use uuid::Uuid;

pub use ::rpc::forge as rpc;
use ::rpc::protos::forge::{
    CreateTenantKeysetRequest, CreateTenantKeysetResponse, CreateTenantRequest,
    CreateTenantResponse, DeleteTenantKeysetRequest, DeleteTenantKeysetResponse, EchoRequest,
    EchoResponse, FindTenantKeysetRequest, FindTenantKeysetResponse, FindTenantRequest,
    FindTenantResponse, InstanceList, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse, UpdateTenantKeysetRequest, UpdateTenantKeysetResponse,
    UpdateTenantRequest, UpdateTenantResponse, ValidateTenantPublicKeyRequest,
    ValidateTenantPublicKeyResponse,
};
use forge_credentials::{CredentialKey, CredentialProvider, Credentials};

use crate::db::ipmi::UserRoles;
use crate::db::machine::MachineSearchConfig;
use crate::db::network_segment::NetworkSegmentSearchConfig;
use crate::model::machine::machine_id::{try_parse_machine_id, MachineType};
use crate::model::machine::network::MachineNetworkStatus;
use crate::model::machine::{InstanceState, ManagedHostState};
use crate::state_controller::snapshot_loader::MachineStateSnapshotLoader;
use crate::{
    auth, cfg,
    credentials::UpdateCredentials,
    db::{
        auth::SshKeyValidationRequest,
        domain::Domain,
        domain::NewDomain,
        instance::{
            status::network::update_instance_network_status_observation, DeleteInstance, Instance,
        },
        instance_type::{DeactivateInstanceType, NewInstanceType, UpdateInstanceType},
        ipmi::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NewNetworkSegment},
        resource_record::DnsQuestion,
        tags::{Tag, TagAssociation, TagCreate, TagDelete, TagsList},
        vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc},
        DatabaseError, ObjectFilter, UuidKeyedObjectFilter,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    ipmi::{ipmi_handler, MachineBmcRequest, RealIpmiCommandHandler},
    kubernetes::{bgkubernetes_handler, VpcApi, VpcApiImpl, VpcApiSim},
    logging::{
        api_logs::LogLayer,
        service_health_metrics::{start_export_service_health_metrics, ServiceHealthContext},
    },
    model::{
        hardware_info::HardwareInfo,
        instance::status::network::InstanceNetworkStatusObservation,
        machine::{machine_id::MachineId, MachineState},
    },
    state_controller::{
        controller::StateController,
        machine::handler::MachineStateHandler,
        machine::io::MachineStateControllerIO,
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
        snapshot_loader::DbSnapshotLoader,
    },
    CarbideError, CarbideResult,
};

use self::rpc::forge_server::Forge;

// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

pub struct Api<C: CredentialProvider> {
    database_connection: sqlx::PgPool,
    credential_provider: Arc<C>,
    authorizer: auth::Authorizer,
    vpc_api: Arc<dyn VpcApi>,
}

#[tonic::async_trait]
impl<C> Forge for Api<C>
where
    C: CredentialProvider + 'static,
{
    async fn create_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin create_domain", e))?;

        let response = Ok(NewDomain::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?);
        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_domain", e))?;

        response
    }

    async fn update_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin update_domain", e))?;

        let rpc::Domain { id, name, .. } = request.into_inner();

        // TODO(jdg): Move this out into a function and share it with delete
        let uuid = match id {
            Some(id) => match Uuid::try_from(id) {
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

        let mut domains = Domain::find(&mut txn, uuid)
            .await
            .map_err(CarbideError::from)?;

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
            .map_err(CarbideError::from)
            .map(rpc::Domain::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit update_domain", e))?;

        response
    }

    async fn delete_domain(
        &self,
        request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin delete_domain", e))?;

        let rpc::DomainDeletion { id, .. } = request.into_inner();

        // load from find from domain.rs
        let uuid = match id {
            Some(id) => match Uuid::try_from(id) {
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

        let mut domains = Domain::find(&mut txn, uuid)
            .await
            .map_err(CarbideError::from)?;

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
            .map_err(CarbideError::from)
            .map(|_| rpc::DomainDeletionResult {})
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_domain", e))?;

        response
    }

    async fn find_domain(
        &self,
        request: Request<rpc::DomainSearchQuery>,
    ) -> Result<Response<rpc::DomainList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_domain", e))?;

        let rpc::DomainSearchQuery { id, name, .. } = request.into_inner();
        let domains = match (id, name) {
            (Some(id), _) => {
                let id = id;
                let uuid = match Uuid::try_from(id) {
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

    async fn create_vpc(
        &self,
        request: Request<rpc::VpcCreationRequest>,
    ) -> Result<Response<rpc::Vpc>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin create_vpc", e))?;

        let response = Ok(NewVpc::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(rpc::Vpc::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_vpc", e))?;

        response
    }

    async fn update_vpc(
        &self,
        request: Request<rpc::VpcUpdateRequest>,
    ) -> Result<Response<rpc::VpcUpdateResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin update_vpc", e))?;

        UpdateVpc::try_from(request.into_inner())?
            .update(&mut txn)
            .await?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit update_vpc", e))?;

        Ok(Response::new(rpc::VpcUpdateResult {}))
    }

    async fn delete_vpc(
        &self,
        request: Request<rpc::VpcDeletionRequest>,
    ) -> Result<Response<rpc::VpcDeletionResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin delete_vpc", e))?;

        // TODO: This needs to validate that nothing references the VPC anymore
        // (like NetworkSegments)

        let response = Ok(DeleteVpc::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(rpc::VpcDeletionResult::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_vpc", e))?;

        response
    }

    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_vpcs", e))?;

        let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

        let vpcs = match (id, name) {
            (Some(id), _) => {
                let id = id;
                let uuid = match Uuid::try_from(id) {
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

    async fn find_network_segments(
        &self,
        request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin find_network_segments", e)
            })?;

        let rpc::NetworkSegmentQuery {
            id, search_config, ..
        } = request.into_inner();

        let uuid_filter = match id {
            Some(id) => match Uuid::try_from(id) {
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

        let search_config = search_config
            .map(NetworkSegmentSearchConfig::from)
            .unwrap_or(NetworkSegmentSearchConfig::default());
        let results = NetworkSegment::find(&mut txn, uuid_filter, search_config)
            .await
            .map_err(CarbideError::from)?;
        let mut network_segments = Vec::with_capacity(results.len());

        for result in results {
            network_segments.push(result.try_into()?);
        }
        Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
    }

    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentCreationRequest>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin create_network_segment", e)
            })?;

        let response = NewNetworkSegment::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map_err(CarbideError::from);

        let response = Ok(Response::new(response?.try_into()?));
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit create_network_segment", e)
        })?;

        response
    }

    async fn update_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentUpdateRequest>,
    ) -> Result<Response<rpc::NetworkSegmentUpdateResult>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn delete_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentDeletionRequest>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin delete_network_segment", e)
            })?;

        let rpc::NetworkSegmentDeletionRequest { id, .. } = request.into_inner();

        let uuid = match id {
            Some(id) => match Uuid::try_from(id) {
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

        let mut segments =
            NetworkSegment::find(&mut txn, uuid, NetworkSegmentSearchConfig::default())
                .await
                .map_err(CarbideError::from)?;

        let segment = match segments.len() {
            1 => segments.remove(0),
            _ => return Err(Status::not_found("network segment not found")),
        };

        let response = Ok(segment
            .mark_as_deleted(&mut txn)
            .await
            .map(|_| rpc::NetworkSegmentDeletionResult {})
            .map(Response::new)?);

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit delete_network_segment", e)
        })?;

        response
    }

    async fn network_segments_for_vpc(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin network_segments_for_vpc", e)
        })?;

        let rpc::VpcSearchQuery { id, .. } = request.into_inner();

        let _uuid = match id {
            Some(id) => match Uuid::try_from(id) {
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

        let results = NetworkSegment::for_vpc(&mut txn, _uuid)
            .await
            .map_err(CarbideError::from)?;

        let mut network_segments = Vec::with_capacity(results.len());

        for result in results {
            network_segments.push(result.try_into()?);
        }

        Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
    }

    async fn allocate_instance(
        &self,
        request: Request<rpc::InstanceAllocationRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        log_request_data(&request);

        let request = InstanceAllocationRequest::try_from(request.into_inner())?;
        let instance_snapshot = allocate_instance(request, &self.database_connection).await?;

        Ok(Response::new(
            rpc::Instance::try_from(instance_snapshot).map_err(CarbideError::from)?,
        ))
    }

    async fn find_instances(
        &self,
        request: Request<rpc::InstanceSearchQuery>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        log_request_data(&request);

        let _auth =
            self.authorizer
                .authorize(&request, auth::Action::Read, auth::Object::Instance)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_instances", e))?;

        let rpc::InstanceSearchQuery { id, .. } = request.into_inner();
        // TODO: We load more information here than necessary - Instance::find()
        // and InstanceSnapshotLoader do redundant jobs
        let raw_instances = match id {
            Some(id) => {
                let id = id;
                let uuid = match Uuid::try_from(id) {
                    Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                    Err(err) => {
                        return Err(Status::invalid_argument(format!(
                            "Invalid UUID supplied: {}",
                            err
                        )));
                    }
                };
                Instance::find(&mut txn, uuid)
                    .await
                    .map_err(CarbideError::from)
            }
            None => Instance::find(&mut txn, UuidKeyedObjectFilter::All)
                .await
                .map_err(CarbideError::from),
        }?;

        let loader = DbSnapshotLoader::default();
        let mut instances = Vec::with_capacity(raw_instances.len());
        for instance in raw_instances {
            let snapshot = loader
                .load_machine_snapshot_for_host(&mut txn, &instance.machine_id)
                .await
                .map_err(CarbideError::from)?
                .instance
                .ok_or(Status::invalid_argument(format!(
                    "Snapshot not found for Instance {}",
                    instance.id()
                )))?;
            instances.push(rpc::Instance::try_from(snapshot).map_err(CarbideError::from)?);
        }

        Ok(Response::new(InstanceList { instances }))
    }

    async fn find_instance_by_machine_id(
        &self,
        request: Request<rpc::MachineId>,
    ) -> Result<Response<InstanceList>, Status> {
        log_request_data(&request);

        let _auth =
            self.authorizer
                .authorize(&request, auth::Action::Read, auth::Object::Instance)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_instance_by_machine_id",
                e,
            ))
        })?;

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;

        let Some(snapshot) = DbSnapshotLoader::default()
            .load_machine_snapshot_for_host(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?.instance else {
            return Ok(Response::new(rpc::InstanceList::default()));
        };

        let response = Response::new(rpc::InstanceList {
            instances: vec![snapshot.try_into().map_err(CarbideError::from)?],
        });

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit find_instance_by_machine_id",
                e,
            ))
        })?;

        Ok(response)
    }

    async fn release_instance(
        &self,
        request: Request<rpc::InstanceReleaseRequest>,
    ) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin release_instance",
                e,
            ))
        })?;

        let delete_instance = DeleteInstance::try_from(request.into_inner())?;
        let instance = Instance::find(
            &mut txn,
            UuidKeyedObjectFilter::One(delete_instance.instance_id),
        )
        .await
        .map_err(CarbideError::from)?;

        let Some(instance) = instance.last() else {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}. Could not find associated instance.",
                    delete_instance.instance_id
                )));
        };

        // Change state to Decommissioned
        let machine = match Machine::find_one(
            &mut txn,
            &instance.machine_id,
            MachineSearchConfig::default(),
        )
        .await
        .map_err(CarbideError::from)?
        {
            None => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    instance.machine_id
                )));
            }
            Some(m) => m,
        };

        if let ManagedHostState::Assigned(InstanceState::Ready) = machine.current_state() {
            if instance.deleted.is_some() {
                return Err(Status::invalid_argument(format!(
                    "Instance {} is already marked for deletion.",
                    delete_instance.instance_id,
                )));
            }
            log::info!(
                "Marking instance {} for deletion.",
                delete_instance.instance_id
            );
            let _ = delete_instance.mark_as_deleted(&mut txn).await?;
        } else {
            return Err(Status::invalid_argument(format!(
                "Could not release instance {} given machine state {:?}",
                delete_instance.instance_id,
                machine.current_state()
            )));
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit release_instance",
                e,
            ))
        })?;

        Ok(Response::new(rpc::InstanceReleaseResult {}))
    }

    async fn record_observed_instance_network_status(
        &self,
        request: Request<rpc::InstanceNetworkStatusObservation>,
    ) -> Result<Response<rpc::ObservedInstanceNetworkStatusRecordResult>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let instance_id = Uuid::try_from(
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

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin record_observed_instance_network_status", e)
        })?;
        update_instance_network_status_observation(&mut txn, instance_id, &observation)
            .await
            .map_err(CarbideError::from)?;
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(
                file!(),
                "commit record_observed_instance_network_status",
                e,
            )
        })?;

        Ok(Response::new(
            rpc::ObservedInstanceNetworkStatusRecordResult {},
        ))
    }

    async fn get_managed_host_network_config(
        &self,
        request: Request<rpc::ManagedHostNetworkConfigRequest>,
    ) -> Result<tonic::Response<rpc::ManagedHostNetworkConfigResponse>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let machine_id = match &request.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine id"));
            }
        };

        let loader = DbSnapshotLoader::default();
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_managed_host_network_config", e)
        })?;

        let snapshot = loader
            .load_machine_snapshot(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_managed_host_network_config",
                e,
            ))
        })?;

        // TODO: Extract network state from Machine State. Loading the Machine state
        // should contain it (and already contains the instance state)
        let _ = snapshot;
        Err(CarbideError::NotImplemented.into())
    }

    async fn record_managed_host_network_status(
        &self,
        request: Request<rpc::ManagedHostNetworkStatusObservation>,
    ) -> Result<Response<rpc::ManagedHostNetworkStatusRecordResult>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let machine_id = match &request.dpu_machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine id"));
            }
        };

        let hs = request
            .health
            .as_ref()
            .ok_or_else(|| CarbideError::MissingArgument("health_status"))?;
        if !hs.is_healthy {
            tracing::debug!(
                "{machine_id} reports network failed checks {:?} because {}",
                hs.failed,
                hs.message.as_deref().unwrap_or_default()
            );
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin record_machine_network_status", e)
        })?;
        let db_observation = MachineNetworkStatus::try_from(request).map_err(CarbideError::from)?;
        Machine::update_network_status_observation(&mut txn, &machine_id, db_observation).await?;
        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit record_machine_network_status",
                e,
            ))
        })?;

        Ok(Response::new(rpc::ManagedHostNetworkStatusRecordResult {}))
    }

    async fn lookup_record(
        &self,
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin lookup_record", e))?;

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

    async fn invoke_instance_power(
        &self,
        request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin invoke_instance_power",
                e,
            ))
        })?;

        let machine_power_request = MachineBmcRequest::try_from(request.into_inner())?;

        let instance = Instance::find_by_machine_id(&mut txn, &machine_power_request.machine_id)
            .await
            .map_err(CarbideError::from)?;
        if instance.is_none() {
            return Err(Status::invalid_argument(format!(
                "Supplied invalid UUID: {}",
                machine_power_request.machine_id
            )));
        }

        machine_power_request
            .set_custom_pxe_on_next_boot(&mut txn)
            .await?;
        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit invoke_instance_power",
                e,
            ))
        })?;

        let _ = machine_power_request
            .invoke_bmc_command(self.database_connection.clone())
            .await?;

        Ok(Response::new(rpc::InstancePowerResult {}))
    }

    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        log_request_data(&request);

        let conn_info = request.extensions().get::<ConnInfo>().unwrap();
        println!(
            "Got a request from: {:?} with authorization_type: {:?}, request: {:?}",
            conn_info.addr, conn_info.authorization_type, request,
        );

        let reply = EchoResponse {
            message: request.into_inner().message,
        };

        Ok(Response::new(reply))
    }

    /// Tenant-related actions
    async fn create_tenant(
        &self,
        _request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        todo!()
    }

    async fn find_tenant(
        &self,
        _request: Request<FindTenantRequest>,
    ) -> Result<Response<FindTenantResponse>, Status> {
        todo!()
    }

    async fn update_tenant(
        &self,
        _request: Request<UpdateTenantRequest>,
    ) -> Result<Response<UpdateTenantResponse>, Status> {
        todo!()
    }

    async fn create_tenant_keyset(
        &self,
        _request: Request<CreateTenantKeysetRequest>,
    ) -> Result<Response<CreateTenantKeysetResponse>, Status> {
        todo!()
    }

    async fn find_tenant_keyset(
        &self,
        _request: Request<FindTenantKeysetRequest>,
    ) -> Result<Response<FindTenantKeysetResponse>, Status> {
        todo!()
    }

    async fn update_tenant_keyset(
        &self,
        _request: Request<UpdateTenantKeysetRequest>,
    ) -> Result<Response<UpdateTenantKeysetResponse>, Status> {
        todo!()
    }

    async fn delete_tenant_keyset(
        &self,
        _request: Request<DeleteTenantKeysetRequest>,
    ) -> Result<Response<DeleteTenantKeysetResponse>, Status> {
        todo!()
    }

    async fn validate_tenant_public_key(
        &self,
        _request: Request<ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<ValidateTenantPublicKeyResponse>, Status> {
        todo!()
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        log_request_data(&request);

        if let Some(conn_info) = request.extensions().get::<ConnInfo>() {
            log::info!(
                "Got a request from: {:?} with authorization_type: {:?}, request: {:?}",
                conn_info.addr,
                conn_info.authorization_type,
                request,
            );
        }

        let machine_discovery_info = request.into_inner();

        let discovery_data = machine_discovery_info
            .discovery_data
            .map(|data| match data {
                rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
            })
            .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;

        let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

        // Generate a stable Machine ID based on the hardware information
        // TODO: This should become an error if not enough information is available
        let stable_machine_id = MachineId::from_hardware_info(&hardware_info);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin discover_machine", e))?;

        let interface_id = match &machine_discovery_info.machine_interface_id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("An interface UUID is required"));
            }
        };

        let interface = MachineInterface::find_one(&mut txn, interface_id).await?;
        let machine = Machine::get_or_create(
            &mut txn,
            stable_machine_id,
            interface,
            hardware_info.is_dpu(),
        )
        .await
        .map(rpc::Machine::from)?;

        let machine_id = match &machine.id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine"));
            }
        };

        MachineTopology::create(&mut txn, &machine_id, &hardware_info).await?;

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: machine.id,
        }));

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit discover_machine", e))?;

        response
    }

    // Host has completed discovery
    async fn discovery_completed(
        &self,
        request: Request<rpc::MachineDiscoveryCompletedRequest>,
    ) -> Result<Response<rpc::MachineDiscoveryCompletedResponse>, Status> {
        log_request_data(&request);

        let req = request.into_inner();

        // Extract and check UUID
        let machine_id = match &req.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        machine.update_discovery_time(&mut txn).await?;
        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit discovery_completed", e))?;

        log::info!("discovery_completed_success: {machine_id}");
        Ok(Response::new(rpc::MachineDiscoveryCompletedResponse {}))
    }

    // Transitions the machine to Ready state.
    // Called by 'forge-scout discovery' once cleanup succeeds.
    async fn cleanup_machine_completed(
        &self,
        request: Request<rpc::MachineCleanupInfo>,
    ) -> Result<Response<rpc::MachineCleanupResult>, Status> {
        log_request_data(&request);

        let cleanup_info = request.into_inner();
        log::info!("cleanup_machine_completed {:?}", cleanup_info);

        // Extract and check UUID
        let machine_id = match &cleanup_info.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };

        // Load machine from DB
        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        machine.update_cleanup_time(&mut txn).await?;
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit cleanup_machine_completed", e)
        })?;

        // State handler should mark Machine as Adopted and reboot host for bios/bmc lockdown.
        Ok(Response::new(rpc::MachineCleanupResult {}))
    }

    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        log_request_data(&request);

        crate::dhcp::discover::discover_dhcp(&self.database_connection, request).await
    }

    async fn get_machine(
        &self,
        request: Request<rpc::MachineId>,
    ) -> Result<Response<rpc::Machine>, Status> {
        log_request_data(&request);

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;
        let (machine, _) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig {
                    include_history: true,
                },
            )
            .await?;
        Ok(Response::new(rpc::Machine::from(machine)))
    }

    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_machines", e))?;

        let rpc::MachineSearchQuery {
            id,
            fqdn,
            search_config,
            ..
        } = request.into_inner();
        let include_dpus = search_config
            .as_ref()
            .map(|x| x.include_dpus)
            .unwrap_or(false);

        let search_config = search_config
            .map(MachineSearchConfig::from)
            .unwrap_or(MachineSearchConfig::default());

        let machines = match (id, fqdn) {
            (Some(id), _) => {
                let machine_id = try_parse_machine_id(&id).map_err(CarbideError::from)?;
                Machine::find(&mut txn, ObjectFilter::One(machine_id), search_config).await
            }
            (None, Some(fqdn)) => Machine::find_by_fqdn(&mut txn, &fqdn, search_config).await,
            (None, None) => Machine::find(&mut txn, ObjectFilter::All, search_config).await,
        };

        let result = machines
            .map(|machine| rpc::MachineList {
                machines: machine
                    .into_iter()
                    .filter(|x| {
                        let ty = x.machine_type();
                        ty.is_some()
                            && (include_dpus
                                || ty.expect("MachineType is none.") == MachineType::Host)
                    })
                    .map(rpc::Machine::from)
                    .collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_interfaces", e))?;

        let rpc::InterfaceSearchQuery { id, .. } = request.into_inner();

        let response = match id {
            Some(id) if id.value.chars().count() > 0 => match Uuid::try_from(id) {
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

    async fn create_instance_type(
        &self,
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin create_instance_type", e)
            })?;

        let response = Ok(NewInstanceType::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_instance_type", e))?;

        response
    }

    async fn update_instance_type(
        &self,
        request: Request<rpc::InstanceType>,
    ) -> Result<Response<rpc::InstanceType>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin update_instance_type", e)
            })?;

        let response = Ok(UpdateInstanceType::try_from(request.into_inner())?
            .update(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(rpc::InstanceType::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit update_instance_type", e))?;

        response
    }

    async fn delete_instance_type(
        &self,
        request: Request<rpc::InstanceTypeDeletion>,
    ) -> Result<Response<rpc::InstanceTypeDeletionResult>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin delete_instance_type", e)
            })?;

        let response = Ok(DeactivateInstanceType::try_from(request.into_inner())?
            .deactivate(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(rpc::InstanceTypeDeletionResult::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_instance_type", e))?;

        response
    }

    async fn create_tag(
        &self,
        request: Request<rpc::TagCreate>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin create_tag", e))?;

        let response = Ok(TagCreate::try_from(request.into_inner())?
            .create(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_tag", e))?;

        response
    }

    async fn delete_tag(
        &self,
        request: Request<rpc::TagDelete>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin delete_tag", e))?;

        let response = Ok(TagDelete::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_tag", e))?;

        response
    }

    async fn list_tags(
        &self,
        request: Request<rpc::TagVoid>,
    ) -> Result<Response<rpc::TagsListResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin list_tags", e))?;

        let response = Ok(Tag::list_all(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit list_tags", e))?;

        response
    }

    async fn assign_tag(
        &self,
        request: Request<rpc::TagAssign>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin assign_tag", e))?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit assign_tag", e))?;

        response
    }

    async fn remove_tag(
        &self,
        request: Request<rpc::TagRemove>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin remove_tag", e))?;

        let response = Ok(TagAssociation::try_from(request.into_inner())?
            .remove(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit remove_tag", e))?;

        response
    }

    async fn set_tags(
        &self,
        request: Request<rpc::TagsList>,
    ) -> Result<Response<rpc::TagResult>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin set_tags", e))?;

        let response = Ok(TagsList::try_from(request.into_inner())?
            .assign(&mut txn)
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit set_tags", e))?;

        response
    }

    async fn validate_user_ssh_key(
        &self,
        request: Request<rpc::SshKeyValidationRequest>,
    ) -> Result<Response<rpc::SshKeyValidationResponse>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin validate_user_ssh_key", e)
            })?;

        let response = Ok(SshKeyValidationRequest::from(request.into_inner())
            .verify_user(&mut txn)
            .await
            .map_err(CarbideError::from)
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit validate_user_ssh_key", e))?;

        response
    }

    // Fetch the DPU admin SSH password from Vault.
    // "host_id" can be any of:
    //  - UUID (primary key)
    //  - IPv4 address
    //  - MAC address
    //  - Hostname
    //
    // Usage:
    //  grpcurl -d '{"host_id": "neptune-bravo"}' -plaintext 127.0.0.1:1079 forge.Forge/GetDpuSSHCredential | jq -r -j ".password"
    // That should evaluate to exactly the password, ready for inclusion in a script.
    //
    async fn get_dpu_ssh_credential(
        &self,
        request: Request<rpc::CredentialRequest>,
    ) -> Result<Response<rpc::CredentialResponse>, Status> {
        log_request_data(&request);

        let query = request.into_inner().host_id;

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin get_dpu_ssh_credential", e)
            })?;
        let machine_id = match Machine::find_by_query(&mut txn, &query)
            .await
            .map_err(CarbideError::from)?
        {
            Some(machine) => {
                if !machine.is_dpu() {
                    return Err(Status::not_found(format!(
                        "Searching for machine {} was found for '{query}', but it is not a DPU",
                        machine.id()
                    )));
                }
                machine.id().clone()
            }
            None => {
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: query,
                }
                .into());
            }
        };

        // We don't need this transaction
        let _ = txn.rollback().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "rollback get_dpu_ssh_credential", e)
        })?;

        // Load credentials from Vault
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuSsh {
                machine_id: machine_id.to_string(),
            })
            .await
            .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                Ok(vaultrs::error::ClientError::APIError { code, .. }) if code == 404 => {
                    CarbideError::NotFoundError {
                        kind: "dpu-ssh-cred",
                        id: machine_id.to_string(),
                    }
                }
                Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                Err(err) => CarbideError::GenericError(format!(
                    "Error getting SSH credentials for DPU: {:?}",
                    err
                )),
            })?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // UpdateMachineCredentials only allows a single account currently so warn if it's
        // not the correct one.
        if username != DPU_ADMIN_USERNAME {
            tracing::warn!("Expected '{DPU_ADMIN_USERNAME}' username in Vault, found '{username}'");
        }

        Ok(Response::new(rpc::CredentialResponse {
            username,
            password,
        }))
    }

    // Network status of each managed host, as reported by forge-dpu-agent.
    // For use by forge-admin-cli
    //
    // Currently: Status of HBN on each DPU
    async fn get_all_managed_host_network_status(
        &self,
        request: Request<rpc::ManagedHostNetworkStatusRequest>,
    ) -> Result<Response<rpc::ManagedHostNetworkStatusResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_managed_host_network_status", e)
        })?;

        let all_status = Machine::get_all_network_status(&mut txn).await?;

        let mut out = Vec::with_capacity(all_status.len());
        for machine_network_status in all_status {
            out.push(machine_network_status.into());
        }
        Ok(Response::new(rpc::ManagedHostNetworkStatusResponse {
            all: out,
        }))
    }

    async fn admin_reboot(
        &self,
        request: Request<rpc::AdminRebootRequest>,
    ) -> Result<Response<rpc::AdminRebootResponse>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let (user, password) = match (req.user, req.password, req.machine_id) {
            // User provided username and password
            (Some(u), Some(p), _) => (u, p),

            // User provided machine_id
            (_, _, Some(machine_id)) => {
                // Load credentials from Vault
                let credentials = self
                    .credential_provider
                    .get_credentials(CredentialKey::Bmc {
                        user_role: UserRoles::Administrator.to_string(),
                        machine_id: machine_id.clone(),
                    })
                    .await
                    .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                        Ok(vaultrs::error::ClientError::APIError { code, .. }) if code == 404 => {
                            CarbideError::GenericError(format!(
                                "Vault key not found: bmc-metadata-items for machine_id {}",
                                machine_id
                            ))
                        }
                        Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                        Err(err) => CarbideError::GenericError(format!(
                            "Error getting credentials for BMC: {:?}",
                            err
                        )),
                    })?;
                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };
                (username, password)
            }

            _ => {
                return Err(Status::invalid_argument(
                    "Please provider either machine_id, or both user and password",
                ));
            }
        };

        // libredfish uses reqwest in blocking mode, making and dropping a runtime
        let _ = tokio::task::spawn_blocking(move || -> Result<(), libredfish::RedfishError> {
            let conf = libredfish::NetworkConfig {
                user: Some(user),
                password: Some(password),
                endpoint: req.ip.clone(),
                // Option<u32> -> Option<u16> because no uint16 in protobuf
                port: req.port.map(|p| p as u16),
                ..Default::default()
            };
            let redfish = libredfish::new(conf)?;
            redfish.boot_once(libredfish::Boot::Pxe)?;
            redfish.power(libredfish::SystemPowerControl::ForceRestart)?;
            tracing::info!("Reboot to PXE requested for {}", req.ip);
            Ok(())
        })
        .await
        .map_err(CarbideError::from)?;

        Ok(Response::new(rpc::AdminRebootResponse {}))
    }

    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataGetRequest>,
    ) -> Result<Response<rpc::BmcMetaDataGetResponse>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_bmc_meta_data", e))?;

        let response = Ok(BmcMetaDataGetRequest::try_from(request.into_inner())?
            .get_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit get_bmc_meta_data", e))?;

        response
    }

    async fn update_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataUpdateRequest>,
    ) -> Result<Response<rpc::BmcMetaDataUpdateResponse>, Status> {
        //Note: Be *careful* when logging this request: do not log the password!
        tracing::Span::current().record(
            "request",
            format!(
                "BmcMetadataUpdateRequest machine_id: {:?} ip: {:?} request_type: {:?}",
                request.get_ref().machine_id,
                request.get_ref().ip,
                request.get_ref().request_type
            ),
        );

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin update_bmc_meta_data", e)
            })?;

        let response = Ok(BmcMetaDataUpdateRequest::try_from(request.into_inner())?
            .update_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit update_bmc_meta_data", e))?;

        response
    }

    async fn update_machine_credentials(
        &self,
        request: Request<MachineCredentialsUpdateRequest>,
    ) -> Result<Response<MachineCredentialsUpdateResponse>, Status> {
        // Note that we don't log the request here via `log_request_data`.
        // Doing that would make credentials show up in the log stream
        tracing::Span::current().record("request", "MachineCredentialsUpdateRequest { }");

        Ok(UpdateCredentials::try_from(request.into_inner())?
            .update(self.credential_provider.as_ref())
            .await
            .map(Response::new)?)
    }

    async fn update_security_group_policy(
        &self,
        request: Request<rpc::SecurityGroupPolicy>,
    ) -> Result<Response<rpc::SecurityGroupPolicy>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn delete_security_group_policy(
        &self,
        request: Request<rpc::SecurityGroupPolicyDeletion>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn bind_security_group(
        &self,
        request: Request<rpc::SecurityGroupBind>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn unbind_security_group(
        &self,
        request: Request<rpc::SecurityGroupBind>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn list_security_group_policies(
        &self,
        request: Request<rpc::SecurityGroupPolicyQuery>,
    ) -> Result<Response<rpc::SecurityGroupPolicyList>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn list_security_group_binds(
        &self,
        request: Request<rpc::SecurityGroupBindQuery>,
    ) -> Result<Response<rpc::SecurityGroupBindList>, Status> {
        log_request_data(&request);

        return Err(Status::unimplemented("not implemented"));
    }

    async fn get_pxe_instructions(
        &self,
        request: Request<rpc::MachineId>,
    ) -> Result<Response<rpc::PxeInstructions>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin get_pxe_instructions", e)
            })?;

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;

        let instance = Instance::find_by_machine_id(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

        let pxe_script = if instance.use_custom_pxe_on_boot {
            Instance::use_custom_ipxe_on_next_boot(&machine_id, false, &mut txn)
                .await
                .map_err(CarbideError::from)?;
            instance.tenant_config.custom_ipxe
        } else {
            "exit".to_string()
        };

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit get_pxe_instructions", e))?;

        Ok(Response::new(rpc::PxeInstructions { pxe_script }))
    }

    /// Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    /// Tells it whether to discover or cleanup based on current machine state.
    async fn forge_agent_control(
        &self,
        request: Request<rpc::ForgeAgentControlRequest>,
    ) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
        log_request_data(&request);

        use ::rpc::forge_agent_control_response::Action;

        let machine_id = match request.into_inner().machine_id {
            Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
            None => {
                log::warn!("forge agent control: missing machine ID");
                return Err(Status::invalid_argument("Missing machine ID"));
            }
        };

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;

        // Treat this message as signal from machine that reboot is finished. Update reboot time.
        machine.update_reboot_time(&mut txn).await?;

        let info = MachineTopology::find_latest_by_machine_ids(&mut txn, &[machine_id.clone()])
            .await
            .map_err(|_| Status::invalid_argument("Missing discovery data"))?
            .remove(&machine_id)
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

        let is_dpu = info.topology().discovery_data.info.is_dpu();
        let dpu_machine = if is_dpu {
            machine.clone()
        } else {
            Machine::find_dpu_by_host_machine_id(&mut txn, &machine_id)
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?
        };

        // Respond based on machine current state
        let state = dpu_machine.current_state();
        let action = if is_dpu {
            match state {
                ManagedHostState::DPUNotReady(MachineState::Init) => Action::Discovery,
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    log::info!(
                        "forge agent control: DPU Machine '{}' in state '{state}'",
                        machine.id()
                    );
                    Action::Noop
                }
            }
        } else {
            match state {
                ManagedHostState::HostNotReady(MachineState::Init) => Action::Retry,
                ManagedHostState::HostNotReady(MachineState::WaitingForDiscovery) => {
                    Action::Discovery
                }
                ManagedHostState::WaitingForCleanup(..) => Action::Reset,
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    log::info!(
                        "forge agent control: Host Machine '{}' in state '{state}'",
                        machine.id()
                    );
                    Action::Noop
                }
            }
        };
        log::info!(
            "forge agent control: machine {} action {:?}",
            machine.id(),
            action
        );
        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit forge_agent_control", e))?;
        Ok(Response::new(rpc::ForgeAgentControlResponse {
            action: action as i32,
        }))
    }

    async fn admin_force_delete_machine(
        &self,
        request: Request<rpc::AdminForceDeleteMachineRequest>,
    ) -> Result<Response<rpc::AdminForceDeleteMachineResponse>, Status> {
        log_request_data(&request);

        let query = request.into_inner().host_query;

        let mut response = rpc::AdminForceDeleteMachineResponse {
            all_done: true,
            ..Default::default()
        };
        // This is the default
        // If we can't delete something in one go - we will reset it
        response.all_done = true;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin investigate admin_force_delete_machine", e)
        })?;

        let machine = match Machine::find_by_query(&mut txn, &query)
            .await
            .map_err(CarbideError::from)?
        {
            Some(machine) => machine,
            None => {
                // If the machine was already deleted, then there is nothing to do
                // and this is a success
                return Ok(Response::new(response));
            }
        };

        // TODO: This should maybe just use the snapshot loading functionality that the
        // state controller will use - which already contains the combined state
        let host_machine;
        let dpu_machine;
        if machine.is_dpu() {
            host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, machine.id()).await?;
            log::info!(
                "Found host Machine {:?}",
                host_machine.as_ref().map(|m| m.id().to_string())
            );
            dpu_machine = Some(machine);
        } else {
            dpu_machine = Machine::find_dpu_by_host_machine_id(&mut txn, machine.id()).await?;
            log::info!(
                "Found dpu Machine {:?}",
                dpu_machine.as_ref().map(|m| m.id().to_string())
            );
            host_machine = Some(machine);
        }

        let mut instance_id = None;
        if let Some(host_machine) = &host_machine {
            instance_id = Instance::find_id_by_machine_id(&mut txn, host_machine.id())
                .await
                .map_err(CarbideError::from)?;
        }

        if let Some(host_machine) = &host_machine {
            response.managed_host_machine_id = host_machine.id().to_string();
            if let Some(iface) = host_machine.interfaces().get(0) {
                response.managed_host_machine_interface_id = iface.id().to_string();
            }
            if let Some(ip) = host_machine.bmc_ip() {
                response.managed_host_bmc_ip = ip.to_string();
            }
        }
        if let Some(dpu_machine) = &dpu_machine {
            response.dpu_machine_id = dpu_machine.id().to_string();
            if let Some(iface) = dpu_machine.interfaces().get(0) {
                response.dpu_machine_interface_id = iface.id().to_string();
            }
            if let Some(ip) = dpu_machine.bmc_ip() {
                response.dpu_bmc_ip = ip.to_string();
            }
        }
        if let Some(instance_id) = &instance_id {
            response.instance_id = instance_id.to_string();
        }

        // So far we only inspected state - now we start the deletion process
        // TODO: In the new model we might just need to move one Machine to this state
        if let Some(host_machine) = &host_machine {
            host_machine
                .advance(&mut txn, ManagedHostState::ForceDeletion, None)
                .await
                .map_err(CarbideError::from)?;
        }
        if let Some(dpu_machine) = &dpu_machine {
            dpu_machine
                .advance(&mut txn, ManagedHostState::ForceDeletion, None)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit admin_force_delete_machine", e)
        })?;

        // We start a new transaction
        // This makeas the ForceDeletion state visible to other consumers

        // Note: The following deletion steps are all ordered in an idempotent fashion

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(
                file!(),
                "begin delete host and instance in admin_force_delete_machine",
                e,
            )
        })?;

        if let Some(instance_id) = instance_id {
            match self
                .vpc_api
                .try_delete_managed_resources(instance_id)
                .await
                .map_err(CarbideError::from)?
            {
                Poll::Ready(()) => {
                    // TODO: Get the actual number back and set it
                    response.deleted_managed_resources = 1;
                }
                Poll::Pending => {
                    response.all_done = false;
                    return Ok(Response::new(response));
                }
            }

            // Delete the instance and allocated address
            // TODO: This might need some changes with the new state machine
            let delete_instance = DeleteInstance { instance_id };
            let _instance = delete_instance.delete(&mut txn).await?;
        }

        if let Some(machine) = &host_machine {
            Machine::force_cleanup(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(
                file!(),
                "end delete host and instance in admin_force_delete_machine",
                e,
            )
        })?;

        if let Some(dpu_machine) = &dpu_machine {
            match self
                .vpc_api
                .try_delete_leaf(dpu_machine.id())
                .await
                .map_err(CarbideError::from)?
            {
                Poll::Ready(()) => {
                    // TODO: Get the actual number back and set it
                    response.deleted_leafs = 1;
                }
                Poll::Pending => {
                    response.all_done = false;
                    return Ok(Response::new(response));
                }
            }

            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(
                    file!(),
                    "begin delete dpu in admin_force_delete_machine",
                    e,
                )
            })?;

            Machine::force_cleanup(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;

            txn.commit().await.map_err(|e| {
                CarbideError::DatabaseError(
                    file!(),
                    "end delete dpu in admin_force_delete_machine",
                    e,
                )
            })?;
        }

        Ok(Response::new(response))
    }
}

const FORGE_ROOT_PEMFILE_PATH: &str = "/opt/forge/forge_root.pem";
const FORGE_ROOT_KEYFILE_PATH: &str = "/opt/forge/forge_root.key";

///
/// this function blocks, don't use it in a raw async context
fn get_tls_acceptor() -> Option<TlsAcceptor> {
    let certs = {
        let fd = match std::fs::File::open(FORGE_ROOT_PEMFILE_PATH) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);
        match rustls_pemfile::certs(&mut buf) {
            Ok(certs) => certs.into_iter().map(Certificate).collect(),
            Err(error) => {
                log::error!("Rustls error reading certs: {:?}", error);
                return None;
            }
        }
    };
    let key = {
        let fd = match std::fs::File::open(FORGE_ROOT_KEYFILE_PATH) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);
        match rustls_pemfile::pkcs8_private_keys(&mut buf) {
            Ok(keys) => {
                if let Some(key) = keys.into_iter().map(PrivateKey).next() {
                    key
                } else {
                    log::error!("Rustls error reading key: no keys?");
                    return None;
                }
            }
            Err(error) => {
                log::error!("Rustls error reading key: {:?}", error);
                return None;
            }
        }
    };

    match ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(mut tls) => {
            tls.alpn_protocols = vec![b"h2".to_vec()];
            Some(TlsAcceptor::from(Arc::new(tls)))
        }
        Err(error) => {
            log::error!("Rustls error building server config: {:?}", error);
            None
        }
    }
}

async fn check_auth<B>(
    request: &HyperRequest<B>,
    peer_certs: Arc<Vec<Certificate>>,
) -> AuthorizationType {
    if let Some(peer_cert) = peer_certs.first() {
        //TODO: actually check that this cert is in some way "valid".  Also, check more than just the first one in the list?
        return AuthorizationType::Certificate(peer_cert.clone());
    } else if let Some(header) = request.headers().get(AUTHORIZATION) {
        //TODO: validate that the token is an encoded, valid JWT
        return AuthorizationType::Jwt(
            header
                .to_str()
                .expect("header not a valid utf8 string?")
                .to_string(),
        );
    } else if request
        .uri()
        .to_string()
        .to_lowercase()
        .contains("discovermachine")
        || request.uri().to_string().to_lowercase().contains("echo")
    //TODO: using this to test, delete the "echo" check once discover machine is tested
    {
        return AuthorizationType::TrustedHardwareIdentifier(None);
    } else if request
        .uri()
        .to_string()
        .to_lowercase()
        .contains("reflection")
    {
        if let Some(user_agent) = request.headers().get(USER_AGENT) {
            if user_agent
                .to_str()
                .expect("header not a valid utf8 string?")
                .to_lowercase()
                .contains("grpc")
            {
                // grpc needs this to function, allow it
                return AuthorizationType::TrustedHardwareIdentifier(None);
            }
        }
    }

    log::error!(
        "failed to authorize request.  Peer certs: {:?}.  Headers: {:?}. URI: {:?}",
        peer_certs,
        request.headers(),
        request.uri()
    );
    AuthorizationType::Unauthorized
}

#[derive(Debug)]
enum AuthorizationType {
    Certificate(Certificate),
    Jwt(
        String, /*TODO: type this as some kind of proper JWT struct not just a string*/
    ),
    TrustedHardwareIdentifier(
        Option<String>, /*TODO: make this not optional once we require TPMs*/
    ),
    Unauthorized,
}

#[derive(Debug, Clone)]
struct MiddlewareAuth {
    addr: SocketAddr,
    peer_certs: Arc<Vec<Certificate>>,
}

impl<B> AsyncAuthorizeRequest<B> for MiddlewareAuth
where
    B: Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = BoxBody;
    type Future = BoxFuture<'static, Result<HyperRequest<B>, HyperResponse<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: HyperRequest<B>) -> Self::Future {
        let peer_certs = self.peer_certs.clone();
        let addr = self.addr;
        Box::pin(async move {
            let authorization_type = check_auth(&request, peer_certs).await;

            match authorization_type {
                AuthorizationType::Unauthorized => {
                    let boxed = BoxBody::default();
                    let unauthorized_response = HyperResponse::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(boxed)
                        .unwrap();
                    let _unused_error_response: Result<
                        HyperRequest<B>,
                        HyperResponse<Self::ResponseBody>,
                    > = Err(unauthorized_response); // TODO: the explicit type is only needed because it's unused, we can delete the type hint when we use the error.

                    request.extensions_mut().insert(ConnInfo {
                        addr,
                        authorization_type: AuthorizationType::Unauthorized,
                    }); //TODO: this is only necessary because we're not erroring out, delete the entire line when we reject unauthorized requests
                    Ok(request) //TODO: remove this and return the previous error to reject unauthorized requests
                }
                authorized_request_type => {
                    request.extensions_mut().insert(ConnInfo {
                        addr,
                        authorization_type: authorized_request_type,
                    });

                    Ok(request)
                }
            }
        })
    }
}

#[derive(Debug)]
struct ConnInfo {
    addr: SocketAddr,
    authorization_type: AuthorizationType,
}

#[tracing::instrument(skip_all)]
async fn api_handler<C>(
    api_service: Arc<Api<C>>,
    listen_port: SocketAddr,
    meter: Meter,
) -> Result<(), Report>
where
    C: CredentialProvider + 'static,
{
    let api_reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
        .build()?;

    let tls_acceptor = tokio::task::spawn_blocking(get_tls_acceptor).await?;

    let listener = TcpListener::bind(listen_port).await?;
    let mut http = Http::new();
    http.http2_only(true);

    let svc = Server::builder()
        .layer(LogLayer::new(meter))
        .add_service(rpc::forge_server::ForgeServer::from_arc(api_service))
        .add_service(api_reflection_service)
        .into_service();

    loop {
        let (conn, addr) = match listener.accept().await {
            Ok(incoming) => incoming,
            Err(e) => {
                log::error!("Error accepting connection: {}", e);
                continue;
            }
        };
        let http = http.clone();
        let tls_acceptor = tls_acceptor.clone();
        let svc = svc.clone();

        tokio::spawn(async move {
            if let Some(tls_acceptor) = tls_acceptor {
                let mut certificates = Vec::new();

                match tls_acceptor
                    .accept_with(conn, |info| {
                        if let Some(certs) = info.peer_certificates() {
                            for cert in certs {
                                certificates.push(cert.clone());
                            }
                        }
                    })
                    .await
                {
                    Ok(conn) => {
                        let auth = MiddlewareAuth {
                            addr,
                            peer_certs: Arc::new(certificates),
                        };
                        let svc = tower::ServiceBuilder::new()
                            .layer(AsyncRequireAuthorizationLayer::new(auth))
                            .service(svc);
                        if let Err(error) = http.serve_connection(conn, svc).await {
                            log::debug!("error servicing http connection: {:?}", error);
                        }
                    }
                    Err(error) => {
                        log::error!("error accepting tls connection: {:?}", error);
                    }
                }
            } else if let Err(error) = http.serve_connection(conn, svc).await {
                log::debug!("error servicing http connection: {:?}", error);
            }
        });
    }
}

fn log_request_data<T: std::fmt::Debug>(request: &Request<T>) {
    tracing::Span::current().record("request", format!("{:?}", request.get_ref()));
}

impl<C> Api<C>
where
    C: CredentialProvider + 'static,
{
    pub fn new(
        credential_provider: Arc<C>,
        database_connection: sqlx::PgPool,
        authorizer: auth::Authorizer,
        vpc_api: Arc<dyn VpcApi>,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            authorizer,
            vpc_api,
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn run(
        daemon_config: &cfg::Daemon,
        credential_provider: Arc<C>,
        meter: opentelemetry::metrics::Meter,
    ) -> Result<(), Report> {
        let service_config = if daemon_config.kubernetes {
            ServiceConfig::default()
        } else {
            ServiceConfig::for_local_development()
        };

        let database_connection = sqlx::pool::PoolOptions::new()
            .max_connections(service_config.max_db_connections)
            .connect(&daemon_config.datastore)
            .await?;
        let stats_pool = database_connection.clone();
        let health_pool = database_connection.clone();

        start_export_service_health_metrics(ServiceHealthContext {
            meter: meter.clone(),
            database_pool: health_pool,
        });

        tokio::spawn(async move {
            loop {
                log::info!("Active DB connections: {}", stats_pool.size());
                tokio::time::sleep(service_config.db_stats_interval).await;
            }
        });

        let vpc_api: Arc<dyn VpcApi> = if daemon_config.kubernetes {
            let client = kube::Client::try_default().await?;
            Arc::new(VpcApiImpl::new(client, daemon_config.dhcp_server.clone()))
        } else {
            Arc::new(VpcApiSim::default())
        };

        let conn_clone = database_connection.clone();
        let authorizer = auth::Authorizer::build_casbin(
            &daemon_config.casbin_policy_file,
            daemon_config.auth_permissive_mode,
        )
        .await?;

        let api_service = Arc::new(Self::new(
            credential_provider.clone(),
            database_connection.clone(),
            authorizer,
            vpc_api.clone(),
        ));

        // handle should be stored in a variable. If is is dropped by compiler, main event will be dropped.
        let _handle = ipmi_handler(
            conn_clone,
            RealIpmiCommandHandler {},
            credential_provider.clone(),
        )
        .await?;

        let _kube_handle = bgkubernetes_handler(
            daemon_config.kubernetes,
            api_service.clone(),
            database_connection.clone(),
        )
        .await?;

        let _machine_state_controller_handle =
            StateController::<MachineStateControllerIO>::builder()
                .database(database_connection.clone())
                .vpc_api(vpc_api.clone())
                .forge_api(api_service.clone())
                .iteration_time(service_config.machine_state_controller_iteration_time)
                .state_handler(Arc::new(MachineStateHandler::default()))
                .build()
                .expect("Unable to build MachineStateController");

        let _network_segment_controller_handle =
            StateController::<NetworkSegmentStateControllerIO>::builder()
                .database(database_connection)
                .vpc_api(vpc_api)
                .forge_api(api_service.clone())
                .iteration_time(service_config.network_segment_state_controller_iteration_time)
                .state_handler(Arc::new(NetworkSegmentStateHandler::new(
                    service_config.network_segment_drain_time,
                )))
                .build()
                .expect("Unable to build NetworkSegmentController");

        let listen_port = daemon_config.listen[0];
        api_handler(api_service, listen_port, meter).await
    }

    async fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> CarbideResult<(Machine, sqlx::Transaction<'_, sqlx::Postgres>)> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin load_machine", e))?;
        let machine = match Machine::find_one(&mut txn, machine_id, search_config).await {
            Err(err) => {
                log::warn!("loading machine for {machine_id}: {err}.");
                return Err(CarbideError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                log::info!("no machine for {machine_id}");
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
            Ok(Some(m)) => m,
        };
        Ok((machine, txn))
    }
}

/// Configurations that are not yet exposed via the CLI
///
/// We might want to integrate those into a toml file instead of hardcoding,
/// but for now this will do it
struct ServiceConfig {
    /// The time for which network segments must have 0 allocated IPs, before they
    /// are actually released
    network_segment_drain_time: chrono::Duration,
    /// Iteration time for the machine state controller
    machine_state_controller_iteration_time: std::time::Duration,
    /// Iteration time for the network segment state controller
    network_segment_state_controller_iteration_time: std::time::Duration,
    /// Maximum datebase connections
    max_db_connections: u32,
    /// The interval in which the time amount of active database connections will be printed
    db_stats_interval: std::time::Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::minutes(5),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(30),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(30),
            max_db_connections: 1000,
            db_stats_interval: std::time::Duration::from_secs(60),
        }
    }
}

impl ServiceConfig {
    /// Configuration for local development
    ///
    /// Components are running faster, so we can observe state changes without waiting too long.
    /// Machine state controller is kept normal for now, since it's output is noisy.
    pub fn for_local_development() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::seconds(60),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(10),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(2),
            max_db_connections: 1000,
            db_stats_interval: std::time::Duration::from_secs(60),
        }
    }
}
