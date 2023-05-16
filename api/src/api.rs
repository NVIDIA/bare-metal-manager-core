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

use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::task::Poll;

pub use ::rpc::forge as rpc;
use ::rpc::protos::forge::{
    CreateTenantKeysetRequest, CreateTenantKeysetResponse, CreateTenantRequest,
    CreateTenantResponse, DeleteTenantKeysetRequest, DeleteTenantKeysetResponse, EchoRequest,
    EchoResponse, FindTenantKeysetRequest, FindTenantKeysetResponse, FindTenantRequest,
    FindTenantResponse, IbSubnet, IbSubnetCreationRequest, IbSubnetDeletionRequest,
    IbSubnetDeletionResult, IbSubnetList, IbSubnetQuery, InstanceList,
    MachineCredentialsUpdateRequest, MachineCredentialsUpdateResponse, UpdateTenantKeysetRequest,
    UpdateTenantKeysetResponse, UpdateTenantRequest, UpdateTenantResponse,
    ValidateTenantPublicKeyRequest, ValidateTenantPublicKeyResponse,
};
use chrono::Duration;
use forge_credentials::{CredentialKey, CredentialProvider, Credentials};
use futures_util::future::BoxFuture;
use http::header::USER_AGENT;
use http::{header::AUTHORIZATION, StatusCode};
use hyper::server::conn::Http;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use opentelemetry::metrics::Meter;
use sqlx::{Postgres, Transaction};
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
use tracing::{debug, info, warn};
use uuid::Uuid;

use self::rpc::forge_server::Forge;
use crate::db::dpu_machine::DpuMachine;
use crate::db::ipmi::UserRoles;
use crate::db::machine::MachineSearchConfig;
use crate::db::network_segment::NetworkSegmentSearchConfig;
use crate::db::vpc_resource_leaf::VpcResourceLeaf;
use crate::ipxe::PxeInstructions;
use crate::model::machine::machine_id::try_parse_machine_id;
use crate::model::machine::network::MachineNetworkStatus;
use crate::model::machine::ManagedHostState;
use crate::model::RpcDataConversionError;
use crate::reachability::PingReachabilityChecker;
use crate::resource_pool::{DbResourcePool, OwnerType, ResourcePoolError};
use crate::state_controller::controller::ReachabilityParams;
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
    ethernet_virtualization,
    instance::{allocate_instance, InstanceAllocationRequest},
    ipmi::{ipmi_handler, MachineBmcRequest, RealIpmiCommandHandler},
    kubernetes::{VpcApi, VpcApiImpl, VpcApiSim},
    logging::{
        api_logs::LogLayer,
        service_health_metrics::{start_export_service_health_metrics, ServiceHealthContext},
    },
    model::{
        hardware_info::HardwareInfo,
        instance::status::network::InstanceNetworkStatusObservation,
        machine::{machine_id::MachineId, MachineState},
    },
    redfish::{RedfishClientPool, RedfishClientPoolImpl},
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

/// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

// vxlan5555 is special HBN single vxlan device. It handles networking between machines on the
// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan5555";

// If you set this to true forge-dpu-agent will start writing the HBN files (frr.conf, etc)
// If you leave it false forge-dpu-agent will write files with a .TEST extension.
const ETH_VIRT_PRODUCTION_MODE: bool = false;

pub struct Api<C: CredentialProvider> {
    database_connection: sqlx::PgPool,
    credential_provider: Arc<C>,
    authorizer: auth::Authorizer,
    redfish_pool: Arc<dyn RedfishClientPool>,
    vpc_api: Arc<dyn VpcApi>,
    eth_data: ethernet_virtualization::EthVirtData,
    identity_pemfile_path: String,
    identity_keyfile_path: String,
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

    async fn find_ib_subnets(
        &self,
        _: Request<IbSubnetQuery>,
    ) -> Result<Response<IbSubnetList>, Status> {
        todo!()
    }

    async fn create_ib_subnet(
        &self,
        _: Request<IbSubnetCreationRequest>,
    ) -> Result<Response<IbSubnet>, Status> {
        todo!()
    }

    async fn delete_ib_subnet(
        &self,
        _: Request<IbSubnetDeletionRequest>,
    ) -> Result<Response<IbSubnetDeletionResult>, Status> {
        todo!()
    }

    async fn ib_subnets_for_vpc(
        &self,
        _: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<IbSubnetList>, Status> {
        todo!()
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

        let mut new_network_segment = NewNetworkSegment::try_from(request.into_inner())?;
        new_network_segment.vlan_id = self
            .allocate_vlan_id(&mut txn, &new_network_segment.name)
            .await?;
        new_network_segment.vni = self
            .allocate_vni(&mut txn, &new_network_segment.name)
            .await?;
        let network_segment = new_network_segment
            .persist(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        let response = Ok(Response::new(network_segment.try_into()?));
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
        log_machine_id(&request.machine_id);
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

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;
        log_machine_id(&machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_instance_by_machine_id",
                e,
            ))
        })?;

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

        log_machine_id(&instance.machine_id);

        if instance.deleted.is_some() {
            log::info!(
                "Instance {} is already marked for deletion.",
                delete_instance.instance_id,
            );
            return Ok(Response::new(rpc::InstanceReleaseResult {}));
        }

        let _ = delete_instance.mark_as_deleted(&mut txn).await?;

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

        if !self.eth_data.is_enabled {
            // Carbide API does not own VPC data, forge-dpu-agent should not do anything
            return Err(CarbideError::NotImplemented.into());
        }

        let request = request.into_inner();
        let dpu_machine_id = match &request.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine id"));
            }
        };
        log_machine_id(&dpu_machine_id);

        let loader = DbSnapshotLoader::default();
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_managed_host_network_config", e)
        })?;

        let snapshot = loader
            .load_machine_snapshot(&mut txn, &dpu_machine_id)
            .await
            .map_err(CarbideError::from)?;

        let loopback_ip = match snapshot.dpu_snapshot.loopback_ip() {
            Some(ip) => ip,
            None => {
                return Err(Status::failed_precondition(format!(
                    "Machine {dpu_machine_id} needs discovery. Does not have a loopback IP yet."
                )));
            }
        };
        let use_admin_network = snapshot.dpu_snapshot.use_admin_network();

        let admin_interface_rpc =
            ethernet_virtualization::admin_network(&mut txn, &snapshot.host_snapshot.machine_id)
                .await?;

        let tenant_interfaces = match &snapshot.instance {
            None => vec![],
            Some(instance) => {
                let interfaces = &instance.config.network.interfaces;
                let mut tenant_interfaces = Vec::with_capacity(interfaces.len());
                for iface in interfaces {
                    tenant_interfaces.push(
                        ethernet_virtualization::tenant_network(
                            &mut txn,
                            instance.instance_id,
                            iface,
                        )
                        .await?,
                    );
                }
                tenant_interfaces
            }
        };

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_managed_host_network_config",
                e,
            ))
        })?;

        let host_config = rpc::ManagedHostNetworkConfig {
            loopback_ip: loopback_ip.to_string(),
        };

        let resp = rpc::ManagedHostNetworkConfigResponse {
            is_production_mode: ETH_VIRT_PRODUCTION_MODE,
            asn: self.eth_data.asn,
            dhcp_servers: self.eth_data.dhcp_servers.clone(),
            vni_device: if use_admin_network {
                "".to_string()
            } else {
                HBN_SINGLE_VLAN_DEVICE.to_string()
            },
            managed_host_config: Some(host_config),
            managed_host_config_version: snapshot
                .dpu_snapshot
                .network_config
                .version
                .to_version_string(),
            use_admin_network,
            admin_interface: Some(admin_interface_rpc),
            tenant_interfaces,
            instance_config_version: if use_admin_network {
                "".to_string()
            } else {
                snapshot
                    .instance
                    .unwrap()
                    .network_config_version
                    .to_version_string()
            },
        };
        Ok(Response::new(resp))
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
        log_machine_id(&machine_id);

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
        log_machine_id(&machine_power_request.machine_id);

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
            .reboot_machine(self.database_connection.clone(), self.redfish_pool.clone())
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
        //TODO: actually implement this
        Ok(Response::new(ValidateTenantPublicKeyResponse {}))
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

        let interface_id = match &machine_discovery_info.machine_interface_id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("An interface UUID is required"));
            }
        };

        let discovery_data = machine_discovery_info
            .discovery_data
            .map(|data| match data {
                rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
            })
            .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;
        let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

        // Generate a stable Machine ID based on the hardware information
        let stable_machine_id = MachineId::from_hardware_info(&hardware_info).ok_or_else(|| {
            CarbideError::InvalidArgument(
                format!("Insufficient HardwareInfo to derive a Stable Machine ID for Machine on InterfaceId {}", interface_id),
            )
        })?;
        log_machine_id(&stable_machine_id);

        if !hardware_info.is_dpu() && hardware_info.tpm_ek_certificate.is_none() {
            return Err(CarbideError::InvalidArgument(format!(
                "Ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {}",
                interface_id
            ))
            .into());
        }

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin discover_machine", e))?;

        let interface = MachineInterface::find_one(&mut txn, interface_id).await?;
        let (machine, loopback_ip) = if hardware_info.is_dpu() {
            let (db_machine, is_new) = Machine::get_or_create(
                &mut txn,
                &stable_machine_id,
                interface,
                hardware_info.is_dpu(),
            )
            .await?;

            let loopback_ip = if is_new {
                let loopback_ip = self
                    .allocate_loopback_ip(&mut txn, &stable_machine_id.to_string())
                    .await?;
                let (mut netconf, version) = db_machine.network_config().clone().take();
                netconf.loopback_ip = loopback_ip;
                netconf.use_admin_network = Some(true);
                Machine::try_update_network_config(&mut txn, &stable_machine_id, version, &netconf)
                    .await
                    .map_err(CarbideError::from)?;
                loopback_ip
            } else {
                None
            };
            (db_machine, loopback_ip)
        } else {
            // Now we know stable machine id for host. Let's update it in db.
            (
                Machine::try_sync_stable_id_with_current_machine_id_for_host(
                    &mut txn,
                    &interface.machine_id,
                    &stable_machine_id,
                )
                .await?,
                None,
            )
        };

        // Once VPC goes away we can remove passing loopback_ip here
        MachineTopology::create(&mut txn, &stable_machine_id, &hardware_info, loopback_ip).await?;

        // Create Host proactively.
        if hardware_info.is_dpu() {
            // In case host interface is created, this method will return existing one, instead
            // creating new everytime.
            let machine_interface = MachineInterface::create_host_machine_interface_proactively(
                &mut txn,
                Some(&hardware_info),
                machine.id(),
            )
            .await?;

            // Create host machine with temporary ID if no machine is attached.
            if machine_interface.machine_id.is_none() {
                let predicted_machine_id =
                    MachineId::host_id_from_dpu_hardware_info(&hardware_info).ok_or_else(|| {
                        CarbideError::InvalidArgument("hardware info".to_string())
                    })?;
                let mi_id = machine_interface.id;
                let (proactive_machine, _) = Machine::get_or_create(
                    &mut txn,
                    &predicted_machine_id,
                    machine_interface,
                    false,
                )
                .await?;

                log::info!(
                    "Created host machine proactively (MI:{}, Machine:{})",
                    mi_id,
                    proactive_machine.id(),
                );
            }
        }

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: Some(stable_machine_id.to_string().into()),
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
        log_machine_id(&machine_id);

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
        log_machine_id(&machine_id);

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

    /// Invoked by forge-scout whenever a certain Machine can not be properly acted on
    async fn report_forge_scout_error(
        &self,
        request: tonic::Request<rpc::ForgeScoutErrorReport>,
    ) -> Result<tonic::Response<rpc::ForgeScoutErrorReportResult>, tonic::Status> {
        log_request_data(&request);
        if let Some(machine_id) = request.get_ref().machine_id.as_ref() {
            let machine_id = try_parse_machine_id(machine_id).map_err(CarbideError::from)?;
            log_machine_id(&machine_id);
        }

        // `log_request_data` will already provide us the error message
        // Therefore we don't have to do anything else
        Ok(Response::new(rpc::ForgeScoutErrorReportResult {}))
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
        log_machine_id(&machine_id);
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
                log_machine_id(&machine_id);
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
                        // We never return PredictedHost
                        ty.is_host() || (ty.is_dpu() && include_dpus)
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
    //  grpcurl -d '{"host_id": "neptune-bravo"}' -insecure 127.0.0.1:1079 forge.Forge/GetDpuSSHCredential | jq -r -j ".password"
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
                log_machine_id(machine.id());
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
                let machine_id = MachineId::from_str(&machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id.clone()))
                })?;
                log_machine_id(&machine_id);

                // Load credentials from Vault
                let credentials = self
                    .credential_provider
                    .get_credentials(CredentialKey::Bmc {
                        user_role: UserRoles::Administrator.to_string(),
                        machine_id: machine_id.to_string(),
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
        tokio::task::spawn_blocking(move || -> Result<(), libredfish::RedfishError> {
            let endpoint = libredfish::Endpoint {
                user: Some(user),
                password: Some(password),
                host: req.ip.clone(),
                // Option<u32> -> Option<u16> because no uint16 in protobuf
                port: req.port.map(|p| p as u16),
            };

            let pool = libredfish::RedfishClientPool::builder().build()?;
            let redfish = pool.create_client(endpoint)?;
            tracing::info!("Switching boot order for {}", req.ip);
            redfish.boot_once(libredfish::Boot::Pxe)?;
            tracing::info!("Force restarting {}", req.ip);
            redfish.power(libredfish::SystemPowerControl::ForceRestart)?;
            tracing::info!("Reboot request succeeded for {}", req.ip);
            Ok(())
        })
        .await
        .map_err(CarbideError::from)?
        .map_err(CarbideError::from)?;

        Ok(Response::new(rpc::AdminRebootResponse {}))
    }

    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataGetRequest>,
    ) -> Result<Response<rpc::BmcMetaDataGetResponse>, Status> {
        log_request_data(&request);
        let request = BmcMetaDataGetRequest::try_from(request.into_inner())?;
        log_machine_id(&request.machine_id);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_bmc_meta_data", e))?;

        let response = Ok(request
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
        let Some(bmc_info) = request.get_ref().bmc_info.clone() else {
            return Err(CarbideError::InvalidArgument("Missing BMC Information".to_owned()).into());
        };

        // Note: Be *careful* when logging this request: do not log the password!
        tracing::Span::current().record(
            "request",
            format!(
                "BmcMetadataUpdateRequest machine_id: {:?} ip: {:?} request_type: {:?}",
                request.get_ref().machine_id,
                bmc_info.ip,
                request.get_ref().request_type
            ),
        );

        if let Some(conn_info) = request.extensions().get::<ConnInfo>() {
            log::info!(
                "Got a UpdateBmcMetadata request from: {:?} with authorization_type: {:?}",
                conn_info.addr,
                conn_info.authorization_type,
            );
        }

        let request = BmcMetaDataUpdateRequest::try_from(request.into_inner())?;
        log_machine_id(&request.machine_id);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin update_bmc_meta_data", e)
            })?;

        let response = Ok(request
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

        let request =
            UpdateCredentials::try_from(request.into_inner()).map_err(CarbideError::from)?;
        log_machine_id(&request.machine_id);

        Ok(request
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
        request: Request<rpc::PxeInstructionRequest>,
    ) -> Result<Response<rpc::PxeInstructions>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin get_pxe_instructions", e)
            })?;

        let request = request.into_inner();

        let interface_id = match request.interface_id {
            None => {
                return Err(Status::invalid_argument("Interface ID is missing."));
            }
            Some(interface_id) => Uuid::try_from(interface_id)
                .map_err(|e| Status::invalid_argument(format!("Interface ID is invalid: {}", e)))?,
        };

        let arch = rpc::MachineArchitecture::from_i32(request.arch)
            .ok_or(Status::invalid_argument("Unknown arch received."))?;
        let pxe_script =
            PxeInstructions::get_pxe_instructions(&mut txn, interface_id, arch).await?;

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
        log_machine_id(&machine_id);

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;

        // Treat this message as signal from machine that reboot is finished. Update reboot time.
        machine.update_reboot_time(&mut txn).await?;

        let is_dpu = machine.is_dpu();
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
                ManagedHostState::DPUNotReady {
                    machine_state: MachineState::Init,
                } => Action::Discovery,
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
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::Init,
                } => Action::Retry,
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::WaitingForDiscovery,
                } => Action::Discovery,
                ManagedHostState::WaitingForCleanup { .. } => Action::Reset,
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
        response.initial_lockdown_state = "".to_string();
        response.machine_unlocked = false;

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
        log_machine_id(machine.id());

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
            if let Some(ip) = host_machine.bmc_info().ip.as_ref() {
                response.managed_host_bmc_ip = ip.to_string();
            }
        }
        if let Some(dpu_machine) = &dpu_machine {
            response.dpu_machine_id = dpu_machine.id().to_string();
            if let Some(iface) = dpu_machine.interfaces().get(0) {
                response.dpu_machine_interface_id = iface.id().to_string();
            }
            if let Some(ip) = dpu_machine.bmc_info().ip.as_ref() {
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
                    response.managed_resource_deletion_pending = true;
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
            if let Some(ip) = machine.bmc_info().ip.as_deref() {
                tracing::info!(
                    "BMC ip {} for machine {} was found. Trying to perform Bios unlock",
                    ip,
                    machine.id().to_string()
                );

                match self
                    .redfish_pool
                    .create_client(machine.id(), ip, None)
                    .await
                {
                    Ok(client) => {
                        let machine_id = machine.id().clone();
                        match tokio::task::spawn_blocking(move || match client.lockdown_status() {
                            Ok(status) if status.is_fully_disabled() => {
                                tracing::info!(
                                    "Bios for Machine {} is not locked down",
                                    machine_id
                                );
                                (status.to_string(), false)
                            }
                            Ok(status) => {
                                tracing::info!(
                                    "Bios for Machine {} is in status {:?}. Unlocking",
                                    machine_id,
                                    status
                                );
                                if let Err(e) =
                                    client.lockdown(libredfish::EnabledDisabled::Disabled)
                                {
                                    tracing::warn!(
                                        "Failed to unlock Machine {}: {}",
                                        machine_id,
                                        e
                                    );
                                    (status.to_string(), false)
                                } else {
                                    (status.to_string(), true)
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to fetch lockdown status for Machine {}: {}",
                                    machine_id,
                                    e
                                );
                                ("".to_string(), false)
                            }
                        })
                        .await
                        {
                            Ok((previous_state, unlocked)) => {
                                response.initial_lockdown_state = previous_state;
                                response.machine_unlocked = unlocked;
                            }
                            Err(e) => {
                                tracing::error!("Failed to join tokio task: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create Redfish client for machine {} due to {}. Skipping bios unlock", machine.id().to_string(), e);
                    }
                }
            }
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
                    response.deleted_leafs = 1;
                }
                Poll::Pending => {
                    response.leaf_deletion_pending = true;
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

            let actual_dpu_machine = DpuMachine::find_by_machine_id(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;
            if let Some(pool) = self.eth_data.pool_loopback_ip.as_ref() {
                // Forge is managing loopback IPs..
                let l_ip = dpu_machine
                    .loopback_ip() // .. and owns ethernet virtualization.
                    .or_else(|| actual_dpu_machine.vpc_loopback_ip()); // .. and sends them to VPC.
                if let Some(loopback_ip) = l_ip {
                    pool.release(&mut txn, loopback_ip)
                        .await
                        .map_err(CarbideError::from)?
                }
            }

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

    async fn admin_define_resource_pool(
        &self,
        request: Request<rpc::DefineResourcePoolRequest>,
    ) -> Result<Response<rpc::DefineResourcePoolResponse>, Status> {
        log_request_data(&request);

        let def = request.into_inner();
        let pool_type = rpc::ResourcePoolType::try_from(def.pool_type)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
        let name = &def.name;
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin admin_define_resource_pool", e)
        })?;
        for range in def.ranges {
            match pool_type {
                rpc::ResourcePoolType::Ipv4 => {
                    let values = expand_ip_range(&range.start, &range.end)
                        .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
                    let num_values = values.len();
                    let pool = DbResourcePool::new(name.to_string());
                    pool.populate(&mut txn, values)
                        .await
                        .map_err(CarbideError::from)?;
                    tracing::debug!("Populated IP resource pool {name} with {num_values} values");
                }
                rpc::ResourcePoolType::Integer => {
                    let values = expand_int_range(&range.start, &range.end)
                        .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
                    let num_values = values.len();
                    let pool = DbResourcePool::new(name.to_string());
                    pool.populate(&mut txn, values)
                        .await
                        .map_err(CarbideError::from)?;
                    tracing::debug!("Populated int resource pool {name} with {num_values} values");
                }
            };
        }
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "end admin_define_resource_pool", e)
        })?;
        Ok(Response::new(rpc::DefineResourcePoolResponse {}))
    }

    async fn migrate_vpc(
        &self,
        request: Request<rpc::MigrateVpcRequest>,
    ) -> Result<tonic::Response<rpc::MigrateVpcResponse>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin migrate_vpc ", e))?;

        for vname in req.vnames {
            let segment =
                match NetworkSegment::find_by_circuit_id(&mut txn, &vname.dhcp_circuit_id).await {
                    Err(_) => {
                        // this happens, it's probably fine
                        info!(
                            "migrate_vpc no network segment for circuit_id {}, skipping.",
                            vname.dhcp_circuit_id
                        );
                        continue;
                    }
                    Ok(segment) => segment,
                };

            if segment.vlan_id.is_none() || segment.vlan_id.unwrap() != vname.vlan_id as i16 {
                NetworkSegment::update_vlan_id(&mut txn, segment.id, vname.vlan_id as i32)
                    .await
                    .map_err(CarbideError::from)?;
                match self.eth_data.pool_vlan_id.as_ref() {
                    Some(pool) => {
                        pool.mark_allocated(
                            &mut txn,
                            vname.vlan_id as i16,
                            OwnerType::NetworkSegment,
                            &segment.id.to_string(),
                        )
                        .await
                        .map_err(CarbideError::from)?;
                    }
                    None => {
                        warn!("Missing vlan_id resource pool. Did you run 'forge-admin-cli resource-pool define'?");
                    }
                }
                debug!("Segment {} copied vlan_id {}", segment.id, vname.vlan_id);
            }

            if segment.vni.is_none() || segment.vni.unwrap() as u32 != vname.vni {
                NetworkSegment::update_vni(&mut txn, segment.id, vname.vni as i32)
                    .await
                    .map_err(CarbideError::from)?;
                match self.eth_data.pool_vni.as_ref() {
                    Some(pool) => {
                        pool.mark_allocated(
                            &mut txn,
                            vname.vni as i32,
                            OwnerType::NetworkSegment,
                            &segment.id.to_string(),
                        )
                        .await
                        .map_err(CarbideError::from)?;
                    }
                    None => {
                        warn!("Missing vni resource pool. Did you run 'forge-admin-cli resource-pool define'?");
                    }
                }
                debug!("Segment {} copied vni {}", segment.id, vname.vni);
            }
        }

        // Copy vpc_resource_leaf.loopback_ip to machines.network_config.loopback_ip
        let dpus = Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .filter(|m| m.is_dpu());
        for machine in dpus {
            let leaf = match VpcResourceLeaf::find(&mut txn, machine.id()).await {
                Ok(leaf) => leaf,
                Err(err) => {
                    info!("No leaf loopback_ip for machine {}. {err}.", machine.id());
                    continue;
                }
            };
            let (mut netconf, version) = machine.network_config().clone().take();
            let vpc_loopback = match leaf.loopback_ip_address() {
                Some(IpAddr::V4(val)) => Some(*val),
                _ => {
                    warn!("Machine {} has invalid loopback", machine.id());
                    continue;
                }
            };
            if vpc_loopback == netconf.loopback_ip {
                debug!("Machine {} already migrated loopback", machine.id());
                continue;
            }
            netconf.loopback_ip = vpc_loopback;
            Machine::try_update_network_config(&mut txn, machine.id(), version, &netconf)
                .await
                .map_err(CarbideError::from)?;

            match self.eth_data.pool_loopback_ip.as_ref() {
                Some(pool) => {
                    pool.mark_allocated(
                        &mut txn,
                        vpc_loopback.unwrap(), // we know it's Some
                        OwnerType::Machine,
                        &machine.id().to_string(),
                    )
                    .await
                    .map_err(CarbideError::from)?;
                }
                None => {
                    warn!("Missing loopback_ip resource pool. Did you run 'forge-admin-cli resource-pool define' or 'forge-admin-cli migrate vpc'?");
                }
            }

            debug!(
                "Machine {} copied loopback {:?}",
                machine.id(),
                netconf.loopback_ip
            );
        }

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "end migrate_vpc", e))?;

        Ok(Response::new(rpc::MigrateVpcResponse {}))
    }
}

// All the IPv4 addresses between start_s and end_s
fn expand_ip_range(start_s: &str, end_s: &str) -> Result<Vec<Ipv4Addr>, eyre::Report> {
    let start_addr: Ipv4Addr = start_s.parse()?;
    let end_addr: Ipv4Addr = end_s.parse()?;
    let start: u32 = start_addr.into();
    let end: u32 = end_addr.into();
    Ok((start..end).map(Ipv4Addr::from).collect())
}

// All the numbers between start_s and end_s
fn expand_int_range(start_s: &str, end_s: &str) -> Result<Vec<i32>, eyre::Report> {
    let start: i32 = start_s.parse()?;
    let end: i32 = end_s.parse()?;
    Ok((start..end).collect())
}

///
/// this function blocks, don't use it in a raw async context
fn get_tls_acceptor<S: AsRef<str>>(
    identity_pemfile_path: S,
    identity_keyfile_path: S,
) -> Option<TlsAcceptor> {
    let certs = {
        let fd = match std::fs::File::open(identity_pemfile_path.as_ref()) {
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

    let mut key = {
        let fd = match std::fs::File::open(identity_keyfile_path.as_ref()) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);

        match rustls_pemfile::ec_private_keys(&mut buf) {
            Ok(keys) => keys.into_iter().map(PrivateKey).next(),
            error => {
                log::error!("Rustls error reading key: {:?}", error);
                None
            }
        }
    };

    //TODO: remove this fallback hack once we move to EC keys locally
    if key.is_none() {
        key = {
            let fd = match std::fs::File::open(identity_keyfile_path.as_ref()) {
                Ok(fd) => fd,
                Err(_) => return None,
            };
            let mut buf = std::io::BufReader::new(&fd);

            match rustls_pemfile::rsa_private_keys(&mut buf) {
                Ok(keys) => keys.into_iter().map(PrivateKey).next(),
                error => {
                    log::error!("Rustls error reading key: {:?}", error);
                    None
                }
            }
        }
    }

    let key = match key {
        Some(key) => key,
        None => {
            log::error!("Rustls error: no keys?");
            return None;
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
    peer_certs: &Arc<Vec<Certificate>>,
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
    }

    let request_uri = request.uri().to_string().to_lowercase();
    if request_uri.contains("discovermachine") {
        // TODO: we will eventually need the actual hardware identifier in a header to use right here.
        return AuthorizationType::TrustedHardwareIdentifier(None);
    } else if cfg!(debug_assertions) {
        // only in debug builds, allow grpcurl unrestricted access to the API.
        if let Some(user_agent) = request.headers().get(USER_AGENT) {
            if user_agent
                .to_str()
                .expect("header not a valid utf8 string?")
                .to_lowercase()
                .contains("grpcurl")
            {
                return AuthorizationType::AuthorizationNotRequired("grpcurl user agent dev build");
            }
        }
    }

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
    AuthorizationNotRequired(&'static str /*reason*/),
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
            let authorization_type = check_auth(&request, &peer_certs).await;

            match authorization_type {
                AuthorizationType::Unauthorized => {
                    // TODO: Since mTLS is not implemented and we always fail auth at the moment,
                    // don't log the failure, overwrite the result, and let the request proceed

                    // log::error!(
                    //     "failed to authorize request. Peer certs: {:?}. Headers: {:?}. URI: {:?}",
                    //     peer_certs,
                    //     request.headers(),
                    //     request.uri()
                    // );

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
) -> eyre::Result<()>
where
    C: CredentialProvider + 'static,
{
    let api_reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
        .build()?;

    let identity_pemfile_path = api_service.identity_pemfile_path.clone();
    let identity_keyfile_path = api_service.identity_keyfile_path.clone();
    let tls_acceptor = tokio::task::spawn_blocking(move || {
        get_tls_acceptor(identity_pemfile_path, identity_keyfile_path)
    })
    .await?;

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
                        log::error!(
                            "error accepting tls connection: {:?}, from address: {:?}",
                            error,
                            addr
                        );
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

/// Logs the Machine ID in the current tracing span
fn log_machine_id(machine_id: &MachineId) {
    tracing::Span::current().record("forge.machine_id", machine_id.to_string());
}

impl<C> Api<C>
where
    C: CredentialProvider + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_provider: Arc<C>,
        database_connection: sqlx::PgPool,
        authorizer: auth::Authorizer,
        redfish_pool: Arc<dyn RedfishClientPool>,
        vpc_api: Arc<dyn VpcApi>,
        eth_data: ethernet_virtualization::EthVirtData,
        identity_pemfile_path: String,
        identity_keyfile_path: String,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            authorizer,
            redfish_pool,
            vpc_api,
            eth_data,
            identity_pemfile_path,
            identity_keyfile_path,
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn run(
        daemon_config: &cfg::Daemon,
        credential_provider: Arc<C>,
        meter: opentelemetry::metrics::Meter,
    ) -> eyre::Result<()> {
        let service_config = if daemon_config.kubernetes {
            ServiceConfig::default()
        } else {
            ServiceConfig::for_local_development()
        };

        // RedfishClientPool uses reqwest in blocking mode.
        // If it is called from an async function directly it will crash the runtime,
        // therefore we have to wrap it inside spawn_blocking.
        let rf_pool =
            tokio::task::spawn_blocking(move || -> Result<_, libredfish::RedfishError> {
                libredfish::RedfishClientPool::builder().build()
            })
            .await??;
        let redfish_pool = RedfishClientPoolImpl::new(credential_provider.clone(), rf_pool);
        let shared_redfish_pool: Arc<dyn RedfishClientPool> = Arc::new(redfish_pool);

        let database_connection = sqlx::pool::PoolOptions::new()
            .max_connections(service_config.max_db_connections)
            .connect(&daemon_config.datastore)
            .await?;

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

        let mut eth_data = if daemon_config.manage_vpc {
            // Forge will own and manage VPC data
            if daemon_config.asn == 0 {
                eyre::bail!("fatal: carbide-api requires a valid `--asn` when managing VPC");
            }
            let mut ethd = ethernet_virtualization::enable(database_connection.clone()).await;
            ethd.asn = daemon_config.asn;
            ethd
        } else {
            // VPC (Go CRD) will own and manage it's data
            ethernet_virtualization::EthVirtData::default()
        };
        eth_data.dhcp_servers = daemon_config.dhcp_server.clone();

        let health_pool = database_connection.clone();
        start_export_service_health_metrics(ServiceHealthContext {
            meter: meter.clone(),
            database_pool: health_pool,
            resource_pool_stats: eth_data.rp_stats.take(),
        });

        let sc_pool_vlan_id = eth_data.pool_vlan_id.clone();
        let sc_pool_vni = eth_data.pool_vni.clone();
        let api_service = Arc::new(Self::new(
            credential_provider.clone(),
            database_connection.clone(),
            authorizer,
            shared_redfish_pool.clone(),
            vpc_api.clone(),
            eth_data,
            daemon_config.identity_pemfile_path.clone(),
            daemon_config.identity_keyfile_path.clone(),
        ));

        // handle should be stored in a variable. If is is dropped by compiler, main event will be dropped.
        let _handle = ipmi_handler(
            conn_clone,
            RealIpmiCommandHandler {},
            credential_provider.clone(),
        )
        .await?;

        let _machine_state_controller_handle =
            StateController::<MachineStateControllerIO>::builder()
                .database(database_connection.clone())
                .meter("forge_machines", meter.clone())
                .redfish_client_pool(shared_redfish_pool.clone())
                .vpc_api(vpc_api.clone())
                .forge_api(api_service.clone())
                .iteration_time(service_config.machine_state_controller_iteration_time)
                .state_handler(Arc::new(MachineStateHandler::default()))
                .reachability_params(ReachabilityParams {
                    checker: Arc::new(PingReachabilityChecker::default()),
                    dpu_wait_time: Duration::minutes(5),
                })
                .build()
                .expect("Unable to build MachineStateController");

        let mut ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
            .database(database_connection)
            .meter("forge_network_segments", meter.clone())
            .redfish_client_pool(shared_redfish_pool.clone())
            .vpc_api(vpc_api)
            .forge_api(api_service.clone());
        if let Some(pool_vlan_id) = sc_pool_vlan_id {
            ns_builder = ns_builder.pool_vlan_id(pool_vlan_id);
        }
        if let Some(pool_vni) = sc_pool_vni {
            ns_builder = ns_builder.pool_vni(pool_vni);
        }
        let _network_segment_controller_handle = ns_builder
            .iteration_time(service_config.network_segment_state_controller_iteration_time)
            .state_handler(Arc::new(NetworkSegmentStateHandler::new(
                service_config.network_segment_drain_time,
            )))
            .reachability_params(ReachabilityParams {
                checker: Arc::new(PingReachabilityChecker::default()),
                dpu_wait_time: Duration::minutes(5),
            })
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
                info!("no machine for {machine_id}");
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
            Ok(Some(m)) => m,
        };
        Ok((machine, txn))
    }

    /// Allocate a value from the loopback IP resource pool.
    ///
    /// If the pool doesn't exist return None.
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_loopback_ip(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<Ipv4Addr>, Status> {
        if self.eth_data.pool_loopback_ip.is_none() {
            return Ok(None);
        }
        match self
            .eth_data
            .pool_loopback_ip
            .as_ref()
            .unwrap()
            .allocate(txn, OwnerType::Machine, owner_id)
            .await
        {
            Ok(val) => Ok(Some(val)),
            Err(ResourcePoolError::Empty) => {
                let msg = format!("Pool lo-ip exhausted, cannot allocate for {owner_id}");
                tracing::error!("{}", &msg);
                Err(Status::resource_exhausted(&msg))
            }
            Err(err) => {
                let msg = format!("Err allocating from lo-ip for {owner_id}: {err}");
                tracing::error!("{}", &msg);
                Err(Status::internal(&msg))
            }
        }
    }

    /// Allocate a value from the vni resource pool.
    ///
    /// If the pool doesn't exist return None.
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_vni(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<i32>, Status> {
        if self.eth_data.pool_vni.is_none() {
            return Ok(None);
        }
        match self
            .eth_data
            .pool_vni
            .as_ref()
            .unwrap()
            .allocate(txn, OwnerType::NetworkSegment, owner_id)
            .await
        {
            Ok(val) => Ok(Some(val)),
            Err(ResourcePoolError::Empty) => {
                let msg = format!("Pool vni exhausted, cannot allocate for {owner_id}");
                tracing::error!("{}", &msg);
                Err(Status::resource_exhausted(&msg))
            }
            Err(err) => {
                let msg = format!("Err allocating from vni for {owner_id}: {err}");
                tracing::error!("{}", &msg);
                Err(Status::internal(&msg))
            }
        }
    }

    /// Allocate a value from the vlan id resource pool.
    ///
    /// If the pool doesn't exist return None.
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_vlan_id(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<i16>, Status> {
        if self.eth_data.pool_vlan_id.is_none() {
            return Ok(None);
        }
        match self
            .eth_data
            .pool_vlan_id
            .as_ref()
            .unwrap()
            .allocate(txn, OwnerType::NetworkSegment, owner_id)
            .await
        {
            Ok(val) => Ok(Some(val)),
            Err(ResourcePoolError::Empty) => {
                let msg = format!("Pool vlan_id exhausted, cannot allocate for {owner_id}");
                tracing::error!("{}", &msg);
                Err(Status::resource_exhausted(&msg))
            }
            Err(err) => {
                let msg = format!("Err allocating from vlan_id for {owner_id}: {err}");
                tracing::error!("{}", &msg);
                Err(Status::internal(&msg))
            }
        }
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
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::minutes(5),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(30),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(30),
            max_db_connections: 1000,
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
        }
    }
}
