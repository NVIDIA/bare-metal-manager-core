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
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use color_eyre::Report;
use futures_util::future::BoxFuture;
use http::header::USER_AGENT;
use http::{header::AUTHORIZATION, StatusCode};
use hyper::server::conn::Http;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use mac_address::MacAddress;
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
use ::rpc::protos::forge::InstanceList;
use ::rpc::protos::forge::{EchoRequest, EchoResponse};
use ::rpc::protos::forge::{MachineCredentialsUpdateRequest, MachineCredentialsUpdateResponse};
use forge_credentials::{CredentialKey, CredentialProvider, Credentials};

use crate::ipmi::Operation;
use crate::CarbideResult;
use crate::{
    auth, cfg,
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
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NewNetworkSegment},
        resource_record::DnsQuestion,
        tags::{Tag, TagAssociation, TagCreate, TagDelete, TagsList},
        vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc},
        UuidKeyedObjectFilter,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    ipmi::{ipmi_handler, MachineBmcRequest, RealIpmiCommandHandler},
    kubernetes::{bgkubernetes_handler, delete_managed_resource, VpcApi, VpcApiImpl, VpcApiSim},
    model::{
        hardware_info::HardwareInfo, instance::status::network::InstanceNetworkStatusObservation,
        machine::MachineState,
    },
    state_controller::{
        controller::StateController,
        machine::handler::MachineStateHandler,
        machine::io::MachineStateControllerIO,
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
        snapshot_loader::{DbSnapshotLoader, InstanceSnapshotLoader},
    },
    CarbideError,
};

use self::rpc::forge_server::Forge;

// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

pub struct Api<C: CredentialProvider> {
    database_connection: sqlx::PgPool,
    credential_provider: Arc<C>,
    authorizer: auth::Authorizer,
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

        let mut segments = NetworkSegment::find(&mut txn, uuid).await?;

        let segment = match segments.len() {
            1 => segments.remove(0),
            _ => return Err(Status::not_found("network segment not found")),
        };

        let response = Ok(segment
            .mark_as_deleted(&mut txn)
            .await
            .map(|_| rpc::NetworkSegmentDeletionResult {})
            .map(Response::new)?);

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

        Ok(Response::new(
            rpc::Instance::try_from(instance_snapshot).map_err(CarbideError::from)?,
        ))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn find_instances(
        &self,
        request: Request<rpc::InstanceSearchQuery>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        let _auth =
            self.authorizer
                .authorize(&request, auth::Action::Read, auth::Object::Instance)?;

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
                let uuid = match Uuid::try_from(id) {
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
        let _auth =
            self.authorizer
                .authorize(&request, auth::Action::Read, auth::Object::Instance)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let uuid = Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;
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
        match machine.current_state() {
            MachineState::Assigned => {
                machine.advance(&mut txn, MachineState::Reset).await?;
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

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;
        update_instance_network_status_observation(&mut txn, instance_id, &observation)
            .await
            .map_err(CarbideError::from)?;
        txn.commit().await.map_err(CarbideError::from)?;

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

        let machine_power_request = MachineBmcRequest::try_from(request.into_inner())?;

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
            .invoke_bmc_command(self.database_connection.clone())
            .await?;

        Ok(Response::new(rpc::InstancePowerResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
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

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        if let Some(conn_info) = request.extensions().get::<ConnInfo>() {
            log::info!(
                "Got a request from: {:?} with authorization_type: {:?}, request: {:?}",
                conn_info.addr,
                conn_info.authorization_type,
                request,
            );
        }

        let machine_discovery_info = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;

        let interface_id = match &machine_discovery_info.machine_interface_id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("An interface UUID is required"));
            }
        };

        let interface = MachineInterface::find_one(&mut txn, interface_id).await?;

        let machine = Machine::get_or_create(&mut txn, interface)
            .await
            .map(rpc::Machine::from)?;

        let uuid = match &machine.id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine"));
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

    // Host has completed discovery
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discovery_completed(
        &self,
        request: Request<rpc::MachineDiscoveryCompletedRequest>,
    ) -> Result<Response<rpc::MachineDiscoveryCompletedResponse>, Status> {
        let req = request.into_inner();

        // Extract and check UUID
        let machine_id = match &req.machine_id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };

        let (machine, mut txn) = self.load_machine(machine_id).await?;

        match machine.current_state() {
            // new machine
            MachineState::Init => {
                machine.advance(&mut txn, MachineState::Adopted).await?;
                machine.advance(&mut txn, MachineState::Ready).await?;
            }
            // after de-provision
            MachineState::Cleanedup => {
                machine.advance(&mut txn, MachineState::Ready).await?;
            }
            // all other states are invalid
            x => {
                log::warn!("discovery_completed {machine_id} in invalid state {x}");
                return Err(Status::failed_precondition(format!("invalid state {x}")));
            }
        }
        log::info!("discovery_completed: {machine_id}");

        Ok(Response::new(rpc::MachineDiscoveryCompletedResponse {}))
    }

    // Transitions the machine to Ready state.
    // Called by 'forge-scout discovery' once cleanup succeeds.
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn cleanup_machine_completed(
        &self,
        request: Request<rpc::MachineCleanupInfo>,
    ) -> Result<Response<rpc::MachineCleanupResult>, Status> {
        let cleanup_info = request.into_inner();
        log::info!("cleanup_machine_completed {:?}", cleanup_info);

        // Extract and check UUID
        let machine_id = match &cleanup_info.machine_id {
            Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };

        let (machine, mut txn) = self.load_machine(machine_id).await?;
        machine.advance(&mut txn, MachineState::Cleanedup).await?;

        let mpr = MachineBmcRequest::new(machine_id, Operation::DisableLockdown, true);
        mpr.invoke_bmc_command(self.database_connection.clone())
            .await?;
        log::info!("Requested disable lockdown and power reset for machine: {machine_id}");

        Ok(Response::new(rpc::MachineCleanupResult {}))
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        crate::dhcp::discover::discover_dhcp(&self.database_connection, request).await
    }

    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_machine(
        &self,
        request: Request<rpc::Uuid>,
    ) -> Result<Response<rpc::Machine>, Status> {
        let machine_id = Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;
        let (machine, _) = self.load_machine(machine_id).await?;
        Ok(Response::new(rpc::Machine::from(machine)))
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
                let uuid = match Uuid::try_from(id) {
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
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn get_dpu_ssh_credential(
        &self,
        request: Request<rpc::CredentialRequest>,
    ) -> Result<Response<rpc::CredentialResponse>, Status> {
        let query = request.into_inner().host_id;

        let uuid = self.find_dpu_machine_uuid(&query).await?;

        // Load credentials from Vault
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuSsh {
                machine_id: uuid.to_string(),
            })
            .await
            .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                Ok(vaultrs::error::ClientError::APIError { code, .. }) if code == 404 => {
                    CarbideError::NotFoundError("dpu-ssh-cred".to_string(), uuid)
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

        let machine_id = Uuid::try_from(request.into_inner()).map_err(CarbideError::from)?;

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

    /// Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    /// Tells it whether to discover or cleanup based on current machine state.
    #[tracing::instrument(skip_all, fields(request = ?request.get_ref()))]
    async fn forge_agent_control(
        &self,
        request: Request<rpc::ForgeAgentControlRequest>,
    ) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
        use ::rpc::forge_agent_control_response::Action;

        // Convert Option<rpc::Uuid> into uuid::Uuid
        let machine_id = match request.into_inner().machine_id {
            Some(rpc_uuid) => Uuid::try_from(&rpc_uuid).map_err(CarbideError::from)?,
            None => {
                log::warn!("forge agent control: missing uuid");
                return Err(Status::invalid_argument("Missing machine UUID"));
            }
        };

        let (machine, _) = self.load_machine(machine_id).await?;

        // Respond based on machine current state
        let state = machine.current_state();
        let action = match state {
            MachineState::Init | MachineState::Cleanedup => Action::Discovery,
            MachineState::Reset => Action::Reset,
            _ => {
                // Later this might go to site admin dashboard for manual intervention
                log::info!(
                    "forge agent control: Machine '{}' in invalid state '{state}'",
                    machine.id()
                );
                Action::Noop
            }
        };
        log::info!(
            "forge agent control: machine {} action {:?}",
            machine.id(),
            action
        );
        Ok(Response::new(rpc::ForgeAgentControlResponse {
            action: action as i32,
        }))
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
async fn api_handler<C>(api_service: Arc<Api<C>>, listen_port: SocketAddr) -> Result<(), Report>
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

impl<C> Api<C>
where
    C: CredentialProvider + 'static,
{
    pub fn new(
        credential_provider: Arc<C>,
        database_connection: sqlx::PgPool,
        authorizer: auth::Authorizer,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            authorizer,
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn run(
        daemon_config: &cfg::Daemon,
        credential_provider: Arc<C>,
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
        tokio::spawn(async move {
            loop {
                log::info!("Active DB connections: {}", stats_pool.size());
                tokio::time::sleep(service_config.db_stats_interval).await;
            }
        });

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
        ));

        // handle should be stored in a variable. If is is dropped by compiler, main event will be dropped.
        let _handle = ipmi_handler(
            conn_clone,
            RealIpmiCommandHandler {},
            credential_provider.clone(),
        )
        .await?;

        let vpc_api: Arc<dyn VpcApi> = if daemon_config.kubernetes {
            let client = kube::Client::try_default().await?;
            Arc::new(VpcApiImpl::new(client, daemon_config.dhcp_server.clone()))
        } else {
            Arc::new(VpcApiSim::default())
        };

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
                .iteration_time(service_config.machine_state_controller_iteration_time)
                .state_handler(Arc::new(MachineStateHandler::default()))
                .build()
                .expect("Unable to build MachineStateController");

        let _network_segment_controller_handle =
            StateController::<NetworkSegmentStateControllerIO>::builder()
                .database(database_connection)
                .vpc_api(vpc_api)
                .iteration_time(service_config.network_segment_state_controller_iteration_time)
                .state_handler(Arc::new(NetworkSegmentStateHandler::new(
                    service_config.network_segment_drain_time,
                )))
                .build()
                .expect("Unable to build NetworkSegmentController");

        let listen_port = daemon_config.listen[0];
        api_handler(api_service, listen_port).await
    }

    // Map any of a UUID, IPv4, MAC or hostname to the UUID of a DPU machine, by querying the
    // database.
    async fn find_dpu_machine_uuid(&self, query: &str) -> Result<Uuid, tonic::Status> {
        if let Ok(uuid) = Uuid::parse_str(query) {
            return Ok(uuid);
        }
        if let Ok(ip) = Ipv4Addr::from_str(query) {
            let mut txn = self
                .database_connection
                .begin()
                .await
                .map_err(CarbideError::from)?;
            match DpuMachine::find_by_ip(&mut txn, &ip).await {
                Ok(machine) => return Ok(*machine.machine_id()),
                Err(err) => {
                    return Err(Status::not_found(format!(
                        "IP address '{ip}' did not match any machines: {err}"
                    )));
                }
            }
        }
        if let Ok(mac) = MacAddress::from_str(query) {
            let mut txn = self
                .database_connection
                .begin()
                .await
                .map_err(CarbideError::from)?;
            match DpuMachine::find_by_mac_address(&mut txn, &mac).await {
                Ok(machine) => return Ok(*machine.machine_id()),
                Err(err) => {
                    return Err(Status::not_found(format!(
                        "MAC address '{mac}' did not match any machines: {err}"
                    )));
                }
            }
        }
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;
        match DpuMachine::find_by_hostname(&mut txn, query).await {
            Ok(machine) => Ok(*machine.machine_id()),
            Err(err) => Err(Status::not_found(format!(
                "Hostname '{query}' did not match any machines: {err}"
            ))),
        }
    }

    async fn load_machine(
        &self,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<(Machine, sqlx::Transaction<'_, sqlx::Postgres>)> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(CarbideError::from)?;
        let machine = match Machine::find_one(&mut txn, machine_id).await {
            Err(err) => {
                log::warn!("loading machine for {machine_id}: {err}.");
                return Err(CarbideError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                log::info!("no machine for {machine_id}");
                return Err(CarbideError::NotFoundError(
                    "machine".to_string(),
                    machine_id,
                ));
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
            machine_state_controller_iteration_time: std::time::Duration::from_secs(30),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(10),
            max_db_connections: 1000,
            db_stats_interval: std::time::Duration::from_secs(60),
        }
    }
}
