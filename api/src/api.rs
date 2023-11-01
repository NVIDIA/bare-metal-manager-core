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

use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

pub use ::rpc::forge as rpc;
use ::rpc::protos::forge::{
    CreateTenantKeysetRequest, CreateTenantKeysetResponse, CreateTenantRequest,
    CreateTenantResponse, DeleteTenantKeysetRequest, DeleteTenantKeysetResponse, EchoRequest,
    EchoResponse, FindTenantKeysetRequest, FindTenantRequest, FindTenantResponse, IbPartition,
    IbPartitionCreationRequest, IbPartitionDeletionRequest, IbPartitionDeletionResult,
    IbPartitionList, IbPartitionQuery, InstanceList, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse, TenantKeySetList, UpdateTenantKeysetRequest,
    UpdateTenantKeysetResponse, UpdateTenantRequest, UpdateTenantResponse,
    ValidateTenantPublicKeyRequest, ValidateTenantPublicKeyResponse,
};
use chrono::Duration;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, CredentialType, Credentials};
use hyper::server::conn::Http;
use itertools::Itertools;
use opentelemetry::metrics::Meter;
use opentelemetry_api::KeyValue;
use sqlx::postgres::PgSslMode;
use sqlx::{ConnectOptions, Pool, Postgres, Transaction};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_rustls::rustls::server::AllowAnyAnonymousOrAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_reflection::server::Builder;
use tower_http::add_extension::AddExtensionLayer;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use uuid::Uuid;

use self::rpc::forge_server::Forge;
use crate::cfg::CarbideConfig;
use crate::db::bmc_metadata::UserRoles;
use crate::db::dpu_agent_upgrade_policy::DpuAgentUpgradePolicy;
use crate::db::ib_partition::{IBPartition, IBPartitionConfig, IBPartitionSearchConfig};
use crate::db::instance_address::InstanceAddress;
use crate::db::machine::{MachineSearchConfig, MaintenanceMode};
use crate::db::machine_boot_override::MachineBootOverride;
use crate::db::network_segment::NetworkSegmentSearchConfig;
use crate::ib::{self, IBFabricManager, DEFAULT_IB_FABRIC_NAME};
use crate::ip_finder;
use crate::ipmitool::IPMITool;
use crate::ipxe::PxeInstructions;
use crate::machine_update_manager::MachineUpdateManager;
use crate::model::config_version::ConfigVersion;
use crate::model::instance::status::network::InstanceInterfaceStatusObservation;
use crate::model::machine::machine_id::try_parse_machine_id;
use crate::model::machine::network::MachineNetworkStatusObservation;
use crate::model::machine::upgrade_policy::AgentUpgradePolicy;
use crate::model::machine::{
    FailureCause, FailureDetails, FailureSource, InstanceState, ManagedHostState, ReprovisionState,
};
use crate::model::network_devices::{DpuToNetworkDeviceMap, NetworkTopologyData};
use crate::model::network_segment::{NetworkDefinition, NetworkSegmentControllerState};
use crate::model::tenant::{
    Tenant, TenantKeyset, TenantKeysetIdentifier, TenantPublicKeyValidationRequest,
    UpdateTenantKeyset,
};
use crate::model::RpcDataConversionError;
use crate::redfish::RedfishCredentialType;
use crate::resource_pool;
use crate::resource_pool::common::CommonPools;
use crate::state_controller::controller::ReachabilityParams;
use crate::state_controller::snapshot_loader::{MachineStateSnapshotLoader, SnapshotLoaderError};
use crate::{
    auth,
    credentials::UpdateCredentials,
    db::{
        bmc_metadata::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest},
        domain::Domain,
        domain::NewDomain,
        instance::{
            status::network::update_instance_network_status_observation, DeleteInstance, Instance,
        },
        instance_type::{DeactivateInstanceType, NewInstanceType, UpdateInstanceType},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NetworkSegmentType, NewNetworkSegment},
        resource_record::DnsQuestion,
        route_servers::RouteServer,
        vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc},
        DatabaseError, ObjectFilter, UuidKeyedObjectFilter,
    },
    ethernet_virtualization,
    instance::{allocate_instance, InstanceAllocationRequest},
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
        bmc_machine::{handler::BmcMachineStateHandler, io::BmcMachineStateControllerIO},
        controller::StateController,
        ib_partition::{handler::IBPartitionStateHandler, io::IBPartitionStateControllerIO},
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

/// Username for default site-wide BMC username.
const FORGE_SITE_WIDE_BMC_USERNAME: &str = "root";

// vxlan5555 is special HBN single vxlan device. It handles networking between machines on the
// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan5555";

// If you set this to true forge-dpu-agent will start writing the HBN files (frr.conf, etc)
// If you leave it false forge-dpu-agent will write files with a .TEST extension.
//
// Only used if `--manage-vpc` on command line.
const ETH_VIRT_PRODUCTION_MODE: bool = true;

pub struct Api<C1: CredentialProvider, C2: CertificateProvider> {
    pub(crate) database_connection: sqlx::PgPool,
    credential_provider: Arc<C1>,
    certificate_provider: Arc<C2>,
    authorizer: auth::Authorizer,
    redfish_pool: Arc<dyn RedfishClientPool>,
    pub(crate) eth_data: ethernet_virtualization::EthVirtData,
    common_pools: Arc<CommonPools>,
    tls_config: ApiTlsConfig,
    machine_update_config: MachineUpdateConfig,
    ib_fabric_manager: Arc<dyn IBFabricManager>,
}

pub struct ApiTlsConfig {
    pub identity_pemfile_path: String,
    pub identity_keyfile_path: String,
    pub root_cafile_path: String,
    pub admin_root_cafile_path: String,
}

pub struct MachineUpdateConfig {
    pub dpu_nic_firmware_update_enabled: bool,
}

#[tonic::async_trait]
impl<C1, C2> Forge for Api<C1, C2>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    async fn version(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<Response<rpc::BuildInfo>, Status> {
        let v = rpc::BuildInfo {
            build_version: forge_version::v!(build_version).to_string(),
            build_date: forge_version::v!(build_date).to_string(),
            git_sha: forge_version::v!(git_sha).to_string(),
            rust_version: forge_version::v!(rust_version).to_string(),
            build_user: forge_version::v!(build_user).to_string(),
            build_hostname: forge_version::v!(build_hostname).to_string(),
        };
        Ok(Response::new(v))
    }

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

        let mut vpc = NewVpc::try_from(request.into_inner())?
            .persist(&mut txn)
            .await
            .map_err(CarbideError::from)?;
        vpc.vni = Some(self.allocate_vpc_vni(&mut txn, &vpc.id.to_string()).await?);
        Vpc::set_vni(&mut txn, vpc.id, vpc.vni.unwrap())
            .await
            .map_err(CarbideError::from)?;

        let rpc_out: rpc::Vpc = vpc.into();

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_vpc", e))?;

        Ok(Response::new(rpc_out))
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

        let vpc = DeleteVpc::try_from(request.into_inner())?
            .delete(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        if let Some(vni) = vpc.vni {
            self.common_pools
                .ethernet
                .pool_vpc_vni
                .release(&mut txn, vni)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_vpc", e))?;

        Ok(Response::new(rpc::VpcDeletionResult {}))
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

    async fn find_ib_partitions(
        &self,
        request: Request<IbPartitionQuery>,
    ) -> Result<Response<IbPartitionList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin find_ib_partitions", e))?;

        let rpc::IbPartitionQuery {
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
            .map(IBPartitionSearchConfig::from)
            .unwrap_or(IBPartitionSearchConfig::default());
        let results = IBPartition::find(&mut txn, uuid_filter, search_config)
            .await
            .map_err(CarbideError::from)?;
        let mut ib_partitions = Vec::with_capacity(results.len());
        for result in results {
            ib_partitions.push(result.try_into()?);
        }

        Ok(Response::new(rpc::IbPartitionList { ib_partitions }))
    }

    async fn create_ib_partition(
        &self,
        req: Request<IbPartitionCreationRequest>,
    ) -> Result<Response<IbPartition>, Status> {
        log_request_data(&req);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin create_ib_partition", e)
            })?;

        let mut resp = IBPartitionConfig::try_from(req.into_inner())?;
        resp.pkey = self.allocate_pkey(&mut txn, &resp.name).await?;
        let resp = IBPartition::create(&mut txn, &resp)
            .await
            .map_err(CarbideError::from)?;
        let resp = rpc::IbPartition::try_from(resp).map(Response::new)?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit create_ib_partition", e))?;

        Ok(resp)
    }

    async fn delete_ib_partition(
        &self,
        request: Request<IbPartitionDeletionRequest>,
    ) -> Result<Response<IbPartitionDeletionResult>, Status> {
        log_request_data(&request);

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin delete_ib_partition", e)
            })?;

        let rpc::IbPartitionDeletionRequest { id, .. } = request.into_inner();

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

        let mut segments = IBPartition::find(&mut txn, uuid, IBPartitionSearchConfig::default())
            .await
            .map_err(CarbideError::from)?;

        let segment = match segments.len() {
            1 => segments.remove(0),
            _ => return Err(Status::not_found("ib subnet not found")),
        };

        let resp = segment
            .mark_as_deleted(&mut txn)
            .await
            .map(|_| rpc::IbPartitionDeletionResult {})
            .map(Response::new)?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit delete_ib_partition", e))?;

        Ok(resp)
    }

    async fn ib_partitions_for_tenant(
        &self,
        request: Request<rpc::TenantSearchQuery>,
    ) -> Result<Response<IbPartitionList>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin find_ib_partions_for_tenant", e)
        })?;

        let rpc::TenantSearchQuery {
            tenant_organization_id,
        } = request.into_inner();

        let _tenant_organization_id: String = match tenant_organization_id {
            Some(id) => id,
            None => {
                return Err(Status::invalid_argument("A organization_id is required"));
            }
        };

        let results = IBPartition::for_tenant(&mut txn, _tenant_organization_id)
            .await
            .map_err(CarbideError::from)?;

        let mut ib_partitions = Vec::with_capacity(results.len());

        for result in results {
            ib_partitions.push(result.try_into()?);
        }

        Ok(Response::new(rpc::IbPartitionList { ib_partitions }))
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
        let request = request.into_inner();

        let new_network_segment = NewNetworkSegment::try_from(request)?;
        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "begin create_network_segment", e)
            })?;
        let network_segment = self
            .save_network_segment(&mut txn, new_network_segment, false)
            .await?;

        let response = Ok(Response::new(network_segment.try_into()?));
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit create_network_segment", e)
        })?;
        response
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

        let loader = DbSnapshotLoader {};
        let mut instances = Vec::with_capacity(raw_instances.len());
        for instance in raw_instances {
            let snapshot = loader
                .load_machine_snapshot(&mut txn, &instance.machine_id)
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

        let Some(snapshot) = DbSnapshotLoader {}
            .load_machine_snapshot(&mut txn, &machine_id)
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
        let delete_instance = DeleteInstance::try_from(request.into_inner())?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin release_instance",
                e,
            ))
        })?;

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
            tracing::info!(
                instance_id = %delete_instance.instance_id,
                "Instance is already marked for deletion.",
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
                .ok_or(CarbideError::IdentifierNotSpecifiedForObject)?,
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
        let dpu_machine_id = match &request.dpu_machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine id"));
            }
        };
        log_machine_id(&dpu_machine_id);

        let loader = DbSnapshotLoader {};
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_managed_host_network_config", e)
        })?;

        let snapshot = match loader
            .load_machine_snapshot(&mut txn, &dpu_machine_id)
            .await
        {
            Ok(snap) => snap,
            Err(SnapshotLoaderError::HostNotFound(_)) => {
                return Err(tonic::Status::not_found(dpu_machine_id.to_string()));
            }
            Err(err) => {
                return Err(CarbideError::from(err).into());
            }
        };

        let loopback_ip = match snapshot.dpu_snapshot.loopback_ip() {
            Some(ip) => ip,
            None => {
                return Err(Status::failed_precondition(format!(
                    "DPU {} needs discovery. Does not have a loopback IP yet.",
                    snapshot.dpu_snapshot.machine_id
                )));
            }
        };
        let use_admin_network = snapshot.dpu_snapshot.use_admin_network();

        let admin_interface_rpc =
            ethernet_virtualization::admin_network(&mut txn, &snapshot.host_snapshot.machine_id)
                .await?;

        let mut network_virtualization_type = None;
        let mut vpc_vni = None;

        let tenant_interfaces = match &snapshot.instance {
            None => vec![],
            Some(instance) => {
                let interfaces = &instance.config.network.interfaces;
                let vpc = Vpc::find_by_segment(&mut txn, interfaces[0].network_segment_id)
                    .await
                    .map_err(CarbideError::from)?;
                network_virtualization_type = Some(vpc.network_virtualization_type);
                vpc_vni = vpc.vni;

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

        let network_config = rpc::ManagedHostNetworkConfig {
            loopback_ip: loopback_ip.to_string(),
        };

        let resp = rpc::ManagedHostNetworkConfigResponse {
            instance_id: snapshot
                .instance
                .as_ref()
                .map(|instance| instance.instance_id.into()),
            is_production_mode: ETH_VIRT_PRODUCTION_MODE,
            asn: self.eth_data.asn,
            dhcp_servers: self.eth_data.dhcp_servers.clone(),
            route_servers: self.eth_data.route_servers.clone(),
            // TODO: Automatically add the prefix(es?) from the IPv4 loopback
            // pool to deny_prefixes. The database stores the pool in an
            // exploded representation, so we either need to reconstruct the
            // original prefix from what's in the database, or find some way to
            // store it when it's added or resized.
            deny_prefixes: self
                .eth_data
                .deny_prefixes
                .iter()
                .map(|net| net.to_string())
                .collect(),
            vni_device: if use_admin_network {
                "".to_string()
            } else {
                HBN_SINGLE_VLAN_DEVICE.to_string()
            },
            managed_host_config: Some(network_config),
            managed_host_config_version: snapshot
                .dpu_snapshot
                .network_config
                .version
                .version_string(),
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
                    .version_string()
            },
            remote_id: dpu_machine_id.remote_id(),
            network_virtualization_type: network_virtualization_type.map(|nvt| nvt as i32),
            vpc_vni: vpc_vni.map(|vni| vni as u32),
        };
        Ok(Response::new(resp))
    }

    async fn record_dpu_network_status(
        &self,
        request: Request<rpc::DpuNetworkStatus>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let dpu_machine_id = match &request.dpu_machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::not_found("Missing machine id"));
            }
        };
        log_machine_id(&dpu_machine_id);

        if let Some(ref network_config_error) = request.network_config_error {
            tracing::info!(machine_id = %dpu_machine_id, "Host failed applying network config: {network_config_error}");
        }

        let hs = request
            .health
            .as_ref()
            .ok_or_else(|| CarbideError::MissingArgument("health_status"))?;
        if hs.is_healthy {
            tracing::trace!(machine_id = %dpu_machine_id, "Machine network is healthy");
        } else {
            tracing::debug!(
                machine_id = %dpu_machine_id,
                "Network failed checks {:?} because {}",
                hs.failed,
                hs.message.as_deref().unwrap_or_default()
            );
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin record_dpu_network_status", e)
        })?;

        let observed_at = match request.observed_at.clone() {
            Some(ts) => {
                // Use DPU clock
                let system_time = std::time::SystemTime::try_from(ts).map_err(|err| {
                    tracing::warn!(
                        machine_id = %dpu_machine_id,
                        "record_dpu_network_status invalid timestamp `observed_at`: {err}"
                    );
                    CarbideError::InvalidArgument("observed_at".to_string())
                })?;
                chrono::DateTime::from(system_time)
            }
            None => {
                // Use carbide-api clock
                chrono::Utc::now()
            }
        };

        let machine_obs = MachineNetworkStatusObservation::try_from(request.clone())
            .map_err(CarbideError::from)?;
        Machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs)
            .await
            .map_err(CarbideError::from)?;
        tracing::trace!(
            machine_id = %dpu_machine_id,
            machine_network_config = ?request.network_config_version,
            instance_network_config = ?request.instance_config_version,
            agent_version = machine_obs.agent_version,
            "Applied network configs",
        );

        // We already persisted the machine parts of applied_config in
        // update_network_status_observation above. Now do the instance parts.
        if let Some(version_string) = request.instance_config_version {
            let Ok(version) = version_string.as_str().parse() else {
                return Err(CarbideError::InvalidArgument("applied_config.instance_config_version".to_string()).into());
            };
            let mut interfaces: Vec<InstanceInterfaceStatusObservation> = vec![];
            for iface in request.interfaces {
                let v = iface.try_into().map_err(CarbideError::from)?;
                interfaces.push(v);
            }
            let instance_obs = InstanceNetworkStatusObservation {
                config_version: version,
                observed_at,
                interfaces,
            };
            let Some(instance_id_rpc) = request.instance_id else {
                return Err(CarbideError::MissingArgument("applied_config.instance_id").into());
            };
            let instance_id = Uuid::try_from(instance_id_rpc).map_err(CarbideError::from)?;
            update_instance_network_status_observation(&mut txn, instance_id, &instance_obs)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit record_dpu_network_status",
                e,
            ))
        })?;

        // Check if we need to flag this forge-dpu-agent for upgrade or mark an upgrade completed
        // We do this here because we just learnt about which version of forge-dpu-agent is
        // running.
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin record_dpu_network_status upgrade check", e)
        })?;
        if let Some(policy) = DpuAgentUpgradePolicy::get(&mut txn)
            .await
            .map_err(CarbideError::from)?
        {
            let _needs_upgrade =
                Machine::apply_agent_upgrade_policy(&mut txn, policy, &dpu_machine_id)
                    .await
                    .map_err(CarbideError::from)?;
        }
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(
                file!(),
                "commit record_dpu_network_status upgrade check",
                e,
            )
        })?;

        Ok(Response::new(()))
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

        let response = DnsQuestion::find_record(&mut txn, question)
            .await
            .map(|dnsrr| rpc::dns_message::DnsResponse {
                rcode: dnsrr.response_code,
                rrs: dnsrr
                    .resource_records
                    .into_iter()
                    .map(|r| r.into())
                    .collect(),
            })
            .map_err(CarbideError::from)?;
        tracing::info!(DnsResponse = ?response, "lookup_record dns responded");

        Ok(Response::new(response))
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

        let request = request.into_inner();
        let machine_id = match &request.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        let loader = DbSnapshotLoader {};
        let snapshot = loader
            .load_machine_snapshot(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?;
        if snapshot.instance.is_none() {
            return Err(Status::invalid_argument(format!(
                "Supplied invalid UUID: {}",
                machine_id
            )));
        }
        let bmc_ip =
            snapshot
                .host_snapshot
                .bmc_info
                .ip
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "bmc_ip",
                    id: machine_id.to_string(),
                })?;

        let always_boot_with_custom_ipxe = snapshot
            .instance
            .map(|instance| {
                instance
                    .config
                    .tenant
                    .map(|tenant| tenant.always_boot_with_custom_ipxe)
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if !always_boot_with_custom_ipxe {
            Instance::use_custom_ipxe_on_next_boot(
                &machine_id,
                request.boot_with_custom_ipxe,
                &mut txn,
            )
            .await
            .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit invoke_instance_power",
                e,
            ))
        })?;

        // TODO: The API call should maybe not directly trigger the reboot
        // but instead queue it for the state handler. That will avoid racing
        // with other internal reboot requests from the state handler.
        let client = self
            .redfish_pool
            .create_client(
                &bmc_ip,
                None,
                RedfishCredentialType::Machine {
                    machine_id: machine_id.to_string(),
                },
            )
            .await
            .map_err(|e| CarbideError::GenericError(e.to_string()))?;

        // Lenovo does not yet provide a BMC lockdown so a user could
        // change the boot order which we set in `libredfish::forge_setup`.
        // We also can't call `boot_once` for other vendors because lockdown
        // prevents it.
        if snapshot.host_snapshot.bmc_vendor.is_lenovo() {
            client
                .boot_once(libredfish::Boot::Pxe)
                .await
                .map_err(CarbideError::from)?;
        }
        client
            .power(libredfish::SystemPowerControl::ForceRestart)
            .await
            .map_err(|e| {
                CarbideError::GenericError(format!("Failed redfish ForceRestart subtask: {}", e))
            })?;

        Ok(Response::new(rpc::InstancePowerResult {}))
    }

    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        log_request_data(&request);

        let reply = EchoResponse {
            message: request.into_inner().message,
        };

        Ok(Response::new(reply))
    }

    /// Tenant-related actions
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        log_request_data(&request);

        let rpc::CreateTenantRequest { organization_id } = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin create_tenant",
                e,
            ))
        })?;

        let response = Tenant::create_and_persist(organization_id, &mut txn)
            .await
            .map(|x| x.into())
            .map(Response::new)
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit create_tenant",
                e,
            ))
        })?;

        Ok(response)
    }

    async fn find_tenant(
        &self,
        request: Request<FindTenantRequest>,
    ) -> Result<Response<FindTenantResponse>, Status> {
        log_request_data(&request);

        let rpc::FindTenantRequest {
            tenant_organization_id,
        } = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "begin find_tenant", e))
        })?;

        let response = Tenant::find(tenant_organization_id, &mut txn)
            .await
            .map(|x| {
                x.map(|a| a.into())
                    .unwrap_or(rpc::FindTenantResponse { tenant: None })
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit find_tenant",
                e,
            ))
        })?;

        Ok(response)
    }

    async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<UpdateTenantResponse>, Status> {
        log_request_data(&request);

        // This doesn't update anything yet :|
        let rpc::UpdateTenantRequest {
            organization_id,
            if_version_match,
            ..
        } = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin update_tenant",
                e,
            ))
        })?;

        let if_version_match: Option<ConfigVersion> =
            if let Some(config_version_str) = if_version_match {
                Some(config_version_str.parse().map_err(CarbideError::from)?)
            } else {
                None
            };

        let response = Tenant::update(organization_id, if_version_match, &mut txn)
            .await
            .map(|x| x.into())
            .map(Response::new)
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit update_tenant",
                e,
            ))
        })?;

        Ok(response)
    }

    async fn create_tenant_keyset(
        &self,
        request: Request<CreateTenantKeysetRequest>,
    ) -> Result<Response<CreateTenantKeysetResponse>, Status> {
        log_request_data(&request);

        let keyset_request: TenantKeyset = request
            .into_inner()
            .try_into()
            .map_err(CarbideError::from)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin create_tenant_keyset",
                e,
            ))
        })?;

        let keyset = keyset_request
            .create(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit create_tenant_keyset",
                e,
            ))
        })?;

        Ok(Response::new(rpc::CreateTenantKeysetResponse {
            keyset: Some(keyset.into()),
        }))
    }

    async fn find_tenant_keyset(
        &self,
        request: Request<FindTenantKeysetRequest>,
    ) -> Result<Response<TenantKeySetList>, Status> {
        log_request_data(&request);

        let rpc::FindTenantKeysetRequest {
            organization_id,
            keyset_id,
            include_key_data,
        } = request.into_inner();

        if organization_id.is_none() && keyset_id.is_some() {
            return Err(Status::invalid_argument(
                "Keyset id is given but Organization id is missing.",
            ));
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_tenant_keyset",
                e,
            ))
        })?;

        let keyset_ids = if let Some(keyset_id) = keyset_id {
            ObjectFilter::One(keyset_id)
        } else {
            ObjectFilter::All
        };

        let keyset = TenantKeyset::find(organization_id, keyset_ids, include_key_data, &mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit find_tenant_keyset",
                e,
            ))
        })?;

        Ok(Response::new(rpc::TenantKeySetList {
            keyset: keyset.into_iter().map(|x| x.into()).collect(),
        }))
    }

    async fn update_tenant_keyset(
        &self,
        request: Request<UpdateTenantKeysetRequest>,
    ) -> Result<Response<UpdateTenantKeysetResponse>, Status> {
        log_request_data(&request);

        let update_request: UpdateTenantKeyset = request
            .into_inner()
            .try_into()
            .map_err(CarbideError::from)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin update_tenant_keyset",
                e,
            ))
        })?;

        update_request
            .update(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit update_tenant_keyset",
                e,
            ))
        })?;

        Ok(Response::new(rpc::UpdateTenantKeysetResponse {}))
    }

    async fn delete_tenant_keyset(
        &self,
        request: Request<DeleteTenantKeysetRequest>,
    ) -> Result<Response<DeleteTenantKeysetResponse>, Status> {
        log_request_data(&request);

        let rpc::DeleteTenantKeysetRequest { keyset_identifier } = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete_tenant_keyset",
                e,
            ))
        })?;

        let Some(keyset_identifier) = keyset_identifier else {
            return Err(Status::invalid_argument("Keyset identifier is missing."))
        };

        let keyset_identifier: TenantKeysetIdentifier =
            keyset_identifier.try_into().map_err(CarbideError::from)?;

        TenantKeyset::delete(keyset_identifier, &mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit delete_tenant_keyset",
                e,
            ))
        })?;

        Ok(Response::new(rpc::DeleteTenantKeysetResponse {}))
    }

    async fn validate_tenant_public_key(
        &self,
        request: Request<ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<ValidateTenantPublicKeyResponse>, Status> {
        let request = TenantPublicKeyValidationRequest::try_from(request.into_inner())
            .map_err(CarbideError::from)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin validate_tenant_public_key",
                e,
            ))
        })?;

        request.validate(&mut txn).await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit validate_tenant_public_key",
                e,
            ))
        })?;
        Ok(Response::new(ValidateTenantPublicKeyResponse {}))
    }

    async fn renew_machine_certificate(
        &self,
        request: Request<rpc::MachineCertificateRenewRequest>,
    ) -> Result<Response<rpc::MachineCertificateResult>, Status> {
        if let Some(machine_identity) = request
            .extensions()
            .get::<auth::AuthContext>()
            // XXX: Does a machine's certificate resemble a service's
            // certificate enough for this to work?
            .and_then(|auth_context| auth_context.get_spiffe_machine_id())
        {
            let certificate = self
                .certificate_provider
                .get_certificate(machine_identity)
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

            return Ok(Response::new(rpc::MachineCertificateResult {
                machine_certificate: Some(certificate.into()),
            }));
        }

        Err(
            CarbideError::ClientCertificateError("no client certificate presented?".to_string())
                .into(),
        )
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        // We don't log_request_data(&request); here because the hardware info is huge

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
        let stable_machine_id = MachineId::from_hardware_info(&hardware_info).map_err(|e| {
            CarbideError::InvalidArgument(
                format!("Insufficient HardwareInfo to derive a Stable Machine ID for Machine on InterfaceId {}: {e}", interface_id),
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
        let machine = if hardware_info.is_dpu() {
            let (db_machine, is_new) =
                Machine::get_or_create(&mut txn, &stable_machine_id, &interface).await?;
            interface
                .associate_interface_with_dpu_machine(&mut txn, &stable_machine_id)
                .await
                .map_err(CarbideError::from)?;
            if is_new {
                let loopback_ip = self
                    .allocate_loopback_ip(&mut txn, &stable_machine_id.to_string())
                    .await?;
                let (mut network_config, version) = db_machine.network_config().clone().take();
                network_config.loopback_ip = Some(loopback_ip);
                network_config.use_admin_network = Some(true);
                Machine::try_update_network_config(
                    &mut txn,
                    &stable_machine_id,
                    version,
                    &network_config,
                )
                .await
                .map_err(CarbideError::from)?;
            }
            db_machine
        } else {
            // Now we know stable machine id for host. Let's update it in db.
            Machine::try_sync_stable_id_with_current_machine_id_for_host(
                &mut txn,
                &interface.machine_id,
                &stable_machine_id,
            )
            .await?
        };

        MachineTopology::create_or_update(&mut txn, &stable_machine_id, &hardware_info).await?;

        if hardware_info.is_dpu() {
            // Create DPU and LLDP Association.
            if let Some(dpu_info) = hardware_info.dpu_info.as_ref() {
                DpuToNetworkDeviceMap::create_dpu_network_device_association(
                    &mut txn,
                    &dpu_info.switches,
                    &stable_machine_id,
                )
                .await
                .map_err(CarbideError::from)?;
            }

            // Create Host proactively.
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
                    MachineId::host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                        CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                    })?;
                let mi_id = machine_interface.id;
                let (proactive_machine, _) =
                    Machine::get_or_create(&mut txn, &predicted_machine_id, &machine_interface)
                        .await?;
                tracing::info!(
                    ?mi_id,
                    machine_id = %proactive_machine.id(),
                    "Created host machine proactively",
                );
            }
        }

        let id_str = stable_machine_id.to_string();
        let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            forge_secrets::certificates::Certificate::default()
        } else {
            self.certificate_provider
                .get_certificate(id_str.as_str())
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
        };

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: Some(id_str.into()),
            machine_certificate: Some(certificate.into()),
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
        machine
            .update_discovery_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        let discovery_result = match req.discovery_error {
            Some(discovery_error) => {
                machine
                    .update_failure_details(
                        &mut txn,
                        FailureDetails {
                            cause: FailureCause::Discovery {
                                err: discovery_error.clone(),
                            },
                            failed_at: chrono::Utc::now(),
                            source: FailureSource::Scout,
                        },
                    )
                    .await
                    .map_err(CarbideError::from)?;
                discovery_error
            }
            None => "Success".to_owned(),
        };

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit discovery_completed", e))?;

        tracing::info!(
            %machine_id,
            discovery_result, "discovery_completed",
        );
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
        tracing::info!(?cleanup_info, "cleanup_machine_completed");

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
        machine
            .update_cleanup_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        if let Some(nvme_result) = cleanup_info.nvme {
            if rpc::machine_cleanup_info::CleanupResult::Error as i32 == nvme_result.result {
                // NVME Cleanup failed. Move machine to failed state.
                machine
                    .update_failure_details(
                        &mut txn,
                        FailureDetails {
                            cause: FailureCause::NVMECleanFailed {
                                err: nvme_result.message.to_string(),
                            },
                            failed_at: chrono::Utc::now(),
                            source: FailureSource::Scout,
                        },
                    )
                    .await
                    .map_err(CarbideError::from)?;
            }
        }

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
                    only_maintenance: false,
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

        let include_ph = search_config
            .as_ref()
            .map(|x| x.include_predicted_host)
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
                        ty.is_host()
                            || (ty.is_dpu() && include_dpus)
                            || (ty.is_predicted_host() && include_ph)
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

        let rpc::InterfaceSearchQuery { id, ip } = request.into_inner();

        let response = match (id, ip) {
            (Some(id), _) if id.value.chars().count() > 0 => match Uuid::try_from(id) {
                Ok(uuid) => Ok(rpc::InterfaceList {
                    interfaces: vec![MachineInterface::find_one(&mut txn, uuid).await?.into()],
                }),
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into()),
            },
            (None, Some(ip)) => match Ipv4Addr::from_str(ip.as_ref()) {
                Ok(ip) => {
                    match MachineInterface::find_by_ip(&mut txn, IpAddr::V4(ip))
                        .await
                        .map_err(CarbideError::from)?
                    {
                        Some(interface) => Ok(rpc::InterfaceList {
                            interfaces: vec![interface.into()],
                        }),
                        None => {
                            return Err(CarbideError::GenericError(format!(
                                "No machine interface with IP {ip} was found"
                            ))
                            .into())
                        }
                    }
                }
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an IP from the request".to_string(),
                )
                .into()),
            },
            (None, None) => {
                match MachineInterface::find_all(&mut txn)
                    .await
                    .map_err(CarbideError::from)
                {
                    Ok(machine_interfaces) => Ok(rpc::InterfaceList {
                        interfaces: machine_interfaces
                            .into_iter()
                            .map(|i| i.into())
                            .collect_vec(),
                    }),
                    Err(error) => return Err(error.into()),
                }
            }
            _ => Err(CarbideError::GenericError(
                "Could not find an ID or IP in the request".to_string(),
            )
            .into()),
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
            tracing::warn!(
                expected = DPU_ADMIN_USERNAME,
                found = username,
                "Unexpected username in Vault"
            );
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
            CarbideError::DatabaseError(file!(), "begin get_all_managed_host_network_status", e)
        })?;

        let all_status = Machine::get_all_network_status_observation(&mut txn, 2000)
            .await
            .map_err(CarbideError::from)?;

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

        let endpoint = libredfish::Endpoint {
            user: Some(user),
            password: Some(password),
            host: req.ip.clone(),
            // Option<u32> -> Option<u16> because no uint16 in protobuf
            port: req.port.map(|p| p as u16),
        };

        let pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;
        let redfish = pool
            .create_client(endpoint)
            .await
            .map_err(CarbideError::from)?;

        // Lenovo does not have BMC lockdown, so a user could switch the boot order. We need
        // to switch it back. On other vendors the call will fail so ignore errors.
        tracing::info!(ip = req.ip, "Switching boot order");
        let _ = redfish.boot_once(libredfish::Boot::Pxe).await;

        tracing::info!(ip = req.ip, "Force restarting");
        redfish
            .power(libredfish::SystemPowerControl::ForceRestart)
            .await
            .map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "Reboot request succeeded");

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

    async fn get_cloud_init_instructions(
        &self,
        request: Request<rpc::CloudInitInstructionsRequest>,
    ) -> Result<Response<rpc::CloudInitInstructions>, Status> {
        log_request_data(&request);
        let cloud_name = "nvidia".to_string();
        let platform = "forge".to_string();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_cloud_init_instructions", e)
        })?;

        let ip_str = &request.into_inner().ip;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("Failed parsing IP '{ip_str}': {e}")))?;
        if ip.is_ipv6() {
            return Err(CarbideError::GenericError("IPv6 not supported".to_string()).into());
        }

        let instructions = match InstanceAddress::find_by_address(&mut txn, ip)
            .await
            .map_err(CarbideError::from)?
        {
            None => {
                // assume there is no instance associated with this IP and check if there is an interface associated with it
                let machine_interface = MachineInterface::find_by_ip(&mut txn, ip)
                    .await
                    .map_err(CarbideError::from)?
                    .ok_or_else(|| {
                        CarbideError::GenericError(format!(
                            "No machine interface with IP {ip} was found"
                        ))
                    })?;

                let domain_id = machine_interface.domain_id.ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "Machine Interface did not have an associated domain {}",
                        machine_interface.id
                    ))
                })?;

                let domain = Domain::find(&mut txn, UuidKeyedObjectFilter::One(domain_id))
                    .await
                    .map_err(CarbideError::from)?
                    .first()
                    .ok_or_else(|| {
                        CarbideError::GenericError(format!(
                            "Could not find a domain for {}",
                            domain_id
                        ))
                    })?
                    .to_owned();

                // This custom pxe is different from a customer instance of pxe. It is more for testing one off
                // changes until a real dev env is established and we can just override our existing code to test
                // It is possible for the user data to be null if we are only trying to test the pxe, and this will
                // follow the same code path and retrieve the non custom user data
                let custom_cloud_init =
                    match MachineBootOverride::find_optional(&mut txn, machine_interface.id).await?
                    {
                        Some(machine_boot_override) => machine_boot_override.custom_user_data,
                        None => None,
                    };

                // we update DPU firmware on first boot every time (determined by a missing machine id) or during reprovisioning.
                let update_firmware = match &machine_interface.machine_id {
                    None => self.machine_update_config.dpu_nic_firmware_update_enabled,
                    Some(machine_id) => {
                        let machine =
                            Machine::find_one(&mut txn, machine_id, MachineSearchConfig::default())
                                .await
                                .map_err(CarbideError::from)?;

                        if let Some(machine) = machine {
                            if let Some(reprov_state) =
                                machine.current_state().as_reprovision_state()
                            {
                                matches!(reprov_state, ReprovisionState::FirmwareUpgrade,)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                };

                let metadata: Option<rpc::CloudInitMetaData> = machine_interface
                    .machine_id
                    .as_ref()
                    .map(|machine_id| rpc::CloudInitMetaData {
                        instance_id: machine_id.to_string(),
                        cloud_name,
                        platform,
                    });

                rpc::CloudInitInstructions {
                    custom_cloud_init,
                    discovery_instructions: Some(rpc::CloudInitDiscoveryInstructions {
                        machine_interface: Some(machine_interface.into()),
                        domain: Some(domain.into()),
                        update_firmware,
                    }),
                    metadata,
                }
            }

            Some(instance_address) => {
                let instance = Instance::find(
                    &mut txn,
                    UuidKeyedObjectFilter::One(instance_address.instance_id),
                )
                .await
                .map_err(CarbideError::from)?
                .first()
                .ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "Could not find an instance for {}",
                        instance_address.instance_id
                    ))
                })?
                .to_owned();

                rpc::CloudInitInstructions {
                    custom_cloud_init: instance.tenant_config.user_data,
                    discovery_instructions: None,
                    metadata: Some(rpc::CloudInitMetaData {
                        instance_id: instance.id.to_string(),
                        cloud_name,
                        platform,
                    }),
                }
            }
        };

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit get_cloud_init_instructions", e)
        })?;

        Ok(Response::new(instructions))
    }

    #[allow(rustdoc::invalid_html_tags)]
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
                tracing::warn!("forge agent control: missing machine ID");
                return Err(Status::invalid_argument("Missing machine ID"));
            }
        };
        log_machine_id(&machine_id);

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;

        // Treat this message as signal from machine that reboot is finished. Update reboot time.
        machine
            .update_reboot_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        let is_dpu = machine.is_dpu();
        let host_machine = if !is_dpu {
            machine.clone()
        } else {
            Machine::find_host_by_dpu_machine_id(&mut txn, &machine_id)
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?
        };

        // Respond based on machine current state
        let state = host_machine.current_state();
        let action = if is_dpu {
            match state {
                ManagedHostState::DPUReprovision {
                    reprovision_state: ReprovisionState::BufferTime,
                } => Action::Retry,
                ManagedHostState::DPUNotReady {
                    machine_state: MachineState::Init,
                }
                | ManagedHostState::DPUReprovision {
                    reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                }
                | ManagedHostState::Assigned {
                    instance_state:
                        InstanceState::DPUReprovision {
                            reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                        },
                } => Action::Discovery,
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    tracing::info!(
                        machine_id = %machine.id(),
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
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
                    tracing::info!(
                        machine_id = %machine.id(),
                        machine_type = "Host",
                        %state,
                        "forge agent control",
                    );
                    Action::Noop
                }
            }
        };
        tracing::info!(
            machine_id = %machine.id(),
            action = action.as_str_name(),
            "forge agent control",
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

        tracing::info!("admin_force_delete_machine query='{query}'");

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
            tracing::info!(
                "Found host Machine {:?}",
                host_machine.as_ref().map(|m| m.id().to_string())
            );
            dpu_machine = Some(machine);
        } else {
            dpu_machine = Machine::find_dpu_by_host_machine_id(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;
            tracing::info!(
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
            let instance = Instance::find(&mut txn, UuidKeyedObjectFilter::One(instance_id))
                .await
                .map_err(CarbideError::from)?
                .first()
                .ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "Could not find an instance for {}",
                        instance_id
                    ))
                })?
                .to_owned();

            let ib_fabric = self
                .ib_fabric_manager
                .connect(DEFAULT_IB_FABRIC_NAME.to_string())
                .await?;

            // Collect the ib partition and ib ports information about this machine
            let mut ib_config_map: HashMap<Uuid, Vec<String>> = HashMap::new();
            let infiniband = instance.ib_config.value.ib_interfaces;
            for ib in &infiniband {
                let ib_partition_id = ib.ib_partition_id;
                if let Some(guid) = ib.guid.as_deref() {
                    ib_config_map
                        .entry(ib_partition_id)
                        .or_insert(vec![])
                        .push(guid.to_string());
                }
            }

            response.ufm_unregistaration_pending = true;
            // unbind ib ports from UFM
            for (ib_partition_id, guids) in ib_config_map.iter() {
                if let Some(pkey) =
                    IBPartition::find_pkey_by_partition_id(&mut txn, *ib_partition_id)
                        .await
                        .map_err(CarbideError::from)?
                {
                    ib_fabric
                        .unbind_ib_ports(pkey.into(), guids.to_vec())
                        .await?;
                    response.ufm_unregistrations += 1;

                    //TODO: release VF GUID resource when VF supported.
                }
            }
            response.ufm_unregistaration_pending = false;

            // Delete the instance and allocated address
            // TODO: This might need some changes with the new state machine
            let delete_instance = DeleteInstance { instance_id };
            let _instance = delete_instance.delete(&mut txn).await?;
        }

        if let Some(machine) = &host_machine {
            if let Some(ip) = machine.bmc_info().ip.as_deref() {
                tracing::info!(
                    ip,
                    machine_id = %machine.id(),
                    "BMC ip for machine was found. Trying to perform Bios unlock",
                );

                match self
                    .redfish_pool
                    .create_client(
                        ip,
                        None,
                        RedfishCredentialType::Machine {
                            machine_id: machine.id().to_string(),
                        },
                    )
                    .await
                {
                    Ok(client) => {
                        let machine_id = machine.id().clone();
                        match client.lockdown_status().await {
                            Ok(status) if status.is_fully_disabled() => {
                                tracing::info!(%machine_id, "Bios is not locked down");
                                response.initial_lockdown_state = status.to_string();
                                response.machine_unlocked = false;
                            }
                            Ok(status) => {
                                tracing::info!(%machine_id, ?status, "Unlocking BIOS");
                                if let Err(e) =
                                    client.lockdown(libredfish::EnabledDisabled::Disabled).await
                                {
                                    tracing::warn!(%machine_id, error = %e, "Failed to unlock");
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = false;
                                } else {
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = true;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(%machine_id, error = %e, "Failed to fetch lockdown status");
                                response.initial_lockdown_state = "".to_string();
                                response.machine_unlocked = false;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.id(),
                            error = %e,
                            "Failed to create Redfish client. Skipping bios unlock",
                        );
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
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::DatabaseError(
                    file!(),
                    "begin delete dpu in admin_force_delete_machine",
                    e,
                )
            })?;

            if let Some(loopback_ip) = dpu_machine.loopback_ip() {
                self.common_pools
                    .ethernet
                    .pool_loopback_ip
                    .release(&mut txn, loopback_ip)
                    .await
                    .map_err(CarbideError::from)?
            }
            DpuToNetworkDeviceMap::delete(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;

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

    /// Example TOML data in request.text:
    ///
    /// [lo-ip]
    /// type = "ipv4"
    /// prefix = "10.180.62.1/26"
    ///
    /// or
    ///
    /// [vlan-id]
    /// type = "integer"
    /// ranges = [{ start = "100", end = "501" }]
    ///
    async fn admin_grow_resource_pool(
        &self,
        request: Request<rpc::GrowResourcePoolRequest>,
    ) -> Result<Response<rpc::GrowResourcePoolResponse>, Status> {
        log_request_data(&request);

        let toml_text = request.into_inner().text;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin admin_grow_resource_pool", e)
        })?;

        let mut pools = HashMap::new();
        let table: toml::Table = toml_text
            .parse()
            .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
        for (name, def) in table {
            let d: resource_pool::ResourcePoolDef = def
                .try_into()
                .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
            pools.insert(name, d);
        }
        use resource_pool::DefineResourcePoolError as DE;
        match resource_pool::define_all_from(&mut txn, &pools).await {
            Ok(()) => {
                txn.commit().await.map_err(|e| {
                    CarbideError::DatabaseError(file!(), "end admin_grow_resource_pool", e)
                })?;
                Ok(Response::new(rpc::GrowResourcePoolResponse {}))
            }
            Err(DE::InvalidArgument(msg)) => Err(tonic::Status::invalid_argument(msg)),
            Err(DE::InvalidToml(err)) => Err(tonic::Status::invalid_argument(err.to_string())),
            Err(DE::ResourcePoolError(msg)) => Err(tonic::Status::internal(msg.to_string())),
            Err(err @ DE::TooBig(_, _)) => Err(tonic::Status::out_of_range(err.to_string())),
        }
    }

    async fn admin_list_resource_pools(
        &self,
        request: Request<rpc::ListResourcePoolsRequest>,
    ) -> Result<tonic::Response<rpc::ResourcePools>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin admin_list_resource_pools ", e)
        })?;

        let snapshot = resource_pool::all(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "end admin_list_resource_pools", e)
        })?;

        Ok(Response::new(rpc::ResourcePools {
            pools: snapshot.into_iter().map(|s| s.into()).collect(),
        }))
    }

    /// Assign all VPCs a VNI
    async fn migrate_vpc_vni(
        &self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Response<rpc::MigrateVpcVniResponse>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin migrate_vpc_vni ", e))?;

        let mut updated_count = 0;
        let all_vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::All)
            .await
            .map_err(CarbideError::from)?;
        let total_vpc_count = all_vpcs.len() as u32;
        for mut vpc in all_vpcs {
            if vpc.vni.is_some() {
                continue;
            }
            vpc.vni = Some(self.allocate_vpc_vni(&mut txn, &vpc.id.to_string()).await?);
            Vpc::set_vni(&mut txn, vpc.id, vpc.vni.unwrap())
                .await
                .map_err(CarbideError::from)?;
            updated_count += 1;
        }
        tracing::info!(
            updated_count,
            total_vpc_count,
            "migrate_vpc_vni: Assigned a VNI to {updated_count} of {total_vpc_count} VPCs"
        );

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "end migrate_vpc_vni", e))?;

        Ok(Response::new(rpc::MigrateVpcVniResponse {
            updated_count,
            total_vpc_count,
        }))
    }

    /// Maintenance mode: Put a machine into maintenance mode or take it out.
    /// Switching a host into maintenance mode prevents an instance being assigned to it.
    async fn set_maintenance(
        &self,
        request: tonic::Request<rpc::MaintenanceRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let machine_id = match &req.host_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                tracing::warn!("forge agent control: missing host ID");
                return Err(Status::invalid_argument("Missing host ID"));
            }
        };
        log_machine_id(&machine_id);

        let (host_machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        if host_machine.is_dpu() {
            return Err(Status::invalid_argument(
                "DPU ID provided. Need managed host.",
            ));
        }
        let dpu_machine = Machine::find_dpu_by_host_machine_id(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?
            .ok_or(CarbideError::NotFoundError {
                kind: "dpu machine for host",
                id: machine_id.to_string(),
            })?;

        // We set status on both host and dpu machine to make them easier to query from DB
        let mode = match req.operation() {
            rpc::MaintenanceOperation::Enable => {
                let Some(reference) = req.reference else {
                    return Err(Status::invalid_argument("Missing reference url".to_string()));
                };
                MaintenanceMode::On { reference }
            }
            rpc::MaintenanceOperation::Disable => MaintenanceMode::Off,
        };
        Machine::set_maintenance_mode(&mut txn, host_machine.id(), mode.clone())
            .await
            .map_err(CarbideError::from)?;
        Machine::set_maintenance_mode(&mut txn, dpu_machine.id(), mode)
            .await
            .map_err(CarbideError::from)?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "end maintenance handler", e))?;

        Ok(Response::new(()))
    }

    async fn find_ip_address(
        &self,
        request: tonic::Request<rpc::FindIpAddressRequest>,
    ) -> Result<tonic::Response<rpc::FindIpAddressResponse>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let ip = req.ip;
        let (matches, errors) = ip_finder::find(self, &ip).await;
        if matches.is_empty() && errors.is_empty() {
            return Err(Status::not_found(ip));
        }
        Ok(Response::new(rpc::FindIpAddressResponse {
            matches,
            errors: errors.into_iter().map(|err| err.to_string()).collect(),
        }))
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let dpu_id = try_parse_machine_id(
            req.dpu_id
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("DPU ID is missing"))?,
        )
        .map_err(CarbideError::from)?;

        log_machine_id(&dpu_id);
        if !dpu_id.machine_type().is_dpu() {
            return Err(Status::invalid_argument(
                "Only DPU reprovisioning is supported.",
            ));
        }

        if !self.machine_update_config.dpu_nic_firmware_update_enabled && req.update_firmware {
            return Err(Status::invalid_argument(
                "DPU NIC firmware update is disabled.",
            ));
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin trigger_dpu_reprovisioning ", e)
        })?;

        let machine = Machine::find_one(&mut txn, &dpu_id, MachineSearchConfig::default())
            .await
            .map_err(CarbideError::from)?;

        let machine = machine.ok_or(CarbideError::NotFoundError {
            kind: "dpu",
            id: dpu_id.to_string(),
        })?;

        // Start reprovisioning only machine is in maintenance mode.
        if !machine.is_maintenance_mode() {
            return Err(Status::invalid_argument(
                "Machine is not in maintenance mode. Set it first.",
            ));
        }

        if let rpc::dpu_reprovisioning_request::Mode::Set = req.mode() {
            let initiator = req.initiator().as_str_name();
            machine
                .trigger_reprovisioning_request(&mut txn, initiator, req.update_firmware)
                .await
                .map_err(CarbideError::from)?;
        } else {
            Machine::clear_reprovisioning_request(&mut txn, &dpu_id)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "end trigger_dpu_reprovisioning", e)
        })?;

        Ok(Response::new(()))
    }

    /// List DPUs waiting for reprovisioning
    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningListRequest>,
    ) -> Result<tonic::Response<rpc::DpuReprovisioningListResponse>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin trigger_dpu_reprovisioning ", e)
        })?;

        let dpus = Machine::list_machines_pending_for_reprovisioning(&mut txn)
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .map(
                |x| rpc::dpu_reprovisioning_list_response::DpuReprovisioningListItem {
                    id: Some(rpc::MachineId {
                        id: x.id().to_string(),
                    }),
                    state: x.current_state().to_string(),
                    requested_at: x.reprovisioning_requested().map(|a| a.requested_at.into()),
                    initiator: x
                        .reprovisioning_requested()
                        .map(|a| a.initiator)
                        .unwrap_or_default(),
                    update_firmware: x
                        .reprovisioning_requested()
                        .map(|a| a.update_firmware)
                        .unwrap_or_default(),
                },
            )
            .collect_vec();

        Ok(Response::new(rpc::DpuReprovisioningListResponse { dpus }))
    }

    async fn get_machine_boot_override(
        &self,
        request: tonic::Request<rpc::Uuid>,
    ) -> Result<tonic::Response<rpc::MachineBootOverride>, tonic::Status> {
        log_request_data(&request);

        let machine_interface_id_str = &request.into_inner().value;

        let machine_interface_id = uuid::Uuid::parse_str(machine_interface_id_str)
            .map_err(CarbideError::UuidConversionError)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin get_machine_boot_override ", e)
        })?;

        let machine_id = match MachineInterface::find_one(&mut txn, machine_interface_id).await {
            Ok(interface) => interface.machine_id,
            Err(_) => None,
        };

        if let Some(machine_id) = machine_id {
            log_machine_id(&machine_id);
        }

        let mbo = match MachineBootOverride::find_optional(&mut txn, machine_interface_id).await? {
            Some(mbo) => mbo,
            None => MachineBootOverride {
                machine_interface_id,
                custom_pxe: None,
                custom_user_data: None,
            },
        };

        Ok(tonic::Response::new(mbo.into()))
    }

    async fn set_machine_boot_override(
        &self,
        request: tonic::Request<rpc::MachineBootOverride>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let mbo: MachineBootOverride = request.into_inner().try_into()?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin set_machine_boot_override ", e)
        })?;

        let machine_id = match MachineInterface::find_one(&mut txn, mbo.machine_interface_id).await
        {
            Ok(interface) => interface.machine_id,
            Err(_) => None,
        };
        match machine_id {
            Some(machine_id) => {
                log_machine_id(&machine_id);
                tracing::warn!(
                    machine_interface_id = mbo.machine_interface_id.to_string(),
                    machine_id = machine_id.to_string(),
                    "Boot override for machine_interface_id is active. Bypassing regular boot"
                );
            }

            None => tracing::warn!(
                machine_interface_id = mbo.machine_interface_id.to_string(),
                "Boot override for machine_interface_id is active. Bypassing regular boot"
            ),
        }

        mbo.update_or_insert(&mut txn).await?;

        txn.commit().await.unwrap();

        Ok(tonic::Response::new(()))
    }

    async fn clear_machine_boot_override(
        &self,
        request: tonic::Request<rpc::Uuid>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let machine_interface_id_str = &request.into_inner().value;

        let machine_interface_id = uuid::Uuid::parse_str(machine_interface_id_str)
            .map_err(CarbideError::UuidConversionError)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin clear_machine_boot_override ", e)
        })?;

        let machine_id = match MachineInterface::find_one(&mut txn, machine_interface_id).await {
            Ok(interface) => interface.machine_id,
            Err(_) => None,
        };
        match machine_id {
            Some(machine_id) => {
                log_machine_id(&machine_id);
                tracing::info!(
                    machine_interface_id = machine_interface_id_str,
                    machine_id = machine_id.to_string(),
                    "Boot override for machine_interface_id disabled."
                );
            }

            None => tracing::info!(
                machine_interface_id = machine_interface_id_str,
                "Boot override for machine_interface_id disabled"
            ),
        }
        MachineBootOverride::clear(&mut txn, machine_interface_id).await?;

        txn.commit().await.unwrap();

        Ok(tonic::Response::new(()))
    }

    async fn get_network_topology(
        &self,
        request: tonic::Request<rpc::NetworkTopologyRequest>,
    ) -> Result<tonic::Response<rpc::NetworkTopologyData>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_lldp_topology ", e))?;

        let query = match &req.id {
            Some(x) => ObjectFilter::One(x.as_str()),
            None => ObjectFilter::All,
        };

        let data = NetworkTopologyData::get_topology(&mut txn, query)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "end get_lldp_topology handler", e)
        })?;

        Ok(Response::new(data.into()))
    }

    async fn admin_bmc_reset(
        &self,
        request: tonic::Request<rpc::AdminBmcResetRequest>,
    ) -> Result<tonic::Response<rpc::AdminBmcResetResponse>, tonic::Status> {
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
                                "Vault key not found: bmc-metadata-items for machine_id {machine_id}"
                            ))
                        }
                        Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                        Err(err) => CarbideError::GenericError(format!(
                            "Error getting credentials for BMC: {err:?}"
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

        let endpoint = libredfish::Endpoint {
            user: Some(user),
            password: Some(password),
            host: req.ip.clone(),
            // Option<u32> -> Option<u16> because no uint16 in protobuf
            port: req.port.map(|p| p as u16),
        };

        let pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;
        let redfish = pool
            .create_client(endpoint)
            .await
            .map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "BMC reseting");
        redfish.bmc_reset().await.map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "Reset request succeeded");

        Ok(Response::new(rpc::AdminBmcResetResponse {}))
    }

    /// Should this DPU upgade it's forge-dpu-agent?
    /// Once the upgrade is complete record_dpu_network_status will receive the updated
    /// version and write the DB to say our upgrade is complete.
    async fn dpu_agent_upgrade_check(
        &self,
        request: tonic::Request<rpc::DpuAgentUpgradeCheckRequest>,
    ) -> Result<tonic::Response<rpc::DpuAgentUpgradeCheckResponse>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let machine_id = MachineId::from_str(&req.machine_id).map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMachineId(
                req.machine_id.clone(),
            ))
        })?;
        log_machine_id(&machine_id);
        if !machine_id.machine_type().is_dpu() {
            return Err(Status::invalid_argument(
                "Upgrade check can only be performed on DPUs",
            ));
        }

        // We usually want these two to match
        let agent_version = req.current_agent_version;
        let server_version = forge_version::v!(build_version);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin dpu_agent_upgrade_check ", e)
        })?;
        let machine = Machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
            .await
            .map_err(CarbideError::from)?;
        let machine = machine.ok_or(CarbideError::NotFoundError {
            kind: "dpu",
            id: machine_id.to_string(),
        })?;
        let should_upgrade = machine.needs_agent_upgrade();
        if should_upgrade {
            tracing::debug!(
                %machine_id,
                agent_version,
                server_version,
                "Needs forge-dpu-agent upgrade",
            );
        } else {
            tracing::trace!(%machine_id, agent_version, "forge-dpu-agent is up to date");
        }
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "end dpu_agent_upgrade_check handler", e)
        })?;

        // The debian/ubuntu package version is our build_version minus the initial `v`
        let package_version = &server_version[1..];

        let response = rpc::DpuAgentUpgradeCheckResponse {
            should_upgrade,
            package_version: package_version.to_string(),
            server_version: server_version.to_string(),
        };
        Ok(tonic::Response::new(response))
    }

    /// Get or set the forge-dpu-agent upgrade policy.
    async fn dpu_agent_upgrade_policy_action(
        &self,
        request: tonic::Request<rpc::DpuAgentUpgradePolicyRequest>,
    ) -> Result<tonic::Response<rpc::DpuAgentUpgradePolicyResponse>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin apply_agent_upgrade_policy_all", e)
        })?;

        let req = request.into_inner();
        let mut did_change = false;
        if let Some(new_policy) = req.new_policy {
            let policy: AgentUpgradePolicy = new_policy.into();

            DpuAgentUpgradePolicy::set(&mut txn, policy)
                .await
                .map_err(CarbideError::from)?;
            did_change = true;
        }

        let Some(active_policy) = DpuAgentUpgradePolicy::get(&mut txn)
            .await
            .map_err(CarbideError::from)? else {
                return Err(tonic::Status::not_found("No agent upgrade policy"));
        };
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit apply_agent_upgrade_policy_all", e)
        })?;
        let response = rpc::DpuAgentUpgradePolicyResponse {
            active_policy: active_policy.into(),
            did_change,
        };
        Ok(tonic::Response::new(response))
    }

    async fn create_credential(
        &self,
        request: tonic::Request<rpc::CredentialCreationRequest>,
    ) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();
        let password = req.password;

        let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
            CarbideError::NotFoundError {
                kind: "credential_type",
                id: req.credential_type.to_string(),
            }
        })?;

        match credential_type {
            rpc::CredentialType::HostBmc => {
                if (self
                    .credential_provider
                    .get_credentials(CredentialKey::HostRedfish {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await)
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Not support to reset host BMC credential",
                    ));
                }

                self.credential_provider
                    .set_credentials(
                        CredentialKey::HostRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: FORGE_SITE_WIDE_BMC_USERNAME.to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for Host Bmc: {:?} ",
                            e
                        ))
                    })?
            }
            rpc::CredentialType::Dpubmc => {
                if (self
                    .credential_provider
                    .get_credentials(CredentialKey::DpuRedfish {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await)
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Not support to reset DPU BMC credential",
                    ));
                }
                self.credential_provider
                    .set_credentials(
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: FORGE_SITE_WIDE_BMC_USERNAME.to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for DPU Bmc: {:?} ",
                            e
                        ))
                    })?
            }
            rpc::CredentialType::Ufm => {
                if let Some(username) = req.username {
                    self.credential_provider
                        .set_credentials(
                            CredentialKey::UfmAuth {
                                fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                            },
                            Credentials::UsernamePassword {
                                username: username.clone(),
                                password: password.clone(),
                            },
                        )
                        .await
                        .map_err(|e| {
                            CarbideError::GenericError(format!(
                                "Error setting credential for Ufm {}: {:?} ",
                                username.clone(),
                                e
                            ))
                        })?;
                } else {
                    return Err(tonic::Status::invalid_argument("missing UFM Url"));
                }
            }
        };

        Ok(Response::new(rpc::CredentialCreationResult {}))
    }

    async fn delete_credential(
        &self,
        request: tonic::Request<rpc::CredentialDeletionRequest>,
    ) -> Result<tonic::Response<rpc::CredentialDeletionResult>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
            CarbideError::NotFoundError {
                kind: "credential_type",
                id: req.credential_type.to_string(),
            }
        })?;

        match credential_type {
            rpc::CredentialType::Ufm => {
                if let Some(username) = req.username {
                    self.credential_provider
                        .set_credentials(
                            CredentialKey::UfmAuth {
                                fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                            },
                            Credentials::UsernamePassword {
                                username: username.clone(),
                                password: "".to_string(),
                            },
                        )
                        .await
                        .map_err(|e| {
                            CarbideError::GenericError(format!(
                                "Error deleting credential for Ufm {}: {:?} ",
                                username.clone(),
                                e
                            ))
                        })?;
                } else {
                    return Err(tonic::Status::invalid_argument("missing UFM Url"));
                }
            }
            rpc::CredentialType::HostBmc | rpc::CredentialType::Dpubmc => {
                // Not support delete BMC credential
            }
        };

        Ok(Response::new(rpc::CredentialDeletionResult {}))
    }

    /// Returns a list of all configured route server addresses
    async fn get_route_servers(
        &self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Response<rpc::RouteServers>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_route_servers", e))?;

        let route_servers = RouteServer::get(&mut txn).await?;

        Ok(tonic::Response::new(rpc::RouteServers {
            route_servers: route_servers
                .into_iter()
                .map(|rs| rs.address.to_string())
                .collect(),
        }))
    }

    /// Overwrites all existing route server entries with the provided list
    async fn add_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        if !self.eth_data.route_servers_enabled {
            return Err(
                CarbideError::InvalidArgument("Route servers are disabled".to_string()).into(),
            );
        }
        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_route_servers", e))?;

        RouteServer::add(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit get_route_servers", e))?;

        Ok(tonic::Response::new(()))
    }

    async fn remove_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_route_servers", e))?;

        RouteServer::remove(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit get_route_servers", e))?;

        Ok(tonic::Response::new(()))
    }

    /// Overwrites all existing route server entries with the provided list
    async fn replace_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin get_route_servers", e))?;

        RouteServer::replace(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit get_route_servers", e))?;

        Ok(tonic::Response::new(()))
    }
}

/// this function blocks, don't use it in a raw async context
fn get_tls_acceptor<S: AsRef<str>>(
    identity_pemfile_path: S,
    identity_keyfile_path: S,
    root_cafile_path: S,
    admin_root_cafile_path: S,
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
                tracing::error!(?error, "Rustls error reading certs");
                return None;
            }
        }
    };

    let key = {
        let fd = match std::fs::File::open(identity_keyfile_path.as_ref()) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);

        match rustls_pemfile::ec_private_keys(&mut buf) {
            Ok(keys) => keys.into_iter().map(PrivateKey).next(),
            error => {
                tracing::error!(?error, "Rustls error reading key");
                None
            }
        }
    };

    let key = match key {
        Some(key) => key,
        None => {
            tracing::error!("Rustls error: no keys?");
            return None;
        }
    };

    let mut roots = RootCertStore::empty();
    match std::fs::read(root_cafile_path.as_ref()) {
        Ok(pem_file) => {
            let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
            let certs_to_add = match rustls_pemfile::certs(&mut cert_cursor) {
                Ok(certs) => certs,
                Err(error) => {
                    tracing::error!(?error, "error parsing root ca cert file");
                    return None;
                }
            };
            let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add.as_slice());
        }
        Err(error) => {
            tracing::error!(?error, "error reading root ca cert file");
            return None;
        }
    }

    if let Ok(pem_file) = std::fs::read(admin_root_cafile_path.as_ref()) {
        let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
        let certs_to_add = match rustls_pemfile::certs(&mut cert_cursor) {
            Ok(certs) => certs,
            Err(error) => {
                tracing::error!(?error, "error parsing admin ca cert file");
                return None;
            }
        };
        let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add.as_slice());
    }

    match ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(AllowAnyAnonymousOrAuthenticatedClient::new(roots))
        .with_single_cert(certs, key)
    {
        Ok(mut tls) => {
            tls.alpn_protocols = vec![b"h2".to_vec()];
            Some(TlsAcceptor::from(Arc::new(tls)))
        }
        Err(error) => {
            tracing::error!(?error, "Rustls error building server config");
            None
        }
    }
}

// This is used as an extension to requests for anything that is an attribute of
// the connection the request came in on, as opposed to the HTTP request itself.
// Note that if you're trying to retrieve it, it's probably inside an Arc in the
// extensions typemap, so .get::<Arc<ConnectionAttributes>>() is what you want.
pub struct ConnectionAttributes {
    peer_address: SocketAddr,
    peer_certificates: Vec<Certificate>,
}

impl ConnectionAttributes {
    pub fn peer_address(&self) -> &SocketAddr {
        &self.peer_address
    }

    pub fn peer_certificates(&self) -> &[Certificate] {
        self.peer_certificates.as_slice()
    }
}

#[tracing::instrument(skip_all)]
async fn api_handler<C1, C2>(
    api_service: Arc<Api<C1, C2>>,
    listen_port: SocketAddr,
    meter: Meter,
) -> eyre::Result<()>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    let api_reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
        .build()?;

    let identity_pemfile_path = api_service.tls_config.identity_pemfile_path.clone();
    let identity_keyfile_path = api_service.tls_config.identity_keyfile_path.clone();
    let root_cafile_path = api_service.tls_config.root_cafile_path.clone();
    let admin_root_cafile_path = api_service.tls_config.admin_root_cafile_path.clone();

    let identity_pemfile_path_clone = identity_pemfile_path.clone();
    let identity_keyfile_path_clone = identity_keyfile_path.clone();
    let root_cafile_path_clone = root_cafile_path.clone();
    let admin_root_cafile_path_clone = admin_root_cafile_path.clone();

    let mut tls_acceptor = tokio::task::spawn_blocking(move || {
        get_tls_acceptor(
            identity_pemfile_path_clone,
            identity_keyfile_path_clone,
            root_cafile_path_clone,
            admin_root_cafile_path_clone,
        )
    })
    .await?;

    let listener = TcpListener::bind(listen_port).await?;
    let mut http = Http::new();
    http.http2_only(true);

    let authn_layer = auth::middleware::AuthenticationMiddleware::default();
    let authz_layer = {
        // TODO: move the initialization of the Authorizer here instead
        let authorizer = Arc::new(api_service.authorizer.clone());
        let authz_handler = auth::middleware::AuthzHandler::new(authorizer);
        AsyncRequireAuthorizationLayer::new(authz_handler)
    };

    let svc = Server::builder()
        .layer(LogLayer::new(meter.clone()))
        .layer(authn_layer)
        .layer(authz_layer)
        .add_service(rpc::forge_server::ForgeServer::from_arc(api_service))
        .add_service(api_reflection_service)
        .into_service();

    let connection_total_counter = meter
        .u64_counter("carbide-api.tls.connection_total")
        .with_description("The amount of tls connections that were attempted")
        .init();
    let connection_succeeded_counter = meter
        .u64_counter("carbide-api.tls.connection_success")
        .with_description("The amount of tls connections that were successful")
        .init();
    let connection_failed_counter = meter
        .u64_counter("carbide-api.tls.connection_fail")
        .with_description("The amount of tcp connections that were failures")
        .init();

    let mut tls_acceptor_created = Instant::now();
    let mut initialize_tls_acceptor = true;
    loop {
        let incoming_connection = listener.accept().await;
        connection_total_counter.add(1, &[]);
        let (conn, addr) = match incoming_connection {
            Ok(incoming) => incoming,
            Err(e) => {
                tracing::error!(error = %e, "Error accepting connection");
                connection_failed_counter
                    .add(1, &[KeyValue::new("reason", "tcp_connection_failure")]);
                continue;
            }
        };

        // TODO: RT: change the subroutine to return the certificate's parsed expiration from
        // the file on disk and only refresh if it's actually necessary to do so,
        // and emit a metric for the remaining duration on the cert

        // hard refresh our certs every five minutes
        // they may have been rewritten on disk by cert-manager and we want to honor the new cert.
        if initialize_tls_acceptor
            || tls_acceptor_created.elapsed() > tokio::time::Duration::from_secs(5 * 60)
        {
            tracing::info!("Refreshing certs");
            initialize_tls_acceptor = false;
            tls_acceptor_created = Instant::now();

            let identity_pemfile_path_clone = identity_pemfile_path.clone();
            let identity_keyfile_path_clone = identity_keyfile_path.clone();
            let root_cafile_path_clone = root_cafile_path.clone();
            let admin_root_cafile_path_clone = admin_root_cafile_path.clone();
            tls_acceptor = tokio::task::spawn_blocking(move || {
                get_tls_acceptor(
                    identity_pemfile_path_clone,
                    identity_keyfile_path_clone,
                    root_cafile_path_clone,
                    admin_root_cafile_path_clone,
                )
            })
            .await?;
        }

        let tls_acceptor = tls_acceptor.clone();
        let http = http.clone();
        let svc = svc.clone();
        let connection_succeeded_counter = connection_succeeded_counter.clone();
        let connection_failed_counter = connection_failed_counter.clone();
        tokio::spawn(async move {
            if let Some(tls_acceptor) = tls_acceptor {
                match tls_acceptor.accept(conn).await {
                    Ok(conn) => {
                        connection_succeeded_counter.add(1, &[]);

                        let (_, session) = conn.get_ref();
                        let connection_attributes = {
                            let peer_address = addr;
                            let peer_certificates =
                                session.peer_certificates().unwrap_or_default().to_vec();
                            Arc::new(ConnectionAttributes {
                                peer_address,
                                peer_certificates,
                            })
                        };
                        let conn_attrs_extension_layer =
                            AddExtensionLayer::new(connection_attributes);

                        let svc = tower::ServiceBuilder::new()
                            .layer(conn_attrs_extension_layer)
                            .service(svc);
                        // TODO: Why does this returns an error Io / UnexpectedEof on every single request?
                        // `h2` already logs the error at DEBUG level
                        let _ = http.serve_connection(conn, svc).await;
                    }
                    Err(error) => {
                        tracing::error!(%error, address = %addr, "error accepting tls connection");
                        connection_failed_counter
                            .add(1, &[KeyValue::new("reason", "tls_connection_failure")]);
                    }
                }
            } else {
                //servicing without tls -- HTTP only
                connection_succeeded_counter.add(1, &[]);
                if let Err(error) = http.serve_connection(conn, svc).await {
                    tracing::debug!(%error, "error servicing plain http connection");
                }
            }
        });
    }
}

fn log_request_data<T: std::fmt::Debug>(request: &Request<T>) {
    tracing::Span::current().record(
        "request",
        truncate(format!("{:?}", request.get_ref()), 1500),
    );
}

/// Logs the Machine ID in the current tracing span
fn log_machine_id(machine_id: &MachineId) {
    tracing::Span::current().record("forge.machine_id", machine_id.to_string());
}

fn truncate(mut s: String, len: usize) -> String {
    if s.len() < len || len < 3 {
        return s;
    }
    s.truncate(len);
    if s.is_char_boundary(len - 2) {
        s.replace_range(len - 2..len, "..");
    }
    s
}

impl<C1, C2> Api<C1, C2>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_provider: Arc<C1>,
        certificate_provider: Arc<C2>,
        database_connection: sqlx::PgPool,
        authorizer: auth::Authorizer,
        redfish_pool: Arc<dyn RedfishClientPool>,
        eth_data: ethernet_virtualization::EthVirtData,
        common_pools: Arc<CommonPools>,
        tls_config: ApiTlsConfig,
        machine_update_config: MachineUpdateConfig,
        ib_fabric_manager: Arc<dyn IBFabricManager>,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            certificate_provider,
            authorizer,
            redfish_pool,
            eth_data,
            common_pools,
            tls_config,
            machine_update_config,
            ib_fabric_manager,
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn start(
        carbide_config: Arc<CarbideConfig>,
        credential_provider: Arc<C1>,
        certificate_provider: Arc<C2>,
        meter: opentelemetry::metrics::Meter,
        ipmi_tool: Arc<dyn IPMITool>,
    ) -> eyre::Result<()> {
        let service_config = if carbide_config.rapid_iterations {
            tracing::info!("Running with rapid iterations for local development");
            ServiceConfig::for_local_development()
        } else {
            ServiceConfig::default()
        };

        let rf_pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;
        let redfish_pool = RedfishClientPoolImpl::new(credential_provider.clone(), rf_pool);
        let shared_redfish_pool: Arc<dyn RedfishClientPool> = Arc::new(redfish_pool);

        // Configure the postgres connection pool
        // We need logs to be enabled at least at `INFO` level. Otherwise
        // our global logging filter would reject the logs before they get injected
        // into the `SqlxQueryTracing` layer.
        let mut database_connect_options = carbide_config
            .database_url
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .log_statements("INFO".parse().unwrap());
        if let Some(ref tls_config) = carbide_config.tls {
            let tls_disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok(); // the integration test doesn't like this
            if !tls_disabled {
                tracing::info!("using TLS for postgres connection.");
                database_connect_options = database_connect_options
                    .ssl_mode(PgSslMode::Require) //TODO: move this to VerifyFull once it actually works
                    .ssl_root_cert(&tls_config.root_cafile_path);
            }
        }
        let database_connection = sqlx::pool::PoolOptions::new()
            .max_connections(service_config.max_db_connections)
            .connect_with(database_connect_options)
            .await?;

        if let Some(domain_name) = &carbide_config.initial_domain_name {
            if Self::create_initial_domain(database_connection.clone(), domain_name).await? {
                tracing::info!("Created initial domain {domain_name}");
            }
        }

        let mut txn = database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin define resource pools", e))?;
        resource_pool::define_all_from(&mut txn, carbide_config.pools.as_ref().unwrap()).await?;
        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit define resource pools", e))?;

        let common_pools = CommonPools::create(database_connection.clone()).await?;

        let ib_fabric_manager_impl = ib::create_ib_fabric_manager(
            credential_provider.clone(),
            carbide_config.enable_ib_fabric.unwrap_or(false),
        );

        let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

        let authorizer = auth::Authorizer::build_casbin(
            &carbide_config
                .auth
                .as_ref()
                .expect("Missing auth config")
                .casbin_policy_file,
            carbide_config
                .auth
                .as_ref()
                .expect("Missing auth config")
                .permissive_mode,
        )
        .await?;

        let route_servers =
            Self::create_initial_route_servers(&database_connection, &carbide_config).await?;

        let eth_data = ethernet_virtualization::EthVirtData {
            asn: carbide_config.asn,
            dhcp_servers: carbide_config.dhcp_servers.clone(),
            route_servers,
            route_servers_enabled: carbide_config.enable_route_servers,
            // Include the site fabric prefixes in the deny prefixes list, since
            // we treat them the same way from here.
            deny_prefixes: [
                carbide_config.site_fabric_prefixes.as_slice(),
                carbide_config.deny_prefixes.as_slice(),
            ]
            .concat(),
        };

        let health_pool = database_connection.clone();
        start_export_service_health_metrics(ServiceHealthContext {
            meter: meter.clone(),
            database_pool: health_pool,
            resource_pool_stats: Some(common_pools.pool_stats.clone()),
        });

        let tls_ref = carbide_config.tls.as_ref().expect("Missing tls config");

        let tls_config = ApiTlsConfig {
            identity_pemfile_path: tls_ref.identity_pemfile_path.clone(),
            identity_keyfile_path: tls_ref.identity_keyfile_path.clone(),
            root_cafile_path: tls_ref.root_cafile_path.clone(),
            admin_root_cafile_path: tls_ref.admin_root_cafile_path.clone(),
        };

        let machine_update_config = MachineUpdateConfig {
            dpu_nic_firmware_update_enabled: carbide_config.dpu_nic_firmware_update_enabled,
        };

        let api_service = Arc::new(Api {
            credential_provider: credential_provider.clone(),
            certificate_provider: certificate_provider.clone(),
            database_connection: database_connection.clone(),
            authorizer,
            redfish_pool: shared_redfish_pool.clone(),
            eth_data,
            common_pools: common_pools.clone(),
            tls_config,
            machine_update_config,
            ib_fabric_manager: ib_fabric_manager.clone(),
        });

        if let Some(networks) = carbide_config.networks.as_ref() {
            api_service.create_initial_networks(networks).await?;
        }

        let mut txn = database_connection
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin agent upgrade policy", e))?;
        let initial_policy: AgentUpgradePolicy = carbide_config
            .initial_dpu_agent_upgrade_policy
            .unwrap_or(super::cfg::AgentUpgradePolicyChoice::Off)
            .into();
        let current_policy = DpuAgentUpgradePolicy::get(&mut txn).await?;
        // Only set if the very first time, it's the initial policy
        if current_policy.is_none() {
            DpuAgentUpgradePolicy::set(&mut txn, initial_policy).await?;
            tracing::debug!(
                %initial_policy,
                "Initialized DPU agent upgrade policy"
            );
        }
        txn.commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit agent upgrade policy", e))?;

        // handles need to be stored in a variable
        // If they are assigned to _ then the destructor will be immediately called
        let _machine_state_controller_handle =
            StateController::<MachineStateControllerIO>::builder()
                .database(database_connection.clone())
                .meter("forge_machines", meter.clone())
                .redfish_client_pool(shared_redfish_pool.clone())
                .ib_fabric_manager(ib_fabric_manager.clone())
                .forge_api(api_service.clone())
                .iteration_time(service_config.machine_state_controller_iteration_time)
                .state_handler(Arc::new(MachineStateHandler::new(
                    service_config.dpu_up_threshold,
                    carbide_config.dpu_nic_firmware_update_enabled,
                )))
                .reachability_params(ReachabilityParams {
                    dpu_wait_time: service_config.dpu_wait_time,
                })
                .ipmi_tool(ipmi_tool.clone())
                .build()
                .expect("Unable to build MachineStateController");

        let sc_pool_vlan_id = common_pools.ethernet.pool_vlan_id.clone();
        let sc_pool_vni = common_pools.ethernet.pool_vni.clone();

        let ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
            .database(database_connection.clone())
            .meter("forge_network_segments", meter.clone())
            .redfish_client_pool(shared_redfish_pool.clone())
            .ib_fabric_manager(ib_fabric_manager.clone())
            .forge_api(api_service.clone());
        let _network_segment_controller_handle = ns_builder
            .iteration_time(service_config.network_segment_state_controller_iteration_time)
            .state_handler(Arc::new(NetworkSegmentStateHandler::new(
                service_config.network_segment_drain_time,
                sc_pool_vlan_id,
                sc_pool_vni,
            )))
            .reachability_params(ReachabilityParams {
                dpu_wait_time: service_config.dpu_wait_time,
            })
            .ipmi_tool(ipmi_tool.clone())
            .build()
            .expect("Unable to build NetworkSegmentController");

        let _ib_partition_controller_handle =
            StateController::<IBPartitionStateControllerIO>::builder()
                .database(database_connection.clone())
                .meter("forge_ib_partitions", meter.clone())
                .redfish_client_pool(shared_redfish_pool.clone())
                .ib_fabric_manager(ib_fabric_manager.clone())
                .pool_pkey(common_pools.infiniband.pool_pkey.clone())
                .reachability_params(ReachabilityParams {
                    dpu_wait_time: service_config.dpu_wait_time,
                })
                .forge_api(api_service.clone())
                .iteration_time(service_config.network_segment_state_controller_iteration_time)
                .state_handler(Arc::new(IBPartitionStateHandler::new(
                    service_config.network_segment_drain_time,
                )))
                .ipmi_tool(ipmi_tool.clone())
                .build()
                .expect("Unable to build IBPartitionStateController");

        let _bmc_machine_controller_handle =
            StateController::<BmcMachineStateControllerIO>::builder()
                .database(database_connection.clone())
                .meter("forge_bmc_machines", meter.clone())
                .redfish_client_pool(shared_redfish_pool.clone())
                .ib_fabric_manager(ib_fabric_manager.clone())
                .reachability_params(ReachabilityParams {
                    dpu_wait_time: service_config.dpu_wait_time,
                })
                .forge_api(api_service.clone())
                .iteration_time(service_config.network_segment_state_controller_iteration_time)
                .state_handler(Arc::new(BmcMachineStateHandler::default()))
                .ipmi_tool(ipmi_tool.clone())
                .build()
                .expect("Unable to build BmcMachineController");

        let machine_update_manager = MachineUpdateManager::new(
            database_connection.clone(),
            carbide_config.clone(),
            meter.clone(),
        );
        let _machine_update_manager_handler = machine_update_manager.start();

        let listen_addr = carbide_config.listen;
        api_handler(api_service, listen_addr, meter).await
    }

    /// Create a Domain if we don't already have one.
    /// Returns true if we created an entry in the db (we had no domains yet), false otherwise.
    async fn create_initial_domain(
        db_pool: sqlx::pool::Pool<Postgres>,
        domain_name: &str,
    ) -> Result<bool, CarbideError> {
        let mut txn = db_pool
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin create_initial_domain", e))?;
        let domains = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
        if domains.is_empty() {
            let domain = NewDomain::new(domain_name);
            domain.persist_first(&mut txn).await?;
            txn.commit().await.map_err(|e| {
                CarbideError::DatabaseError(file!(), "commit create_initial_domain", e)
            })?;
            Ok(true)
        } else {
            let names: Vec<String> = domains.into_iter().map(|d| d.name).collect();
            if !names.iter().any(|n| n == domain_name) {
                tracing::warn!(
                    "Initial domain name '{domain_name}' in config file does not match existing database domains: {:?}",
                    names
                );
            }
            Ok(false)
        }
    }

    // pub so we can test it from integration test
    pub async fn create_initial_networks(
        &self,
        networks: &HashMap<String, NetworkDefinition>,
    ) -> Result<(), CarbideError> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin create_initial_networks", e)
        })?;
        let all_domains = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
        if all_domains.len() != 1 {
            // We only create initial networks if we only have a single domain - usually created
            // as initial_domain_name in config file.
            // Having multiple domains is fine, it means we probably created the network much
            // earlier.
            tracing::info!("Multiple domains, skipping initial network creation");
            return Ok(());
        }
        let domain_id = all_domains[0].id;
        for (name, def) in networks {
            if NetworkSegment::find_by_name(&mut txn, name).await.is_ok() {
                // Network segments are only created the first time we start carbide-api
                tracing::debug!("Network segment {name} exists");
                continue;
            }
            let ns = NewNetworkSegment::build_from(name, domain_id, def)?;
            self.save_network_segment(&mut txn, ns, true).await?;
            tracing::info!("Created network segment {name}");
        }
        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit create_initial_networks", e)
        })?;
        Ok(())
    }

    pub async fn create_initial_route_servers(
        database_connection: &Pool<Postgres>,
        carbide_config: &Arc<CarbideConfig>,
    ) -> Result<Vec<String>, CarbideError> {
        let mut txn = database_connection.begin().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "begin create_initial_route_servers", e)
        })?;
        let result = if carbide_config.enable_route_servers {
            let route_servers: Vec<IpAddr> = carbide_config
                .route_servers
                .iter()
                .map(|rs| IpAddr::from_str(rs))
                .collect::<Result<Vec<IpAddr>, _>>()
                .map_err(CarbideError::AddressParseError)?;

            RouteServer::get_or_create(&mut txn, &route_servers).await?
        } else {
            RouteServer::replace(&mut txn, &vec![]).await?;
            vec![]
        };

        txn.commit().await.map_err(|e| {
            CarbideError::DatabaseError(file!(), "commit create_initial_route_servers", e)
        })?;
        Ok(result.into_iter().map(|rs| rs.to_string()).collect())
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
                tracing::warn!(%machine_id, error = %err, "failed loading machine");
                return Err(CarbideError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                tracing::info!(%machine_id, "machine not found");
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
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_loopback_ip(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Ipv4Addr, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_loopback_ip
            .allocate(txn, resource_pool::OwnerType::Machine, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(owner_id, pool = "lo-ip", "Pool exhausted, cannot allocate");
                Err(CarbideError::ResourceExhausted("pool lo-ip".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "lo-ip", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the vni resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_vni(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<i32, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_vni
            .allocate(txn, resource_pool::OwnerType::NetworkSegment, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(owner_id, pool = "vni", "Pool exhausted, cannot allocate");
                Err(CarbideError::ResourceExhausted("pool vni".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "vni", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the vlan id resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_vlan_id(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<i16, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_vlan_id
            .allocate(txn, resource_pool::OwnerType::NetworkSegment, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(
                    owner_id,
                    pool = "vlan_id",
                    "Pool exhausted, cannot allocate"
                );
                Err(CarbideError::ResourceExhausted("pool vlan_id".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "vlan_id", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the vpc vni resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_vpc_vni(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<i32, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_vpc_vni
            .allocate(txn, resource_pool::OwnerType::Vpc, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(
                    owner_id,
                    pool = "vpc_vni",
                    "Pool exhausted, cannot allocate"
                );
                Err(CarbideError::ResourceExhausted("pool vpc_vni".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "vpc_vni", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the pkey resource pool.
    ///
    /// If the pool doesn't exist return error.
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_pkey(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<i16>, CarbideError> {
        match self
            .common_pools
            .infiniband
            .pool_pkey
            .as_ref()
            .allocate(txn, resource_pool::OwnerType::IBPartition, owner_id)
            .await
        {
            Ok(val) => Ok(Some(val)),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(owner_id, pool = "pkey", "Pool exhausted, cannot allocate");
                Err(CarbideError::ResourceExhausted("pool pkey".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "pkey", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    async fn save_network_segment(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        mut ns: NewNetworkSegment,
        set_to_ready: bool,
    ) -> Result<NetworkSegment, CarbideError> {
        if ns.segment_type != NetworkSegmentType::Underlay {
            ns.vlan_id = Some(self.allocate_vlan_id(txn, &ns.name).await?);
            ns.vni = Some(self.allocate_vni(txn, &ns.name).await?);
        }
        let initial_state = if set_to_ready {
            NetworkSegmentControllerState::Ready
        } else {
            NetworkSegmentControllerState::Provisioning
        };
        let network_segment = match ns.persist(txn, initial_state).await {
            Ok(segment) => segment,
            Err(DatabaseError {
                source: sqlx::Error::Database(e),
                ..
            }) if e.constraint() == Some("network_prefixes_prefix_excl") => {
                return Err(CarbideError::NetworkSegmentPrefixOverlap)
            }
            Err(err) => {
                return Err(err.into());
            }
        };
        Ok(network_segment)
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
    /// How long to wait for DPU to restart after BMC lockdown. Not a timeout, it's a forced wait.
    /// This will be replaced with querying lockdown state.
    dpu_wait_time: chrono::Duration,
    /// How long to wait for a health report from the DPU before we assume it's down
    dpu_up_threshold: chrono::Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::minutes(5),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(30),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(30),
            max_db_connections: 1000,
            dpu_wait_time: Duration::minutes(5),
            dpu_up_threshold: Duration::minutes(5),
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
            dpu_wait_time: Duration::seconds(1),
            // In local dev forge-dpu-agent probably isn't running, so no heartbeat
            dpu_up_threshold: Duration::weeks(52),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn test_truncate() {
        let s = "hello world".to_string();
        let len = 10;
        assert_eq!(truncate(s, len), "hello wo..");
    }
}
