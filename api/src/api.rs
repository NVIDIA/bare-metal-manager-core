/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::db::attestation as db_attest;
use crate::db::network_segment::NetworkSegment;
use crate::model::instance::config::network::NetworkDetails;
pub use ::rpc::forge as rpc;
use ::rpc::forge::BmcEndpointRequest;
use ::rpc::forge_agent_control_response::forge_agent_control_extra_info::KeyValuePair;
use ::rpc::protos::forge::{
    EchoRequest, EchoResponse, InstancePhoneHomeLastContactRequest,
    InstancePhoneHomeLastContactResponse, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse,
};
use ::rpc::protos::measured_boot as measured_boot_pb;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialProvider};
use itertools::Itertools;
use libredfish::SystemPowerControl;
use mac_address::MacAddress;
use sqlx::{Postgres, Transaction};
use tonic::{Request, Response, Status};
use tss_esapi::{
    structures::{Attest, Public as TssPublic, Signature},
    traits::UnMarshall,
};

use self::rpc::forge_server::Forge;
use crate::attestation as attest;
use crate::cfg::file::CarbideConfig;
use crate::db::explored_endpoints::DbExploredEndpoint;
use crate::db::ib_partition::IBPartition;
use crate::db::machine::{MachineSearchConfig, MaintenanceMode};
use crate::db::machine_validation::{
    MachineValidation, MachineValidationState, MachineValidationStatus,
};
use crate::db::managed_host::LoadSnapshotOptions;
use crate::db::network_devices::NetworkDeviceSearchConfig;
use crate::dynamic_settings;
use crate::handlers::machine_validation::{
    add_machine_validation_test, add_update_machine_validation_external_config,
    get_machine_validation_external_config, get_machine_validation_external_configs,
    get_machine_validation_results, get_machine_validation_runs, get_machine_validation_tests,
    machine_validation_test_enable_disable_test, machine_validation_test_next_version,
    machine_validation_test_verfied, mark_machine_validation_complete,
    on_demand_machine_validation, persist_validation_result,
    remove_machine_validation_external_config, update_machine_validation_run,
    update_machine_validation_test,
};
use crate::ib::{IBFabricManager, DEFAULT_IB_FABRIC_NAME};
use crate::logging::log_limiter::LogLimiter;
use crate::measured_boot;
use crate::model::machine::machine_id::{
    from_hardware_info, host_id_from_dpu_hardware_info, try_parse_machine_id,
};
use crate::model::machine::{
    get_action_for_dpu_state, DpuInitState, DpuInitStates, FailureCause, FailureDetails,
    FailureSource, ManagedHostState, ManagedHostStateSnapshot,
};
use crate::model::network_devices::{DpuToNetworkDeviceMap, NetworkDevice, NetworkTopologyData};
use crate::model::tenant::Tenant;
use crate::redfish::RedfishAuth;
use crate::resource_pool;
use crate::resource_pool::common::CommonPools;
use crate::site_explorer::EndpointExplorer;
use crate::storage::NvmeshClientPool;
use crate::{
    auth,
    db::{
        self,
        explored_managed_host::DbExploredManagedHost,
        instance::{DeleteInstance, Instance},
        machine::Machine,
        machine_topology::MachineTopology,
        DatabaseError, ObjectFilter,
    },
    ethernet_virtualization,
    model::{hardware_info::HardwareInfo, machine::MachineState},
    redfish::RedfishClientPool,
    CarbideError, CarbideResult,
};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::machine::{MachineId, MachineType};
use forge_uuid::{infiniband::IBPartitionId, machine::MachineInterfaceId};
use utils::HostPortPair;

pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    pub(crate) credential_provider: Arc<dyn CredentialProvider>,
    pub(crate) certificate_provider: Arc<dyn CertificateProvider>,
    pub(crate) redfish_pool: Arc<dyn RedfishClientPool>,
    pub(crate) nvmesh_pool: Arc<dyn NvmeshClientPool>,
    pub(crate) eth_data: ethernet_virtualization::EthVirtData,
    pub(crate) common_pools: Arc<CommonPools>,
    pub(crate) ib_fabric_manager: Arc<dyn IBFabricManager>,
    pub(crate) runtime_config: Arc<CarbideConfig>,
    pub(crate) dpu_health_log_limiter: LogLimiter<MachineId>,
    pub dynamic_settings: dynamic_settings::DynamicSettings,
    pub(crate) endpoint_explorer: Arc<dyn EndpointExplorer>,
}

#[tonic::async_trait]
impl Forge for Api {
    async fn version(
        &self,
        request: tonic::Request<rpc::VersionRequest>,
    ) -> Result<Response<rpc::BuildInfo>, Status> {
        log_request_data(&request);
        let version_request = request.into_inner();

        let v = rpc::BuildInfo {
            build_version: forge_version::v!(build_version).to_string(),
            build_date: forge_version::v!(build_date).to_string(),
            git_sha: forge_version::v!(git_sha).to_string(),
            rust_version: forge_version::v!(rust_version).to_string(),
            build_user: forge_version::v!(build_user).to_string(),
            build_hostname: forge_version::v!(build_hostname).to_string(),

            runtime_config: if version_request.display_config {
                Some((*self.runtime_config).clone().into())
            } else {
                None
            },
        };
        Ok(Response::new(v))
    }

    async fn create_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        crate::handlers::domain::create(self, request).await
    }

    async fn update_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        crate::handlers::domain::update(self, request).await
    }

    async fn delete_domain(
        &self,
        request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        crate::handlers::domain::delete(self, request).await
    }

    async fn find_domain(
        &self,
        request: Request<rpc::DomainSearchQuery>,
    ) -> Result<Response<rpc::DomainList>, Status> {
        crate::handlers::domain::find(self, request).await
    }

    async fn create_vpc(
        &self,
        request: Request<rpc::VpcCreationRequest>,
    ) -> Result<Response<rpc::Vpc>, Status> {
        crate::handlers::vpc::create(self, request).await
    }

    async fn update_vpc(
        &self,
        request: Request<rpc::VpcUpdateRequest>,
    ) -> Result<Response<rpc::VpcUpdateResult>, Status> {
        crate::handlers::vpc::update(self, request).await
    }

    async fn update_vpc_virtualization(
        &self,
        request: Request<rpc::VpcUpdateVirtualizationRequest>,
    ) -> Result<Response<rpc::VpcUpdateVirtualizationResult>, Status> {
        crate::handlers::vpc::update_virtualization(self, request).await
    }

    async fn delete_vpc(
        &self,
        request: Request<rpc::VpcDeletionRequest>,
    ) -> Result<Response<rpc::VpcDeletionResult>, Status> {
        crate::handlers::vpc::delete(self, request).await
    }

    async fn find_vpc_ids(
        &self,
        request: Request<rpc::VpcSearchFilter>,
    ) -> Result<Response<rpc::VpcIdList>, Status> {
        crate::handlers::vpc::find_ids(self, request).await
    }

    async fn find_vpcs_by_ids(
        &self,
        request: Request<rpc::VpcsByIdsRequest>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        crate::handlers::vpc::find_by_ids(self, request).await
    }

    // DEPRECATED: use find_vpc_ids and find_vpcs_by_ids instead
    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        crate::handlers::vpc::find(self, request).await
    }

    async fn create_vpc_prefix(
        &self,
        request: Request<rpc::VpcPrefixCreationRequest>,
    ) -> Result<Response<rpc::VpcPrefix>, Status> {
        crate::handlers::vpc_prefix::create(self, request).await
    }

    async fn search_vpc_prefixes(
        &self,
        request: Request<rpc::VpcPrefixSearchQuery>,
    ) -> Result<Response<rpc::VpcPrefixIdList>, Status> {
        crate::handlers::vpc_prefix::search(self, request).await
    }

    async fn get_vpc_prefixes(
        &self,
        request: Request<rpc::VpcPrefixGetRequest>,
    ) -> Result<Response<rpc::VpcPrefixList>, Status> {
        crate::handlers::vpc_prefix::get(self, request).await
    }

    async fn update_vpc_prefix(
        &self,
        request: Request<rpc::VpcPrefixUpdateRequest>,
    ) -> Result<Response<rpc::VpcPrefix>, Status> {
        crate::handlers::vpc_prefix::update(self, request).await
    }
    async fn delete_vpc_prefix(
        &self,
        request: Request<rpc::VpcPrefixDeletionRequest>,
    ) -> Result<Response<rpc::VpcPrefixDeletionResult>, Status> {
        crate::handlers::vpc_prefix::delete(self, request).await
    }

    async fn find_ib_partition_ids(
        &self,
        request: Request<rpc::IbPartitionSearchFilter>,
    ) -> Result<Response<rpc::IbPartitionIdList>, Status> {
        crate::handlers::ib_partition::find_ids(self, request).await
    }

    async fn find_ib_partitions_by_ids(
        &self,
        request: Request<rpc::IbPartitionsByIdsRequest>,
    ) -> Result<Response<rpc::IbPartitionList>, Status> {
        crate::handlers::ib_partition::find_by_ids(self, request).await
    }

    // DEPRECATED: use find_ib_partition_ids and find_ib_partitions_by_ids instead
    async fn find_ib_partitions(
        &self,
        request: Request<rpc::IbPartitionQuery>,
    ) -> Result<Response<rpc::IbPartitionList>, Status> {
        crate::handlers::ib_partition::find(self, request).await
    }

    async fn create_ib_partition(
        &self,
        request: Request<rpc::IbPartitionCreationRequest>,
    ) -> Result<Response<rpc::IbPartition>, Status> {
        crate::handlers::ib_partition::create(self, request).await
    }

    async fn delete_ib_partition(
        &self,
        request: Request<rpc::IbPartitionDeletionRequest>,
    ) -> Result<Response<rpc::IbPartitionDeletionResult>, Status> {
        crate::handlers::ib_partition::delete(self, request).await
    }

    async fn ib_partitions_for_tenant(
        &self,
        request: Request<rpc::TenantSearchQuery>,
    ) -> Result<Response<rpc::IbPartitionList>, Status> {
        crate::handlers::ib_partition::for_tenant(self, request).await
    }

    async fn find_network_segment_ids(
        &self,
        request: Request<rpc::NetworkSegmentSearchFilter>,
    ) -> Result<Response<rpc::NetworkSegmentIdList>, Status> {
        crate::handlers::network_segment::find_ids(self, request).await
    }

    async fn find_network_segments_by_ids(
        &self,
        request: Request<rpc::NetworkSegmentsByIdsRequest>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::find_by_ids(self, request).await
    }

    // DEPRECATED: use find_network_segment_ids and find_network_segments_by_ids instead
    async fn find_network_segments(
        &self,
        request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::find(self, request).await
    }

    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentCreationRequest>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        crate::handlers::network_segment::create(self, request).await
    }

    async fn delete_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentDeletionRequest>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        crate::handlers::network_segment::delete(self, request).await
    }

    async fn network_segments_for_vpc(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::for_vpc(self, request).await
    }

    async fn allocate_instance(
        &self,
        request: Request<rpc::InstanceAllocationRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        crate::handlers::instance::allocate(self, request).await
    }

    async fn find_instance_ids(
        &self,
        request: Request<rpc::InstanceSearchFilter>,
    ) -> Result<Response<rpc::InstanceIdList>, Status> {
        crate::handlers::instance::find_ids(self, request).await
    }

    async fn find_instances_by_ids(
        &self,
        request: Request<rpc::InstancesByIdsRequest>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        crate::handlers::instance::find_by_ids(self, request).await
    }

    // DEPRECATED: use find_instance_ids and find_instances_by_ids instead
    async fn find_instances(
        &self,
        request: Request<rpc::InstanceSearchQuery>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        crate::handlers::instance::find(self, request).await
    }

    async fn find_instance_by_machine_id(
        &self,
        request: Request<::rpc::common::MachineId>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        crate::handlers::instance::find_by_machine_id(self, request).await
    }

    async fn release_instance(
        &self,
        request: Request<rpc::InstanceReleaseRequest>,
    ) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
        crate::handlers::instance::release(self, request).await
    }

    async fn record_observed_instance_network_status(
        &self,
        request: Request<rpc::InstanceNetworkStatusObservation>,
    ) -> Result<Response<rpc::ObservedInstanceNetworkStatusRecordResult>, tonic::Status> {
        crate::handlers::instance::record_observed_network_status(self, request).await
    }

    async fn update_instance_phone_home_last_contact(
        &self,
        request: Request<InstancePhoneHomeLastContactRequest>,
    ) -> Result<Response<InstancePhoneHomeLastContactResponse>, Status> {
        crate::handlers::instance::update_phone_home_last_contact(self, request).await
    }

    async fn update_instance_operating_system(
        &self,
        request: tonic::Request<rpc::InstanceOperatingSystemUpdateRequest>,
    ) -> Result<tonic::Response<rpc::Instance>, Status> {
        crate::handlers::instance::update_operating_system(self, request).await
    }

    async fn update_instance_config(
        &self,
        request: tonic::Request<rpc::InstanceConfigUpdateRequest>,
    ) -> Result<tonic::Response<rpc::Instance>, Status> {
        crate::handlers::instance::update_instance_config(self, request).await
    }

    async fn get_managed_host_network_config(
        &self,
        request: Request<rpc::ManagedHostNetworkConfigRequest>,
    ) -> Result<tonic::Response<rpc::ManagedHostNetworkConfigResponse>, tonic::Status> {
        crate::handlers::dpu::get_managed_host_network_config(self, request).await
    }

    async fn update_agent_reported_inventory(
        &self,
        request: Request<rpc::DpuAgentInventoryReport>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::dpu::update_agent_reported_inventory(self, request).await
    }

    async fn record_dpu_network_status(
        &self,
        request: Request<rpc::DpuNetworkStatus>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::dpu::record_dpu_network_status(self, request).await
    }

    async fn record_hardware_health_report(
        &self,
        request: Request<rpc::HardwareHealthReport>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::health::record_hardware_health_report(self, request).await
    }

    async fn get_hardware_health_report(
        &self,
        request: Request<::rpc::common::MachineId>,
    ) -> Result<Response<rpc::OptionalHealthReport>, tonic::Status> {
        crate::handlers::health::get_hardware_health_report(self, request).await
    }

    async fn list_health_report_overrides(
        &self,
        request: Request<::rpc::common::MachineId>,
    ) -> Result<Response<rpc::ListHealthReportOverrideResponse>, tonic::Status> {
        crate::handlers::health::list_health_report_overrides(self, request).await
    }

    async fn insert_health_report_override(
        &self,
        request: Request<rpc::InsertHealthReportOverrideRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::health::insert_health_report_override(self, request).await
    }

    async fn remove_health_report_override(
        &self,
        request: Request<rpc::RemoveHealthReportOverrideRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::health::remove_health_report_override(self, request).await
    }

    async fn lookup_record(
        &self,
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        crate::handlers::dns::lookup_record(self, request).await
    }

    async fn invoke_instance_power(
        &self,
        request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        crate::handlers::instance::invoke_power(self, request).await
    }

    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        log_request_data(&request);

        let reply = EchoResponse {
            message: request.into_inner().message,
        };

        Ok(Response::new(reply))
    }

    async fn create_tenant(
        &self,
        request: Request<rpc::CreateTenantRequest>,
    ) -> Result<Response<rpc::CreateTenantResponse>, Status> {
        crate::handlers::tenant::create(self, request).await
    }

    async fn find_tenant(
        &self,
        request: Request<rpc::FindTenantRequest>,
    ) -> Result<Response<rpc::FindTenantResponse>, Status> {
        crate::handlers::tenant::find(self, request).await
    }

    async fn update_tenant(
        &self,
        request: Request<rpc::UpdateTenantRequest>,
    ) -> Result<Response<rpc::UpdateTenantResponse>, Status> {
        crate::handlers::tenant::update(self, request).await
    }

    async fn create_tenant_keyset(
        &self,
        request: Request<rpc::CreateTenantKeysetRequest>,
    ) -> Result<Response<rpc::CreateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::create(self, request).await
    }

    async fn find_tenant_keyset_ids(
        &self,
        request: Request<rpc::TenantKeysetSearchFilter>,
    ) -> Result<Response<rpc::TenantKeysetIdList>, Status> {
        crate::handlers::tenant_keyset::find_ids(self, request).await
    }

    async fn find_tenant_keysets_by_ids(
        &self,
        request: Request<rpc::TenantKeysetsByIdsRequest>,
    ) -> Result<Response<rpc::TenantKeySetList>, Status> {
        crate::handlers::tenant_keyset::find_by_ids(self, request).await
    }

    // DEPRECATED: use find_tenant_keyset_ids and find_tenant_keysets_by_ids instead
    async fn find_tenant_keyset(
        &self,
        request: Request<rpc::FindTenantKeysetRequest>,
    ) -> Result<Response<rpc::TenantKeySetList>, Status> {
        crate::handlers::tenant_keyset::find(self, request).await
    }

    async fn update_tenant_keyset(
        &self,
        request: Request<rpc::UpdateTenantKeysetRequest>,
    ) -> Result<Response<rpc::UpdateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::update(self, request).await
    }

    async fn delete_tenant_keyset(
        &self,
        request: Request<rpc::DeleteTenantKeysetRequest>,
    ) -> Result<Response<rpc::DeleteTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::delete(self, request).await
    }

    async fn validate_tenant_public_key(
        &self,
        request: Request<rpc::ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<rpc::ValidateTenantPublicKeyResponse>, Status> {
        crate::handlers::tenant_keyset::validate_public_key(self, request).await
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
        let remote_ip: Option<IpAddr> = match request.metadata().get("X-Forwarded-For") {
            None => {
                // Normal production case.
                // This is set in api/src/listener.rs::listen_and_serve when we `accept` the connection
                // The IP is usually an IPv4-mapped IPv6 addresses (e.g. `::ffff:10.217.133.10`) so
                // we use to_canonical() to convert it to IPv4.
                request
                    .extensions()
                    .get::<Arc<crate::listener::ConnectionAttributes>>()
                    .map(|conn_attrs| conn_attrs.peer_address().ip().to_canonical())
            }
            Some(ip_str) => {
                // Development case, we override the remote IP with HTTP header
                ip_str
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse().map(|ip: IpAddr| ip.to_canonical()).ok())
            }
        };

        let machine_discovery_info = request.into_inner();

        let interface_id = machine_discovery_info
            .machine_interface_id
            .and_then(|id| MachineInterfaceId::try_from(id).ok());

        let discovery_data = machine_discovery_info
            .discovery_data
            .map(|data| match data {
                rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
            })
            .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;
        let attest_key_info_opt = discovery_data.attest_key_info.clone();
        let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

        // this is an early check for certificate creation that happens later on in this method.
        // let's save us the hassle and return immediately if the below condition is not satisfied
        if self.runtime_config.attestation_enabled
            && !hardware_info.is_dpu()
            && attest_key_info_opt.is_none()
        {
            return Err(Status::invalid_argument("AttestKeyInfo is not populated"));
        }

        // Generate a stable Machine ID based on the hardware information
        let stable_machine_id = from_hardware_info(&hardware_info).map_err(|e| {
            CarbideError::InvalidArgument(
                format!("Insufficient HardwareInfo to derive a Stable Machine ID for Machine on InterfaceId {:?}: {e}", interface_id),
            )
        })?;
        log_machine_id(&stable_machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin discover_machine",
                e,
            ))
        })?;

        tracing::debug!(
            ?remote_ip,
            ?interface_id,
            "discover_machine loading interface"
        );

        if !hardware_info.is_dpu() && hardware_info.tpm_ek_certificate.is_none() {
            return Err(CarbideError::InvalidArgument(format!(
                "Ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {:?}",
                interface_id
            ))
            .into());
        } else if !hardware_info.is_dpu() {
            // this means we do have an EK cert for a host

            // get the EK cert from incoming message
            let tpm_ek_cert =
                hardware_info
                    .tpm_ek_certificate
                    .as_ref()
                    .ok_or(CarbideError::InvalidArgument(
                        "tpm_ek_cert is empty".to_string(),
                    ))?;

            attest::match_insert_new_ek_cert_status_against_ca(
                &mut txn,
                tpm_ek_cert,
                &stable_machine_id,
            )
            .await?;
        }

        let interface =
            db::machine_interface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
        let machine = if hardware_info.is_dpu() {
            // if site explorer is creating machine records and there isn't one for this machine return an error
            if **self.runtime_config.site_explorer.create_machines.load() {
                Machine::find_one(
                    &mut txn,
                    &stable_machine_id,
                    MachineSearchConfig {
                        include_dpus: true,
                        ..MachineSearchConfig::default()
                    },
                )
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    Status::invalid_argument(format!(
                        "Machine id {stable_machine_id} was not discovered by site-explorer."
                    ))
                })?;
            }

            let db_machine = if machine_discovery_info.create_machine {
                Machine::get_or_create(&mut txn, &stable_machine_id, &interface).await?
            } else {
                Machine::find_one(
                    &mut txn,
                    &stable_machine_id,
                    MachineSearchConfig {
                        include_dpus: true,
                        ..MachineSearchConfig::default()
                    },
                )
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    Status::invalid_argument(format!("Machine id {stable_machine_id} not found."))
                })?
            };

            db::machine_interface::associate_interface_with_dpu_machine(
                &interface.id,
                &stable_machine_id,
                &mut txn,
            )
            .await
            .map_err(CarbideError::from)?;

            let (network_config, _version) = db_machine.network_config().clone().take();
            if network_config.loopback_ip.is_none() {
                let loopback_ip = Machine::allocate_loopback_ip(
                    &self.common_pools,
                    &mut txn,
                    &stable_machine_id.to_string(),
                )
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
            // Create Host proactively.
            // In case host interface is created, this method will return existing one, instead
            // creating new everytime.
            let machine_interface =
                db::machine_interface::create_host_machine_dpu_interface_proactively(
                    &mut txn,
                    Some(&hardware_info),
                    machine.id(),
                )
                .await?;

            // Create host machine with temporary ID if no machine is attached.
            if machine_interface.machine_id.is_none() {
                let predicted_machine_id =
                    host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                        CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                    })?;
                let mi_id = machine_interface.id;
                let proactive_machine =
                    Machine::get_or_create(&mut txn, &predicted_machine_id, &machine_interface)
                        .await?;

                // Update host and DPUs state correctly.
                Machine::update_state(
                    &mut txn,
                    &predicted_machine_id,
                    ManagedHostState::DPUInit {
                        dpu_states: DpuInitStates {
                            states: HashMap::from([(machine.id().clone(), DpuInitState::Init)]),
                        },
                    },
                )
                .await
                .map_err(CarbideError::from)?;

                tracing::info!(
                    ?mi_id,
                    machine_id = %proactive_machine.id(),
                    "Created host machine proactively",
                );
            }
        }

        let id_str = stable_machine_id.to_string();

        // if attestation is enabled and it is not a DPU, then we create a random nonce (auth token)
        // and create a decrypting challenge (make credential) out of it.
        // Whoever was able to decrypt it (activate credential), possesses
        // the TPM that the endorsement key (EK) and the attestation key (AK) that they came from.
        // if attestation is not enabled, or it is a DPU, then issue machine certificates immediately
        let mut attest_key_bind_challenge_opt: Option<rpc::AttestKeyBindChallenge> = None;
        let mut machine_certificate_opt: Option<rpc::MachineCertificate> = None;

        if self.runtime_config.attestation_enabled && !hardware_info.is_dpu() {
            if let Some(attest_key_info) = attest_key_info_opt {
                tracing::info!("It is not a DPU and attestation is enabled. Generating Attest Key Bind Challenge ...");

                attest_key_bind_challenge_opt = Some(
                    crate::handlers::measured_boot::create_attest_key_bind_challenge(
                        &mut txn,
                        &attest_key_info,
                        &stable_machine_id,
                    )
                    .await?,
                );
            } else {
                return Err(Status::invalid_argument("Internal Error: This should have been handled above! AttestKeyInfo is not populated."));
            }
        } else {
            tracing::info!(
                "Attestation enabled is {}. Is_DPU is {}. Vending certs to machine with id {}",
                self.runtime_config.attestation_enabled,
                hardware_info.is_dpu(),
                id_str
            );

            let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
                forge_secrets::certificates::Certificate::default()
            } else {
                self.certificate_provider
                    .get_certificate(id_str.as_str())
                    .await
                    .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
            };
            machine_certificate_opt = Some(certificate.into())
        }

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: Some(id_str.into()),
            machine_certificate: machine_certificate_opt,
            attest_key_challenge: attest_key_bind_challenge_opt,
        }));

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit discover_machine",
                e,
            ))
        })?;

        if hardware_info.is_dpu() {
            // WARNING: DONOT REUSE OLD TXN HERE. IT WILL CREATE DEADLOCK.
            //
            // Create a new transaction here for network devices. Inner transaction is not so
            // helpful in postgres and using same transaction creates deadlock with
            // machine_interface table.
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin discover_machine",
                    e,
                ))
            })?;
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
            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit new txn discover_machine",
                    e,
                ))
            })?;
        }

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

        let discovery_result = "Success".to_owned();

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit discovery_completed",
                e,
            ))
        })?;

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
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit cleanup_machine_completed",
                e,
            ))
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

        Ok(crate::dhcp::discover::discover_dhcp(
            &self.database_connection,
            request,
            &self.runtime_config.host_health,
        )
        .await?)
    }

    async fn get_machine(
        &self,
        request: Request<::rpc::common::MachineId>,
    ) -> Result<Response<rpc::Machine>, Status> {
        log_request_data(&request);

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;
        log_machine_id(&machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "begin get_machine", e))
        })?;
        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            LoadSnapshotOptions {
                include_history: true,
                include_instance_data: false,
                hardware_health: self.runtime_config.host_health.hardware_health_reports,
            },
        )
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "end get_machine", e))
        })?;

        let rpc_machine = snapshot
            .rpc_machine_state(match machine_id.machine_type().is_dpu() {
                true => Some(&machine_id),
                false => None,
            })
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;
        Ok(Response::new(rpc_machine))
    }

    async fn find_machine_ids(
        &self,
        request: Request<rpc::MachineSearchConfig>,
    ) -> Result<Response<::rpc::common::MachineIdList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines",
                e,
            ))
        })?;

        let search_config = request.into_inner().into();

        let machine_ids = Machine::find_machine_ids(&mut txn, search_config)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(::rpc::common::MachineIdList {
            machine_ids: machine_ids.into_iter().map(|id| id.into()).collect(),
        }))
    }

    async fn find_machines_by_ids(
        &self,
        request: Request<::rpc::forge::MachinesByIdsRequest>,
    ) -> Result<Response<::rpc::MachineList>, Status> {
        log_request_data(&request);
        let request = request.into_inner();
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines_by_ids",
                e,
            ))
        })?;

        let machine_ids: Result<Vec<MachineId>, CarbideError> = request
            .machine_ids
            .iter()
            .map(|id| {
                MachineId::from_str(&id.id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(id.id.clone()))
                })
            })
            .collect();

        let machine_ids = machine_ids?;

        let max_find_by_ids = self.runtime_config.max_find_by_ids as usize;
        if machine_ids.len() > max_find_by_ids {
            return Err(CarbideError::InvalidArgument(format!(
                "no more than {max_find_by_ids} IDs can be accepted"
            ))
            .into());
        } else if machine_ids.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "at least one ID must be provided".to_string(),
            )
            .into());
        }

        let snapshots = db::managed_host::load_by_machine_ids(
            &mut txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: request.include_history,
                include_instance_data: false,
                hardware_health: self.runtime_config.host_health.hardware_health_reports,
            },
        )
        .await
        .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end find_machines_by_ids",
                e,
            ))
        })?;

        Ok(tonic::Response::new(snapshot_map_to_rpc_machines(
            snapshots,
        )))
    }

    async fn find_tenant_organization_ids(
        &self,
        request: Request<rpc::TenantSearchFilter>,
    ) -> Result<Response<rpc::TenantOrganizationIdList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_tenant_ids",
                e,
            ))
        })?;

        let search_config = request.into_inner();

        let tenant_org_ids = Tenant::find_tenant_organization_ids(&mut txn, search_config)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::TenantOrganizationIdList {
            tenant_organization_ids: tenant_org_ids.into_iter().collect(),
        }))
    }

    async fn find_tenants_by_organization_ids(
        &self,
        request: Request<rpc::TenantByOrganizationIdsRequest>,
    ) -> Result<Response<rpc::TenantList>, Status> {
        log_request_data(&request);
        let request = request.into_inner();
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_tenants_by_organization_ids",
                e,
            ))
        })?;

        let tenant_organization_ids: Vec<String> = request.organization_ids;

        let max_find_by_ids = self.runtime_config.max_find_by_ids as usize;
        if tenant_organization_ids.len() > max_find_by_ids {
            return Err(CarbideError::InvalidArgument(format!(
                "no more than {max_find_by_ids} IDs can be accepted"
            ))
            .into());
        } else if tenant_organization_ids.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "at least one ID must be provided".to_string(),
            )
            .into());
        }

        let tenants: Vec<rpc::Tenant> =
            db::tenant::load_by_organization_ids(&mut txn, &tenant_organization_ids)
                .await
                .map_err(CarbideError::from)?
                .into_iter()
                .filter_map(|tenant| rpc::Tenant::try_from(tenant).ok())
                .collect();

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end find_tenants_by_organization_ids",
                e,
            ))
        })?;

        Ok(tonic::Response::new(rpc::TenantList { tenants }))
    }

    // DEPRECATED: use find_machine_ids and find_machines_by_ids instead
    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        log_request_data(&request);
        let request = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines",
                e,
            ))
        })?;

        let search_config = request
            .search_config
            .map(MachineSearchConfig::from)
            .unwrap_or_default();

        let machine_ids: Vec<MachineId> = match (request.id, request.fqdn) {
            (Some(id), _) => {
                let machine_id = try_parse_machine_id(&id).map_err(CarbideError::from)?;
                log_machine_id(&machine_id);
                vec![machine_id]
            }
            (None, Some(fqdn)) => {
                match Machine::find_id_by_fqdn(&mut txn, &fqdn)
                    .await
                    .map_err(CarbideError::from)?
                {
                    Some(id) => vec![id],
                    None => vec![],
                }
            }
            (None, None) => Machine::find_machine_ids(&mut txn, search_config)
                .await
                .map_err(CarbideError::from)?,
        };

        let snapshots = db::managed_host::load_by_machine_ids(
            &mut txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: search_config.include_history,
                include_instance_data: false,
                hardware_health: self.runtime_config.host_health.hardware_health_reports,
            },
        )
        .await
        .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "end find_machines", e))
        })?;

        Ok(Response::new(snapshot_map_to_rpc_machines(snapshots)))
    }

    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_interfaces",
                e,
            ))
        })?;

        let rpc::InterfaceSearchQuery { id, ip } = request.into_inner();

        let mut interfaces: Vec<rpc::MachineInterface> = match (id, ip) {
            (Some(id), _) if id.value.chars().count() > 0 => match MachineInterfaceId::try_from(id)
            {
                Ok(uuid) => vec![db::machine_interface::find_one(&mut txn, uuid)
                    .await?
                    .into()],
                Err(_) => {
                    return Err(CarbideError::internal(
                        "Could not marshall an ID from the request".to_string(),
                    )
                    .into());
                }
            },
            (None, Some(ip)) => match Ipv4Addr::from_str(ip.as_ref()) {
                Ok(ip) => {
                    match db::machine_interface::find_by_ip(&mut txn, IpAddr::V4(ip))
                        .await
                        .map_err(CarbideError::from)?
                    {
                        Some(interface) => vec![interface.into()],
                        None => {
                            return Err(CarbideError::internal(format!(
                                "No machine interface with IP {ip} was found"
                            ))
                            .into());
                        }
                    }
                }
                Err(_) => {
                    return Err(CarbideError::internal(
                        "Could not marshall an IP from the request".to_string(),
                    )
                    .into());
                }
            },
            (None, None) => {
                match db::machine_interface::find_all(&mut txn)
                    .await
                    .map_err(CarbideError::from)
                {
                    Ok(machine_interfaces) => machine_interfaces
                        .into_iter()
                        .map(|i| i.into())
                        .collect_vec(),
                    Err(error) => return Err(error.into()),
                }
            }
            _ => {
                return Err(CarbideError::internal(
                    "Could not find an ID or IP in the request".to_string(),
                )
                .into());
            }
        };

        // Link BMC interface to its machine, for carbide-web and admin-cli.
        // Don't link if the search returned multiple, in case perf is an issue.
        if interfaces.len() == 1 {
            let interface = interfaces.get_mut(0).unwrap();
            let not_linked_yet = interface.machine_id.is_none();
            let maybe_a_bmc_interface = interface.primary_interface && interface.address.len() == 1;
            if not_linked_yet && maybe_a_bmc_interface {
                let Some(ip) = interface.address.first() else {
                    return Err(Status::internal(
                        "Impossible interface.address array length",
                    ));
                };
                match MachineTopology::find_machine_id_by_bmc_ip(&mut txn, ip).await {
                    Ok(Some(machine_id)) => {
                        let rpc_machine_id = Some(machine_id.clone().into());
                        interface.is_bmc = Some(true);
                        match machine_id.machine_type() {
                            MachineType::Dpu => interface.attached_dpu_machine_id = rpc_machine_id,
                            MachineType::Host | MachineType::PredictedHost => {
                                interface.machine_id = rpc_machine_id
                            }
                        }
                    }
                    Ok(None) => {} // expected, not a BMC interface
                    Err(err) => {
                        tracing::warn!(%err, %ip, "MachineTopology::find_machine_id_by_bmc_ip error");
                    }
                }
            }
        }

        Ok(Response::new(rpc::InterfaceList { interfaces }))
    }

    async fn delete_interface(
        &self,
        request: Request<rpc::InterfaceDeleteQuery>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_interfaces",
                e,
            ))
        })?;

        let rpc::InterfaceDeleteQuery { id } = request.into_inner();
        let Some(id) = id else {
            return Err(CarbideError::MissingArgument("delete interface.interface_id").into());
        };

        let interface = match MachineInterfaceId::try_from(id) {
            Ok(uuid) => db::machine_interface::find_one(&mut txn, uuid).await?,
            Err(_) => {
                return Err(CarbideError::internal(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into())
            }
        };

        // There should not be any machine associated with this interface.
        if let Some(machine_id) = interface.machine_id {
            return Err(Status::invalid_argument(format!(
                "Already a machine {machine_id} is attached to this interface. Delete that first."
            )));
        }

        // There should not be any BMC information associated with any machine.
        for address in interface.addresses.iter() {
            let machine_id =
                MachineTopology::find_machine_id_by_bmc_ip(&mut txn, &address.to_string())
                    .await
                    .map_err(CarbideError::from)?;

            if let Some(machine_id) = machine_id {
                return Err(Status::invalid_argument(
                    format!("This looks like a BMC interface and attached with machine: {machine_id}. Delete that first."),
                ));
            }
        }

        db::machine_interface::delete(&interface.id, &mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit delete interface",
                e,
            ))
        })?;

        Ok(Response::new(()))
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
        crate::handlers::credential::get_dpu_ssh_credential(self, request).await
    }

    /// Network status of each managed host, as reported by forge-dpu-agent.
    /// For use by forge-admin-cli
    ///
    /// Currently: Status of HBN on each DPU
    async fn get_all_managed_host_network_status(
        &self,
        request: Request<rpc::ManagedHostNetworkStatusRequest>,
    ) -> Result<Response<rpc::ManagedHostNetworkStatusResponse>, Status> {
        crate::handlers::dpu::get_all_managed_host_network_status(self, request).await
    }

    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataGetRequest>,
    ) -> Result<Response<rpc::BmcMetaDataGetResponse>, Status> {
        crate::handlers::bmc_metadata::get(self, request).await
    }

    // TODO(spyda): do we ever use this?
    async fn update_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataUpdateRequest>,
    ) -> Result<Response<rpc::BmcMetaDataUpdateResponse>, Status> {
        crate::handlers::bmc_metadata::update(self, request).await
    }

    async fn update_machine_credentials(
        &self,
        request: Request<MachineCredentialsUpdateRequest>,
    ) -> Result<Response<MachineCredentialsUpdateResponse>, Status> {
        crate::handlers::credential::update_machine_credentials(self, request).await
    }

    // The carbide pxe server makes this RPC call
    async fn get_pxe_instructions(
        &self,
        request: Request<rpc::PxeInstructionRequest>,
    ) -> Result<Response<rpc::PxeInstructions>, Status> {
        crate::handlers::pxe::get_pxe_instructions(self, request).await
    }

    async fn get_cloud_init_instructions(
        &self,
        request: Request<rpc::CloudInitInstructionsRequest>,
    ) -> Result<Response<rpc::CloudInitInstructions>, Status> {
        crate::handlers::pxe::get_cloud_init_instructions(self, request).await
    }

    async fn clear_site_exploration_error(
        &self,
        request: Request<rpc::ClearSiteExplorationErrorRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::site_explorer::clear_site_exploration_error(self, request).await
    }

    async fn is_bmc_in_managed_host(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<rpc::IsBmcInManagedHostResponse>, tonic::Status> {
        crate::handlers::site_explorer::is_bmc_in_managed_host(self, request).await
    }

    async fn bmc_credential_status(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<rpc::BmcCredentialStatusResponse>, tonic::Status> {
        crate::handlers::bmc_endpoint_explorer::bmc_credential_status(self, request).await
    }

    async fn re_explore_endpoint(
        &self,
        request: Request<rpc::ReExploreEndpointRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::site_explorer::re_explore_endpoint(self, request).await
    }

    // DEPRECATED: use find_explored_endpoint_ids, find_explored_endpoints_by_ids and find_explored_managed_host_ids, find_explored_managed_hosts_by_ids instead
    async fn get_site_exploration_report(
        &self,
        request: tonic::Request<::rpc::forge::GetSiteExplorationRequest>,
    ) -> Result<Response<::rpc::site_explorer::SiteExplorationReport>, Status> {
        crate::handlers::site_explorer::get_site_exploration_report(self, request).await
    }

    async fn find_explored_endpoint_ids(
        &self,
        request: Request<::rpc::site_explorer::ExploredEndpointSearchFilter>,
    ) -> Result<Response<::rpc::site_explorer::ExploredEndpointIdList>, Status> {
        crate::handlers::site_explorer::find_explored_endpoint_ids(self, request).await
    }

    async fn find_explored_endpoints_by_ids(
        &self,
        request: Request<::rpc::site_explorer::ExploredEndpointsByIdsRequest>,
    ) -> Result<Response<::rpc::site_explorer::ExploredEndpointList>, Status> {
        crate::handlers::site_explorer::find_explored_endpoints_by_ids(self, request).await
    }

    async fn find_explored_managed_host_ids(
        &self,
        request: Request<::rpc::site_explorer::ExploredManagedHostSearchFilter>,
    ) -> Result<Response<::rpc::site_explorer::ExploredManagedHostIdList>, Status> {
        crate::handlers::site_explorer::find_explored_managed_host_ids(self, request).await
    }

    async fn find_explored_managed_hosts_by_ids(
        &self,
        request: Request<::rpc::site_explorer::ExploredManagedHostsByIdsRequest>,
    ) -> Result<Response<::rpc::site_explorer::ExploredManagedHostList>, Status> {
        crate::handlers::site_explorer::find_explored_managed_hosts_by_ids(self, request).await
    }

    // Ad-hoc BMC exploration
    async fn explore(
        &self,
        request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
    ) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
        crate::handlers::bmc_endpoint_explorer::explore(self, request).await
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

        let is_dpu = machine.is_dpu();
        let host_machine = if !is_dpu {
            machine.clone()
        } else {
            Machine::find_host_by_dpu_machine_id(&mut txn, &machine_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?
        };

        // Respond based on machine current state
        let state = host_machine.current_state();
        let (action, action_data) = if is_dpu {
            get_action_for_dpu_state(&state, &machine_id)?
        } else {
            match state {
                ManagedHostState::HostInit {
                    machine_state: MachineState::Init,
                } => (Action::Retry, None),
                ManagedHostState::HostInit {
                    machine_state:
                        MachineState::MachineValidating {
                            context,
                            id,
                            completed,
                            total,
                            is_enabled,
                        },
                } => {
                    tracing::info!(
                        " context : {} id: {} is_enabled: {}, completed {}, total {}",
                        context,
                        id,
                        is_enabled,
                        completed,
                        total,
                    );
                    if is_enabled {
                        MachineValidation::update_status(
                            &mut txn,
                            &id,
                            MachineValidationStatus {
                                state: MachineValidationState::InProgress,
                                ..MachineValidationStatus::default()
                            },
                        )
                        .await?;
                        let machine_validation =
                            MachineValidation::find_by_id(&mut txn, &id).await?;
                        (
                            Action::MachineValidation,
                            Some(
                                rpc::forge_agent_control_response::ForgeAgentControlExtraInfo {
                                    pair: [
                                        KeyValuePair {
                                            key: "Context".to_string(),
                                            value: context,
                                        },
                                        KeyValuePair {
                                            key: "ValidationId".to_string(),
                                            value: id.to_string(),
                                        },
                                        KeyValuePair {
                                            key: "IsEnabled".to_string(),
                                            value: is_enabled.to_string(),
                                        },
                                        KeyValuePair {
                                            key: "MachineValidationFilter".to_string(),
                                            value: serde_json::to_string(
                                                &machine_validation.filter,
                                            )
                                            .map_err(CarbideError::from)?,
                                        },
                                    ]
                                    .to_vec(),
                                },
                            ),
                        )
                    } else {
                        // This avoids sending Machine validation command scout
                        tracing::info!("Skipped machine validation",);
                        (Action::Noop, None)
                    }
                }
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForDiscovery,
                }
                | ManagedHostState::Failed {
                    details:
                        FailureDetails {
                            cause: FailureCause::Discovery { .. },
                            ..
                        },
                    ..
                } => (Action::Discovery, None),
                ManagedHostState::WaitingForCleanup { .. }
                | ManagedHostState::Failed {
                    details:
                        FailureDetails {
                            cause: FailureCause::NVMECleanFailed { .. },
                            ..
                        },
                    ..
                } => (Action::Reset, None),
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    tracing::info!(
                        machine_id = %machine.id(),
                        machine_type = "Host",
                        %state,
                        "forge agent control",
                    );
                    (Action::Noop, None)
                }
            }
        };
        tracing::info!(
            machine_id = %machine.id(),
            action = action.as_str_name(),
            "forge agent control",
        );
        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit forge_agent_control",
                e,
            ))
        })?;
        Ok(Response::new(rpc::ForgeAgentControlResponse {
            action: action as i32,
            data: action_data,
        }))
    }

    async fn admin_force_delete_machine(
        &self,
        request: Request<rpc::AdminForceDeleteMachineRequest>,
    ) -> Result<Response<rpc::AdminForceDeleteMachineResponse>, Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let query = request.host_query;

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
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin investigate admin_force_delete_machine",
                e,
            ))
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
        let dpu_machines;
        if machine.is_dpu() {
            if let Some(host) = Machine::find_host_by_dpu_machine_id(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?
            {
                tracing::info!("Found host Machine {:?}", machine.id().to_string());
                // Get all DPUs attached to this host, in case there are more than one.
                dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, host.id())
                    .await
                    .map_err(CarbideError::from)?;
                host_machine = Some(host);
            } else {
                host_machine = None;
                dpu_machines = vec![machine];
            }
        } else {
            dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;
            tracing::info!(
                "Found dpu Machines {:?}",
                dpu_machines.iter().map(|m| m.id().to_string()).join(", ")
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
            if let Some(iface) = host_machine.interfaces().first() {
                response.managed_host_machine_interface_id = iface.id.to_string();
            }
            if let Some(ip) = host_machine.bmc_info().ip.as_ref() {
                response.managed_host_bmc_ip = ip.to_string();
            }
        }
        if let Some(dpu_machine) = dpu_machines.first() {
            response.dpu_machine_ids = dpu_machines.iter().map(|m| m.id().to_string()).collect();
            // deprecated field:
            response.dpu_machine_id = dpu_machine.id().to_string();

            let dpu_interfaces = dpu_machines
                .iter()
                .flat_map(|m| m.interfaces().clone())
                .collect::<Vec<_>>();
            if let Some(iface) = dpu_interfaces.first() {
                response.dpu_machine_interface_ids =
                    dpu_interfaces.iter().map(|i| i.id.to_string()).collect();
                // deprecated field:
                response.dpu_machine_interface_id = iface.id.to_string();
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
        for dpu_machine in dpu_machines.iter() {
            dpu_machine
                .advance(&mut txn, ManagedHostState::ForceDeletion, None)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit admin_force_delete_machine",
                e,
            ))
        })?;

        // We start a new transaction
        // This makeas the ForceDeletion state visible to other consumers

        // Note: The following deletion steps are all ordered in an idempotent fashion

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete host and instance in admin_force_delete_machine",
                e,
            ))
        })?;

        if let Some(instance_id) = instance_id {
            let instance = Instance::find_by_id(&mut txn, instance_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    CarbideError::internal(format!(
                        "Could not find an instance for {}",
                        instance_id
                    ))
                })?
                .to_owned();

            let ib_fabric = self
                .ib_fabric_manager
                .connect(DEFAULT_IB_FABRIC_NAME)
                .await?;

            // Collect the ib partition and ib ports information about this machine
            let mut ib_config_map: HashMap<IBPartitionId, Vec<String>> = HashMap::new();
            let infiniband = instance.config.infiniband.ib_interfaces;
            for ib in &infiniband {
                let ib_partition_id = ib.ib_partition_id;
                if let Some(guid) = ib.guid.as_deref() {
                    ib_config_map
                        .entry(ib_partition_id)
                        .or_default()
                        .push(guid.to_string());
                }
            }

            response.ufm_unregistration_pending = true;
            // unbind ib ports from UFM
            for (ib_partition_id, guids) in ib_config_map.iter() {
                if let Some(pkey) =
                    IBPartition::find_pkey_by_partition_id(&mut txn, *ib_partition_id)
                        .await
                        .map_err(CarbideError::from)?
                {
                    ib_fabric.unbind_ib_ports(pkey, guids.to_vec()).await?;
                    response.ufm_unregistrations += 1;

                    //TODO: release VF GUID resource when VF supported.
                }
            }
            response.ufm_unregistration_pending = false;

            // Delete the instance and allocated address
            // TODO: This might need some changes with the new state machine
            let delete_instance = DeleteInstance { instance_id };
            let _instance = delete_instance.delete(&mut txn).await?;

            let network_segment_ids_with_vpc = instance
                .config
                .network
                .interfaces
                .iter()
                .filter_map(|x| match x.network_details {
                    Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                    _ => None,
                })
                .collect_vec();

            // Mark all network ready for delete which were created for vpc_prefixes.
            if !network_segment_ids_with_vpc.is_empty() {
                NetworkSegment::mark_as_deleted_no_validation(
                    &mut txn,
                    &network_segment_ids_with_vpc,
                )
                .await?;
            }
        }

        if let Some(machine) = &host_machine {
            if let Some(ip) = machine.bmc_info().ip.as_deref() {
                if let Some(bmc_mac_address) = machine.bmc_info().mac {
                    tracing::info!(
                        ip,
                        machine_id = %machine.id(),
                        "BMC IP and MAC address for machine was found. Trying to perform Bios unlock",
                    );

                    match self
                        .redfish_pool
                        .create_client(
                            ip,
                            machine.bmc_info().port,
                            RedfishAuth::Key(CredentialKey::BmcCredentials {
                                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                            }),
                            true,
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

                            if machine.bios_password_set_time().is_some() {
                                if let Err(e) = crate::redfish::clear_host_uefi_password(
                                    client.as_ref(),
                                    self.redfish_pool.clone(),
                                )
                                .await
                                {
                                    tracing::warn!(%machine_id, error = %e, "Failed to clear host UEFI password while force deleting machine");
                                }

                                // TODO (spyda): have libredfish return whether the client needs to reboot the host after clearing the host uefi password
                                if machine.bmc_vendor().is_lenovo() {
                                    if let Err(e) =
                                        client.power(SystemPowerControl::ForceRestart).await
                                    {
                                        tracing::warn!(%machine_id, error = %e, "Failed to reboot host (to clear the UEFI password on a Lenovo) while force deleting machine");
                                    }
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
                } else {
                    tracing::warn!(
                        "Failed to unlock this host because Forge could not retrieve the BMC MAC address for machine {}",
                        machine.id()
                    );
                }
            } else {
                tracing::warn!(
                    "Failed to unlock this host because Forge could not retrieve the BMC IP address for machine {}",
                    machine.id()
                );
            }
        }

        if let Some(machine) = &host_machine {
            if request.delete_bmc_interfaces {
                if let Some(bmc_ip) = &machine.bmc_info().ip {
                    response.host_bmc_interface_associated = true;
                    if let Ok(ip_addr) = IpAddr::from_str(bmc_ip) {
                        if db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                            .await
                            .map_err(CarbideError::from)?
                            .is_some()
                        {
                            response.host_bmc_interface_deleted = true;
                        }
                    }
                }
            }
            Machine::force_cleanup(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;

            if request.delete_interfaces {
                for interface in machine.interfaces() {
                    db::machine_interface::delete(&interface.id, &mut txn)
                        .await
                        .map_err(CarbideError::from)?;
                }
                response.host_interfaces_deleted = true;
            }

            if let Some(addr) = &machine.bmc_info().ip {
                if let Ok(addr) = IpAddr::from_str(addr) {
                    tracing::info!("Cleaning up explored endpoint at {addr} {}", machine.id());

                    DbExploredEndpoint::delete(&mut txn, addr)
                        .await
                        .map_err(CarbideError::from)?;

                    DbExploredManagedHost::delete_by_host_bmc_addr(&mut txn, addr)
                        .await
                        .map_err(CarbideError::from)?;
                }
            }

            if request.delete_bmc_credentials {
                self.clear_bmc_credentials(machine).await?;
            }

            if let Err(e) =
                db_attest::EkCertVerificationStatus::delete_ca_verification_status_by_machine_id(
                    &mut txn,
                    machine.id(),
                )
                .await
            {
                // just log the error and carry on
                tracing::error!(
                    "Could not remove EK cert status for machine with id {}: {}",
                    machine.id(),
                    e
                );
            }
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end delete host and instance in admin_force_delete_machine",
                e,
            ))
        })?;

        for dpu_machine in dpu_machines.iter() {
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin delete dpu in admin_force_delete_machine",
                    e,
                ))
            })?;

            // Free up all loopback IPs allocated for this DPU.
            db::vpc::VpcDpuLoopback::delete(dpu_machine.id(), &mut txn)
                .await
                .map_err(CarbideError::from)?;

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

            if request.delete_bmc_interfaces {
                if let Some(bmc_ip) = &dpu_machine.bmc_info().ip {
                    response.dpu_bmc_interface_associated = true;
                    if let Ok(ip_addr) = IpAddr::from_str(bmc_ip) {
                        if db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                            .await
                            .map_err(CarbideError::from)?
                            .is_some()
                        {
                            response.dpu_bmc_interface_deleted = true;
                        }
                    }
                }
            }

            Machine::force_cleanup(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;

            if request.delete_interfaces {
                for interface in dpu_machine.interfaces() {
                    db::machine_interface::delete(&interface.id, &mut txn)
                        .await
                        .map_err(CarbideError::from)?;
                }
                response.dpu_interfaces_deleted = true;
            }

            if let Some(addr) = &dpu_machine.bmc_info().ip {
                if let Ok(addr) = IpAddr::from_str(addr) {
                    tracing::info!(
                        "Cleaning up explored endpoint at {addr} {}",
                        dpu_machine.id()
                    );

                    DbExploredEndpoint::delete(&mut txn, addr)
                        .await
                        .map_err(CarbideError::from)?;
                }
            }

            if request.delete_bmc_credentials {
                self.clear_bmc_credentials(dpu_machine).await?;
            }

            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "end delete dpu in admin_force_delete_machine",
                    e,
                ))
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
        crate::handlers::resource_pool::grow(self, request).await
    }

    async fn admin_list_resource_pools(
        &self,
        request: Request<rpc::ListResourcePoolsRequest>,
    ) -> Result<tonic::Response<rpc::ResourcePools>, tonic::Status> {
        crate::handlers::resource_pool::list(self, request).await
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
        let dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?;

        // We set status on both host and dpu machine to make them easier to query from DB
        let mode = match req.operation() {
            rpc::MaintenanceOperation::Enable => {
                let Some(reference) = req.reference else {
                    return Err(Status::invalid_argument(
                        "Missing reference url".to_string(),
                    ));
                };

                let reference = reference.trim().to_string();
                if reference.len() < 5 {
                    return Err(Status::invalid_argument(
                        "Provide some valid reference. Minimum expected length is 5.".to_string(),
                    ));
                }

                // Maintenance mode is implemented as a host health override
                crate::handlers::health::insert_health_report_override(
                    self,
                    tonic::Request::new(rpc::InsertHealthReportOverrideRequest {
                        machine_id: req.host_id.clone(),
                        r#override: Some(::rpc::forge::HealthReportOverride {
                            report: Some(health_report::HealthReport {
                                source: "maintenance".to_string(),
                                observed_at: Some(chrono::Utc::now()),
                                successes: Vec::new(),
                                alerts: vec![health_report::HealthProbeAlert {
                                    id: "Maintenance".parse().unwrap(),
                                    target: None,
                                    in_alert_since: Some(chrono::Utc::now()),
                                    message: reference.clone(),
                                    tenant_message: None,
                                    classifications: vec![
                                        health_report::HealthAlertClassification::prevent_allocations(),
                                    ],
                                }],
                            }
                            .into()),
                            mode: ::rpc::forge::OverrideMode::Merge.into(),
                        }),
                    }),
                )
                .await?;

                MaintenanceMode::On { reference }
            }
            rpc::MaintenanceOperation::Disable => {
                for dpu_machine in dpu_machines.iter() {
                    if dpu_machine.reprovisioning_requested().is_some() {
                        return Err(Status::invalid_argument(format!(
                            "Reprovisioning request is set on DPU: {}. Clear it first.",
                            dpu_machine.id()
                        )));
                    }
                }

                match crate::handlers::health::remove_health_report_override(
                    self,
                    tonic::Request::new(rpc::RemoveHealthReportOverrideRequest {
                        machine_id: req.host_id.clone(),
                        source: "maintenance".to_string(),
                    }),
                )
                .await
                {
                    Ok(_) => (),
                    Err(status) if status.code() == tonic::Code::NotFound => (),
                    Err(status) => return Err(status),
                };

                MaintenanceMode::Off
            }
        };

        Machine::set_maintenance_mode(&mut txn, host_machine.id(), &mode)
            .await
            .map_err(CarbideError::from)?;

        for dpu_machine in &dpu_machines {
            Machine::set_maintenance_mode(&mut txn, dpu_machine.id(), &mode)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end maintenance handler",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn find_ip_address(
        &self,
        request: tonic::Request<rpc::FindIpAddressRequest>,
    ) -> Result<tonic::Response<rpc::FindIpAddressResponse>, tonic::Status> {
        crate::handlers::finder::find_ip_address(self, request).await
    }

    async fn identify_uuid(
        &self,
        request: tonic::Request<rpc::IdentifyUuidRequest>,
    ) -> Result<tonic::Response<rpc::IdentifyUuidResponse>, tonic::Status> {
        crate::handlers::finder::identify_uuid(self, request).await
    }

    async fn identify_mac(
        &self,
        request: tonic::Request<rpc::IdentifyMacRequest>,
    ) -> Result<tonic::Response<rpc::IdentifyMacResponse>, tonic::Status> {
        crate::handlers::finder::identify_mac(self, request).await
    }

    async fn identify_serial(
        &self,
        request: tonic::Request<rpc::IdentifySerialRequest>,
    ) -> Result<tonic::Response<rpc::IdentifySerialResponse>, tonic::Status> {
        crate::handlers::finder::identify_serial(self, request).await
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        crate::handlers::dpu::trigger_dpu_reprovisioning(self, request).await
    }

    /// List DPUs waiting for reprovisioning
    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningListRequest>,
    ) -> Result<tonic::Response<rpc::DpuReprovisioningListResponse>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin trigger_dpu_reprovisioning ",
                e,
            ))
        })?;

        let dpus = Machine::list_machines_requested_for_reprovisioning(&mut txn)
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .map(
                |x| rpc::dpu_reprovisioning_list_response::DpuReprovisioningListItem {
                    id: Some(::rpc::common::MachineId {
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
                    initiated_at: x
                        .reprovisioning_requested()
                        .map(|a| a.started_at.map(|x| x.into()))
                        .unwrap_or_default(),
                    user_approval_received: x
                        .reprovisioning_requested()
                        .map(|x| x.user_approval_received)
                        .unwrap_or_default(),
                },
            )
            .collect_vec();

        Ok(Response::new(rpc::DpuReprovisioningListResponse { dpus }))
    }

    /// Retrieves all DPU information including id and loopback IP
    async fn get_dpu_info_list(
        &self,
        request: Request<rpc::GetDpuInfoListRequest>,
    ) -> Result<Response<rpc::GetDpuInfoListResponse>, Status> {
        log_request_data(&request);

        let _request: rpc::GetDpuInfoListRequest = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_all_dpu_ip",
                e,
            ))
        })?;

        let dpu_list = Machine::find_dpu_ids_and_loopback_ips(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        // Commit database transaction
        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_dpu_info_list",
                e,
            ))
        })?;

        let response = rpc::GetDpuInfoListResponse { dpu_list };

        Ok(Response::new(response))
    }

    async fn get_machine_boot_override(
        &self,
        request: tonic::Request<::rpc::common::Uuid>,
    ) -> Result<tonic::Response<rpc::MachineBootOverride>, tonic::Status> {
        crate::handlers::boot_override::get(self, request).await
    }

    async fn set_machine_boot_override(
        &self,
        request: tonic::Request<rpc::MachineBootOverride>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::boot_override::set(self, request).await
    }

    async fn clear_machine_boot_override(
        &self,
        request: tonic::Request<::rpc::common::Uuid>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::boot_override::clear(self, request).await
    }

    async fn get_network_topology(
        &self,
        request: tonic::Request<rpc::NetworkTopologyRequest>,
    ) -> Result<tonic::Response<rpc::NetworkTopologyData>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_lldp_topology ",
                e,
            ))
        })?;

        let query = match &req.id {
            Some(x) => ObjectFilter::One(x.as_str()),
            None => ObjectFilter::All,
        };

        let data = NetworkTopologyData::get_topology(&mut txn, query)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end get_lldp_topology handler",
                e,
            ))
        })?;

        Ok(Response::new(data.into()))
    }

    async fn admin_bmc_reset(
        &self,
        request: tonic::Request<rpc::AdminBmcResetRequest>,
    ) -> Result<tonic::Response<rpc::AdminBmcResetResponse>, tonic::Status> {
        log_request_data(&request);

        let req = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin admin_bmc_reset",
                e,
            ))
        })?;

        let bmc_endpoint_request = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit admin_bmc_reset",
                e,
            ))
        })?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!(
            "Resetting BMC (ipmi tool: {}): {}",
            req.use_ipmitool,
            endpoint_address
        );

        if req.use_ipmitool {
            crate::handlers::bmc_endpoint_explorer::ipmitool_reset_bmc(self, bmc_endpoint_request)
                .await?;
        } else {
            crate::handlers::bmc_endpoint_explorer::redfish_reset_bmc(self, bmc_endpoint_request)
                .await?;
        }

        tracing::info!(
            "BMC Reset (ipmi tool: {}) request succeeded to {}",
            req.use_ipmitool,
            endpoint_address
        );

        Ok(Response::new(rpc::AdminBmcResetResponse {}))
    }

    async fn forge_setup(
        &self,
        request: tonic::Request<rpc::ForgeSetupRequest>,
    ) -> Result<Response<::rpc::forge::ForgeSetupResponse>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "begin forge_setup", e))
        })?;

        let bmc_endpoint_request = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit forge_setup",
                e,
            ))
        })?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!("Starting Forge Setup for BMC: {}", endpoint_address);

        crate::handlers::bmc_endpoint_explorer::forge_setup(self, bmc_endpoint_request.clone())
            .await?;

        tracing::info!("Forge Setup request succeeded to {}", endpoint_address);

        Ok(Response::new(rpc::ForgeSetupResponse {}))
    }

    async fn fetch_forge_setup_status(
        &self,
        request: tonic::Request<rpc::ForgeSetupStatusRequest>,
    ) -> Result<Response<::rpc::forge::ForgeSetupStatus>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin fetch_forge_setup_status",
                e,
            ))
        })?;

        let bmc_endpoint_request = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit fetch_forge_setup_status",
                e,
            ))
        })?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!("Fetching Forge Setup Status: {}", endpoint_address);

        crate::handlers::bmc_endpoint_explorer::forge_setup_status(
            self,
            bmc_endpoint_request.clone(),
        )
        .await
    }

    /// Should this DPU upgrade it's forge-dpu-agent?
    /// Once the upgrade is complete record_dpu_network_status will receive the updated
    /// version and write the DB to say our upgrade is complete.
    async fn dpu_agent_upgrade_check(
        &self,
        request: tonic::Request<rpc::DpuAgentUpgradeCheckRequest>,
    ) -> Result<tonic::Response<rpc::DpuAgentUpgradeCheckResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_check(self, request).await
    }

    /// Get or set the forge-dpu-agent upgrade policy.
    async fn dpu_agent_upgrade_policy_action(
        &self,
        request: tonic::Request<rpc::DpuAgentUpgradePolicyRequest>,
    ) -> Result<tonic::Response<rpc::DpuAgentUpgradePolicyResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_policy_action(self, request).await
    }

    async fn create_credential(
        &self,
        request: tonic::Request<rpc::CredentialCreationRequest>,
    ) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
        crate::handlers::credential::create_credential(self, request).await
    }

    async fn delete_credential(
        &self,
        request: tonic::Request<rpc::CredentialDeletionRequest>,
    ) -> Result<tonic::Response<rpc::CredentialDeletionResult>, tonic::Status> {
        crate::handlers::credential::delete_credential(self, request).await
    }

    /// Returns a list of all configured route server addresses
    async fn get_route_servers(
        &self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Response<rpc::RouteServers>, Status> {
        crate::handlers::route_server::get(self, request).await
    }

    /// Overwrites all existing route server entries with the provided list
    async fn add_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::route_server::add(self, request).await
    }

    async fn remove_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::route_server::remove(self, request).await
    }

    /// Overwrites all existing route server entries with the provided list
    async fn replace_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::route_server::replace(self, request).await
    }

    // Override RUST_LOG or site-explorer create_machines
    async fn set_dynamic_config(
        &self,
        request: tonic::Request<rpc::SetDynamicConfigRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let exp_str = req.expiry.as_deref().unwrap_or("1h");
        let expiry = duration_str::parse(exp_str).map_err(|err| {
            Status::invalid_argument(format!("Invalid expiry string '{exp_str}'. {err}"))
        })?;
        const MAX_SET_INTERNAL_EXPIRY: Duration = Duration::from_secs(60 * 60 * 60); // 60 hours
        if MAX_SET_INTERNAL_EXPIRY < expiry {
            return Err(Status::invalid_argument(
                "Expiry exceeds max allowed of 60 hours",
            ));
        }
        let expire_at = chrono::Utc::now() + expiry;

        let Ok(requested_setting) = rpc::ConfigSetting::try_from(req.setting) else {
            return Err(Status::invalid_argument(format!(
                "Not a supported dynamic config setting: {}",
                req.setting
            )));
        };

        if req.value.is_empty() && !matches!(requested_setting, rpc::ConfigSetting::BmcProxy) {
            return Err(Status::invalid_argument("'value' cannot be empty"));
        }

        match requested_setting {
            rpc::ConfigSetting::LogFilter => {
                let current_level = self.dynamic_settings.log_filter.load();
                let next_level = current_level
                    .with_base(&req.value, Some(expire_at))
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "Invalid log filter string '{}'. {err}",
                            req.value
                        ))
                    })?;
                self.dynamic_settings.log_filter.store(Arc::new(next_level));
                tracing::info!("Log filter updated to '{}'", req.value);
            }
            rpc::ConfigSetting::CreateMachines => {
                let is_enabled = req.value.parse::<bool>().map_err(|err| {
                    Status::invalid_argument(format!(
                        "Invalid create_machines string '{}'. {err}",
                        req.value
                    ))
                })?;
                self.dynamic_settings
                    .create_machines
                    .store(Arc::new(is_enabled));
                tracing::info!("site-explorer create_machines updated to '{}'", req.value);
            }
            rpc::ConfigSetting::BmcProxy => {
                let Some(true) = self.runtime_config.site_explorer.allow_changing_bmc_proxy else {
                    return Err(Status::permission_denied(
                        "site-explorer.bmc_proxy is not allowed to be changed on this server",
                    ));
                };

                if req.value.is_empty() {
                    self.dynamic_settings.bmc_proxy.store(Arc::new(None))
                } else {
                    let host_port_pair = req.value.parse::<HostPortPair>().map_err(|err| {
                        Status::invalid_argument(format!(
                            "Invalid bmc_proxy string '{}': {err}",
                            req.value
                        ))
                    })?;

                    self.dynamic_settings
                        .bmc_proxy
                        .store(Arc::new(Some(host_port_pair)));
                }
                tracing::info!("site-explorer create_machines updated to '{}'", req.value);
            }
        }
        Ok(tonic::Response::new(()))
    }

    async fn clear_host_uefi_password(
        &self,
        request: tonic::Request<rpc::ClearHostUefiPasswordRequest>,
    ) -> Result<tonic::Response<rpc::ClearHostUefiPasswordResponse>, tonic::Status> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin clear_host_uefi_password",
                e,
            ))
        })?;

        let request = request.into_inner();
        let machine_id = match &request.host_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        if !machine_id.machine_type().is_host() {
            return Err(Status::invalid_argument(
                "Carbide only supports clearing the UEFI password on discovered hosts",
            ));
        }

        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                hardware_health: self.runtime_config.host_health.hardware_health_reports,
            },
        )
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        let redfish_client = self
            .redfish_pool
            .create_client_from_machine_snapshot(&snapshot.host_snapshot, &mut txn)
            .await
            .map_err(|e| {
                tracing::error!("unable to create redfish client: {}", e);
                tonic::Status::internal(format!(
                    "Could not create connection to Redfish API to {}, check logs",
                    machine_id
                ))
            })?;

        let job_id: Option<String> = crate::redfish::clear_host_uefi_password(
            redfish_client.as_ref(),
            self.redfish_pool.clone(),
        )
        .await?;

        Ok(Response::new(rpc::ClearHostUefiPasswordResponse { job_id }))
    }

    async fn set_host_uefi_password(
        &self,
        request: tonic::Request<rpc::SetHostUefiPasswordRequest>,
    ) -> Result<tonic::Response<rpc::SetHostUefiPasswordResponse>, tonic::Status> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin set_host_uefi_password",
                e,
            ))
        })?;

        let request = request.into_inner();
        let machine_id = match &request.host_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        if !machine_id.machine_type().is_host() {
            return Err(Status::invalid_argument(
                "Carbide only supports setting the UEFI password on discovered hosts",
            ));
        }

        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                hardware_health: self.runtime_config.host_health.hardware_health_reports,
            },
        )
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        let redfish_client = crate::redfish::build_redfish_client_from_bmc_ip(
            snapshot.host_snapshot.bmc_addr(),
            &self.redfish_pool,
            &mut txn,
        )
        .await
        .map_err(|e| {
            tracing::error!("unable to create redfish client: {}", e);
            tonic::Status::internal(format!(
                "Could not create connection to Redfish API to {}, check logs",
                machine_id
            ))
        })?;

        let job_id = crate::redfish::set_host_uefi_password(
            redfish_client.as_ref(),
            self.redfish_pool.clone(),
        )
        .await?;

        Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
    }

    async fn get_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<rpc::ExpectedMachine>, tonic::Status> {
        crate::handlers::expected_machine::get(self, request).await
    }

    async fn add_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::expected_machine::add(self, request).await
    }

    async fn delete_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::expected_machine::delete(self, request).await
    }

    async fn update_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::expected_machine::update(self, request).await
    }

    async fn replace_all_expected_machines(
        &self,
        request: tonic::Request<rpc::ExpectedMachineList>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::expected_machine::replace_all(self, request).await
    }

    async fn get_all_expected_machines(
        &self,
        request: tonic::Request<()>,
    ) -> Result<Response<rpc::ExpectedMachineList>, tonic::Status> {
        crate::handlers::expected_machine::get_all(self, request).await
    }

    async fn get_all_expected_machines_linked(
        &self,
        request: tonic::Request<()>,
    ) -> Result<Response<rpc::LinkedExpectedMachineList>, tonic::Status> {
        crate::handlers::expected_machine::get_linked(self, request).await
    }

    async fn delete_all_expected_machines(
        &self,
        request: tonic::Request<()>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::expected_machine::delete_all(self, request).await
    }

    async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: Request<::rpc::common::MachineIdList>,
    ) -> Result<tonic::Response<rpc::ConnectedDeviceList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_connected_devices_by_dpu_machine_ids",
                e,
            ))
        })?;
        let dpu_ids: Vec<String> = request
            .into_inner()
            .machine_ids
            .into_iter()
            .map(|id| id.id)
            .collect();

        let connected_devices = DpuToNetworkDeviceMap::find_by_dpu_ids(&mut txn, &dpu_ids)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::ConnectedDeviceList {
            connected_devices: connected_devices.into_iter().map_into().collect(),
        }))
    }

    async fn find_network_devices_by_device_ids(
        &self,
        request: Request<rpc::NetworkDeviceIdList>,
    ) -> Result<tonic::Response<rpc::NetworkTopologyData>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_network_devices_by_device_ids",
                e,
            ))
        })?;
        let request = request.into_inner(); // keep lifetime for this scope
        let network_device_ids: Vec<&str> = request
            .network_device_ids
            .iter()
            .map(|d| d.as_str())
            .collect();
        let network_devices = NetworkDevice::find(
            &mut txn,
            ObjectFilter::List(&network_device_ids),
            &NetworkDeviceSearchConfig::new(false),
        )
        .await
        .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::NetworkTopologyData {
            network_devices: network_devices.into_iter().map_into().collect(),
        }))
    }

    async fn find_machine_ids_by_bmc_ips(
        &self,
        request: Request<rpc::BmcIpList>,
    ) -> Result<tonic::Response<rpc::MachineIdBmcIpPairs>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machine_ids_by_bmc_ips",
                e,
            ))
        })?;
        let pairs = MachineTopology::find_machine_bmc_pairs(&mut txn, request.into_inner().bmc_ips)
            .await
            .map_err(CarbideError::from)?;
        let rpc_pairs = rpc::MachineIdBmcIpPairs {
            pairs: pairs
                .into_iter()
                .map(|(machine_id, bmc_ip)| rpc::MachineIdBmcIp {
                    machine_id: Some(machine_id.clone().into()),
                    bmc_ip,
                })
                .collect(),
        };

        Ok(tonic::Response::new(rpc_pairs))
    }

    async fn find_mac_address_by_bmc_ip(
        &self,
        request: Request<rpc::BmcIp>,
    ) -> Result<tonic::Response<rpc::MacAddressBmcIp>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let bmc_ip = req.bmc_ip;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_mac_address_by_bmc_ip",
                e,
            ))
        })?;

        let interface = db::machine_interface::find_by_ip(&mut txn, bmc_ip.parse().unwrap())
            .await
            .map_err(CarbideError::from)?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine_interface",
                id: bmc_ip.clone(),
            })?;

        Ok(tonic::Response::new(rpc::MacAddressBmcIp {
            bmc_ip,
            mac_address: interface.mac_address.to_string(),
        }))
    }

    async fn attest_quote(
        &self,
        request: tonic::Request<rpc::AttestQuoteRequest>,
    ) -> std::result::Result<tonic::Response<rpc::AttestQuoteResponse>, tonic::Status> {
        log_request_data(&request);

        // TODO: consider if this code can be turned into a templated function and reused
        // in bind_attest_key
        let machine_id = match &request.get_ref().machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(CarbideError::MissingArgument("machine_id").into());
            }
        };
        log_machine_id(&machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin machine attestation verify quote",
                e,
            ))
        })?;

        let ak_pub_bytes =
            match db_attest::SecretAkPub::get_by_secret(&mut txn, &request.get_ref().credential)
                .await?
            {
                Some(entry) => entry.ak_pub,
                None => {
                    return Err(Status::from(CarbideError::AttestQuoteError(
                        "Could not form SQL query to fetch AK Pub".into(),
                    )));
                }
            };

        let ak_pub = TssPublic::unmarshall(ak_pub_bytes.as_slice()).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshal AK Pub: {0}", e))
        })?;

        let attest = Attest::unmarshall(&(request.get_ref()).attestation).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshall Attest struct: {0}", e))
        })?;

        let signature = Signature::unmarshall(&(request.get_ref()).signature).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshall Signature struct: {0}", e))
        })?;

        // Make sure sure the signature can at least be verified
        // as valid or invalid. If it can't be verified in any
        // way at all, return an error.
        let signature_valid =
            attest::verify_signature(&ak_pub, &request.get_ref().attestation, &signature)
                .inspect_err(|_| {
                    tracing::warn!(
                        "PCR signature verification failed (event log: {})",
                        attest::event_log_to_string(&request.get_ref().event_log)
                    );
                })?;

        // Make sure we can verify the the PCR hash one way
        // or another. If it can't be, return an error.
        let pcr_hash_matches = attest::verify_pcr_hash(&attest, &request.get_ref().pcr_values)
            .inspect_err(|_| {
                tracing::warn!(
                    "PCR hash verification failed (event log: {})",
                    attest::event_log_to_string(&request.get_ref().event_log)
                );
            })?;

        // And now pass on through the computed signature
        // validity and PCR hash match to see if execution can
        // continue (the event log goes with, since it will be
        // logged in the event of an invalid signature or PCR
        // hash mismatch).
        attest::verify_quote_state(
            signature_valid,
            pcr_hash_matches,
            &request.get_ref().event_log,
        )?;

        // If we've reached this point, we can now clean up
        // now ephemeral secret data from the database, and send
        // off the PCR values as a MeasurementReport.
        db_attest::SecretAkPub::delete(&mut txn, &request.get_ref().credential).await?;

        let pcr_values: ::measured_boot::pcr::PcrRegisterValueVec = request
            .into_inner()
            .pcr_values
            .drain(..)
            .map(hex::encode)
            .collect::<Vec<String>>()
            .into();

        // In this case, we're not doing anything with
        // the resulting report (at least not yet), so just
        // throw it away.
        let report = crate::measured_boot::db::report::new_with_txn(
            &mut txn,
            machine_id.clone(),
            pcr_values.into_inner().as_slice(),
        )
        .await
        .map_err(|e| {
            Status::internal(format!(
                "Failed storing measurement report: (machine_id: {}, err: {})",
                &machine_id, e
            ))
        })?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit machine attestation verify quote",
                e,
            ))
        })?;

        // if the attestation was successful and enabled, we can now vend the certs
        // - get attestation result
        // - if enabled and not successful, send response without certs
        // - else send response with certs
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin machine attestation verify quote",
                e,
            ))
        })?;

        if self.runtime_config.attestation_enabled
            && !attest::has_passed_attestation(&mut txn, &machine_id, &report.report_id).await?
        {
            tracing::info!(
                "Attestation failed for machine with id {} - not vending any certs",
                machine_id
            );
            return Ok(tonic::Response::new(rpc::AttestQuoteResponse {
                success: false,
                machine_certificate: None,
            }));
        }

        let id_str = machine_id.to_string();
        let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            forge_secrets::certificates::Certificate::default()
        } else {
            self.certificate_provider
                .get_certificate(id_str.as_str())
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
        };

        tracing::info!(
            "Attestation succeeded for machine with id {} - sending a cert back. Attestion_enabled is {}",
            machine_id,
            self.runtime_config.attestation_enabled
        );
        Ok(tonic::Response::new(rpc::AttestQuoteResponse {
            success: true,
            machine_certificate: Some(certificate.into()),
        }))
    }

    async fn create_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_create_system_measurement_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_delete_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn rename_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_rename_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_show_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_show_measurement_system_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profile_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileBundlesResponse>, Status>
    {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profile_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profile_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileMachinesResponse>, Status>
    {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profile_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn create_measurement_report(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_create_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_report(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_delete_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn promote_measurement_report(
        &self,
        request: Request<measured_boot_pb::PromoteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::PromoteMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_promote_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn revoke_measurement_report(
        &self,
        request: Request<measured_boot_pb::RevokeMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::RevokeMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_revoke_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_report_for_id(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportForIdRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportForIdResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_report_for_id(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_reports_for_machine(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsForMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsForMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_reports_for_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_reports(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_reports(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_report(
        &self,
        request: Request<measured_boot_pb::ListMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_list_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn match_measurement_report(
        &self,
        request: Request<measured_boot_pb::MatchMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::MatchMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_match_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn create_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_create_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_delete_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn rename_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_rename_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn update_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::UpdateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::UpdateMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_update_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_bundle_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundleMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundleMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundle_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_journal(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_delete_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_show_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_journals(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_show_measurement_journals(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ListMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_list_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn attest_candidate_machine(
        &self,
        request: Request<measured_boot_pb::AttestCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AttestCandidateMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_attest_candidate_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_candidate_machine(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ListCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_list_candidate_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn import_site_measurements(
        &self,
        request: Request<measured_boot_pb::ImportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ImportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_import_site_measurements(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn export_site_measurements(
        &self,
        request: Request<measured_boot_pb::ExportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ExportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_export_site_measurements(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn add_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_add_measurement_trusted_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn remove_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_remove_measurement_trusted_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_trusted_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_list_measurement_trusted_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn add_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_add_measurement_trusted_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn remove_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_remove_measurement_trusted_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_trusted_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_list_measurement_trusted_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    // Host has rebooted
    async fn reboot_completed(
        &self,
        request: Request<rpc::MachineRebootCompletedRequest>,
    ) -> Result<Response<rpc::MachineRebootCompletedResponse>, Status> {
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
            .update_reboot_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit reboot_completed",
                e,
            ))
        })?;

        Ok(Response::new(rpc::MachineRebootCompletedResponse {}))
    }

    // machine has completed validation
    async fn machine_validation_completed(
        &self,
        request: Request<rpc::MachineValidationCompletedRequest>,
    ) -> Result<Response<rpc::MachineValidationCompletedResponse>, Status> {
        mark_machine_validation_complete(self, request).await
    }

    async fn persist_validation_result(
        &self,
        request: tonic::Request<rpc::MachineValidationResultPostRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        persist_validation_result(self, request).await
    }

    async fn get_machine_validation_results(
        &self,
        request: tonic::Request<rpc::MachineValidationGetRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationResultList>, Status> {
        get_machine_validation_results(self, request).await
    }

    async fn machine_set_auto_update(
        &self,
        request: tonic::Request<rpc::MachineSetAutoUpdateRequest>,
    ) -> Result<tonic::Response<rpc::MachineSetAutoUpdateResponse>, Status> {
        log_request_data(&request);

        let request = request.into_inner();

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(file!(), line!(), "connect", e))
            })?;

        let machine_id = match &request.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine ID is required"));
            }
        };
        let Some(machine) =
            Machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
                .await
                .map_err(CarbideError::from)?
        else {
            return Err(Status::not_found("The machine ID was not found"));
        };
        log_machine_id(machine.id());

        let state = match request.action() {
            rpc::machine_set_auto_update_request::SetAutoupdateAction::Enable => Some(true),
            rpc::machine_set_auto_update_request::SetAutoupdateAction::Disable => Some(false),
            rpc::machine_set_auto_update_request::SetAutoupdateAction::Clear => None,
        };
        Machine::set_firmware_autoupdate(&mut txn, &machine_id, state)
            .await
            .map_err(CarbideError::from)?;

        txn.commit()
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), "commit", e)))?;

        Ok(Response::new(rpc::MachineSetAutoUpdateResponse {}))
    }

    async fn get_machine_validation_external_config(
        &self,
        request: tonic::Request<rpc::GetMachineValidationExternalConfigRequest>,
    ) -> Result<tonic::Response<rpc::GetMachineValidationExternalConfigResponse>, Status> {
        get_machine_validation_external_config(self, request).await
    }

    async fn get_machine_validation_external_configs(
        &self,
        request: tonic::Request<rpc::GetMachineValidationExternalConfigsRequest>,
    ) -> Result<tonic::Response<rpc::GetMachineValidationExternalConfigsResponse>, Status> {
        get_machine_validation_external_configs(self, request).await
    }
    async fn add_update_machine_validation_external_config(
        &self,
        request: tonic::Request<rpc::AddUpdateMachineValidationExternalConfigRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        add_update_machine_validation_external_config(self, request).await
    }

    async fn import_storage_cluster(
        &self,
        request: Request<rpc::StorageClusterAttributes>,
    ) -> Result<Response<rpc::StorageCluster>, Status> {
        crate::storage::import_storage_cluster(self, request).await
    }

    async fn list_storage_cluster(
        &self,
        request: Request<rpc::ListStorageClusterRequest>,
    ) -> Result<Response<rpc::ListStorageClusterResponse>, Status> {
        crate::storage::list_storage_cluster(self, request).await
    }

    async fn get_storage_cluster(
        &self,
        request: Request<::rpc::Uuid>,
    ) -> Result<Response<rpc::StorageCluster>, Status> {
        crate::storage::get_storage_cluster(self, request).await
    }

    async fn delete_storage_cluster(
        &self,
        request: Request<rpc::DeleteStorageClusterRequest>,
    ) -> Result<Response<rpc::DeleteStorageClusterResponse>, Status> {
        crate::storage::delete_storage_cluster(self, request).await
    }

    async fn update_storage_cluster(
        &self,
        request: Request<rpc::UpdateStorageClusterRequest>,
    ) -> Result<Response<rpc::StorageCluster>, Status> {
        crate::storage::update_storage_cluster(self, request).await
    }

    async fn create_storage_pool(
        &self,
        request: Request<rpc::StoragePoolAttributes>,
    ) -> Result<Response<rpc::StoragePool>, Status> {
        crate::storage::create_storage_pool(self, request).await
    }

    async fn list_storage_pool(
        &self,
        request: Request<rpc::ListStoragePoolRequest>,
    ) -> Result<Response<rpc::ListStoragePoolResponse>, Status> {
        crate::storage::list_storage_pool(self, request).await
    }

    async fn get_storage_pool(
        &self,
        request: Request<::rpc::Uuid>,
    ) -> Result<Response<rpc::StoragePool>, Status> {
        crate::storage::get_storage_pool(self, request).await
    }

    async fn delete_storage_pool(
        &self,
        request: Request<rpc::DeleteStoragePoolRequest>,
    ) -> Result<Response<rpc::DeleteStoragePoolResponse>, Status> {
        crate::storage::delete_storage_pool(self, request).await
    }

    async fn update_storage_pool(
        &self,
        request: Request<rpc::StoragePoolAttributes>,
    ) -> Result<Response<rpc::StoragePool>, Status> {
        crate::storage::update_storage_pool(self, request).await
    }

    async fn create_storage_volume(
        &self,
        request: Request<rpc::StorageVolumeAttributes>,
    ) -> Result<Response<rpc::StorageVolume>, Status> {
        crate::storage::create_storage_volume(self, request).await
    }

    async fn list_storage_volume(
        &self,
        request: Request<rpc::StorageVolumeFilter>,
    ) -> Result<Response<rpc::ListStorageVolumeResponse>, Status> {
        crate::storage::list_storage_volume(self, request).await
    }

    async fn get_storage_volume(
        &self,
        request: Request<::rpc::Uuid>,
    ) -> Result<Response<rpc::StorageVolume>, Status> {
        crate::storage::get_storage_volume(self, request).await
    }

    async fn delete_storage_volume(
        &self,
        request: Request<rpc::DeleteStorageVolumeRequest>,
    ) -> Result<Response<rpc::DeleteStorageVolumeResponse>, Status> {
        crate::storage::delete_storage_volume(self, request).await
    }

    async fn update_storage_volume(
        &self,
        request: Request<rpc::StorageVolumeAttributes>,
    ) -> Result<Response<rpc::StorageVolume>, Status> {
        crate::storage::update_storage_volume(self, request).await
    }

    async fn create_os_image(
        &self,
        request: Request<rpc::OsImageAttributes>,
    ) -> Result<Response<rpc::OsImage>, Status> {
        crate::storage::create_os_image(self, request).await
    }

    async fn list_os_image(
        &self,
        request: Request<rpc::ListOsImageRequest>,
    ) -> Result<Response<rpc::ListOsImageResponse>, Status> {
        crate::storage::list_os_image(self, request).await
    }

    async fn get_os_image(
        &self,
        request: Request<::rpc::Uuid>,
    ) -> Result<Response<rpc::OsImage>, Status> {
        crate::storage::get_os_image(self, request).await
    }

    async fn delete_os_image(
        &self,
        request: Request<rpc::DeleteOsImageRequest>,
    ) -> Result<Response<rpc::DeleteOsImageResponse>, Status> {
        crate::storage::delete_os_image(self, request).await
    }

    async fn update_os_image(
        &self,
        request: Request<rpc::OsImageAttributes>,
    ) -> Result<Response<rpc::OsImage>, Status> {
        crate::storage::update_os_image(self, request).await
    }
    async fn get_machine_validation_runs(
        &self,
        request: tonic::Request<rpc::MachineValidationRunListGetRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationRunList>, Status> {
        get_machine_validation_runs(self, request).await
    }

    async fn admin_power_control(
        &self,
        request: tonic::Request<rpc::AdminPowerControlRequest>,
    ) -> Result<Response<rpc::AdminPowerControlResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let action = req.action();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin admin_power_control",
                e,
            ))
        })?;

        let bmc_endpoint_request = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit admin_power_control",
                e,
            ))
        })?;

        let action = match action {
            ::rpc::forge::admin_power_control_request::SystemPowerControl::On => {
                libredfish::SystemPowerControl::On
            }
            ::rpc::forge::admin_power_control_request::SystemPowerControl::GracefulShutdown => {
                libredfish::SystemPowerControl::GracefulShutdown
            }
            ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff => {
                libredfish::SystemPowerControl::ForceOff
            }
            ::rpc::forge::admin_power_control_request::SystemPowerControl::GracefulRestart => {
                libredfish::SystemPowerControl::GracefulRestart
            }
            ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart => {
                libredfish::SystemPowerControl::ForceRestart
            }
        };

        crate::handlers::bmc_endpoint_explorer::redfish_power_control(
            self,
            bmc_endpoint_request,
            action,
        )
        .await?;

        Ok(Response::new(rpc::AdminPowerControlResponse {}))
    }

    async fn on_demand_machine_validation(
        &self,
        request: tonic::Request<rpc::MachineValidationOnDemandRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationOnDemandResponse>, Status> {
        on_demand_machine_validation(self, request).await
    }

    async fn tpm_add_ca_cert(
        &self,
        request: Request<rpc::TpmCaCert>,
    ) -> Result<Response<rpc::TpmCaAddedCaStatus>, tonic::Status> {
        crate::handlers::tpm_ca::tpm_add_ca_cert(&self.database_connection, request).await
    }

    async fn tpm_show_ca_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::TpmCaCertDetailCollection>, tonic::Status> {
        crate::handlers::tpm_ca::tpm_show_ca_certs(&self.database_connection, &request).await
    }

    async fn tpm_show_unmatched_ek_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::TpmEkCertStatusCollection>, tonic::Status> {
        crate::handlers::tpm_ca::tpm_show_unmatched_ek_certs(&self.database_connection, &request)
            .await
    }

    async fn tpm_delete_ca_cert(
        &self,
        request: Request<rpc::TpmCaCertId>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::tpm_ca::tpm_delete_ca_cert(&self.database_connection, request).await
    }

    async fn remove_machine_validation_external_config(
        &self,
        request: tonic::Request<rpc::RemoveMachineValidationExternalConfigRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        remove_machine_validation_external_config(self, request).await
    }
    async fn get_machine_validation_tests(
        &self,
        request: tonic::Request<rpc::MachineValidationTestsGetRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestsGetResponse>, Status> {
        get_machine_validation_tests(self, request).await
    }

    async fn update_machine_validation_test(
        &self,
        request: tonic::Request<rpc::MachineValidationTestUpdateRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
        update_machine_validation_test(self, request).await
    }
    async fn add_machine_validation_test(
        &self,
        request: tonic::Request<rpc::MachineValidationTestAddRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
        add_machine_validation_test(self, request).await
    }

    async fn machine_validation_test_verfied(
        &self,
        request: tonic::Request<rpc::MachineValidationTestVerfiedRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestVerfiedResponse>, Status> {
        machine_validation_test_verfied(self, request).await
    }
    async fn machine_validation_test_next_version(
        &self,
        request: tonic::Request<rpc::MachineValidationTestNextVersionRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestNextVersionResponse>, Status> {
        machine_validation_test_next_version(self, request).await
    }
    async fn machine_validation_test_enable_disable_test(
        &self,
        request: tonic::Request<rpc::MachineValidationTestEnableDisableTestRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationTestEnableDisableTestResponse>, Status> {
        machine_validation_test_enable_disable_test(self, request).await
    }
    async fn update_machine_validation_run(
        &self,
        request: tonic::Request<rpc::MachineValidationRunRequest>,
    ) -> Result<tonic::Response<rpc::MachineValidationRunResponse>, Status> {
        update_machine_validation_run(self, request).await
    }
}

pub(crate) fn log_request_data<T: std::fmt::Debug>(request: &Request<T>) {
    tracing::Span::current().record(
        "request",
        truncate(
            format!("{:?}", request.get_ref()),
            ::rpc::MAX_ERR_MSG_SIZE as usize,
        ),
    );
}

/// Logs the Machine ID in the current tracing span
pub(crate) fn log_machine_id(machine_id: &MachineId) {
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

/// Accepts an optional partial or complete BmcEndpointRequest and optional machine ID and returns a complete and valid BmcEndpointRequest.
///
/// * `txn`                  - Active database transaction
/// * `bmc_endpoint_request` - Optional BmcEndpointRequest.  Can supply _only_ ip_address or all fields.
/// * `machine_id`           - Optional machine ID that can be used to build a new BmcEndpointRequest.
pub(crate) async fn validate_and_complete_bmc_endpoint_request(
    txn: &mut Transaction<'_, Postgres>,
    bmc_endpoint_request: Option<rpc::BmcEndpointRequest>,
    machine_id: Option<String>,
) -> Result<rpc::BmcEndpointRequest, tonic::Status> {
    match (bmc_endpoint_request, machine_id) {
        (Some(bmc_endpoint_request), _) => {
            let interface = db::machine_interface::find_by_ip(
                txn,
                bmc_endpoint_request.ip_address.parse().unwrap(),
            )
            .await
            .map_err(CarbideError::from)?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine_interface",
                id: bmc_endpoint_request.ip_address.clone(),
            })?;

            let bmc_mac = match bmc_endpoint_request.mac_address {
                // No MAC in the request, use the interface MAC
                None => interface.mac_address.to_string(),

                // MAC passed in the request, check if it matches the interface MAC
                Some(request_mac) => {
                    let parsed_mac = request_mac
                        .parse::<MacAddress>()
                        .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;

                    if parsed_mac != interface.mac_address {
                        return Err(CarbideError::BmcMacIpMismatch {
                            requested_ip: bmc_endpoint_request.ip_address.clone(),
                            requested_mac: request_mac,
                            found_mac: interface.mac_address.to_string(),
                        }
                        .into());
                    }

                    request_mac
                }
            };

            Ok(BmcEndpointRequest {
                ip_address: bmc_endpoint_request.ip_address,
                mac_address: Some(bmc_mac),
            })
        }
        // User provided machine_id
        (_, Some(machine_id)) => {
            let machine_id = MachineId::from_str(&machine_id).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id.clone()))
            })?;
            log_machine_id(&machine_id);

            let mut topologies =
                MachineTopology::find_latest_by_machine_ids(txn, &[machine_id.clone()])
                    .await
                    .map_err(CarbideError::from)?;

            let topology =
                topologies
                    .remove(&machine_id)
                    .ok_or_else(|| CarbideError::NotFoundError {
                        kind: "machine",
                        id: machine_id.to_string(),
                    })?;

            let bmc_ip = topology.topology().bmc_info.ip.as_ref().ok_or_else(|| {
                CarbideError::internal(
                    format!("Machine found for {machine_id} but BMC IP is missing").to_string(),
                )
            })?;

            let bmc_mac_address = topology.topology().bmc_info.mac.ok_or_else(|| {
                CarbideError::internal(format!("BMC endpoint for {bmc_ip} ({machine_id}) found but does not have associated MAC").to_string())
            })?;

            Ok(BmcEndpointRequest {
                ip_address: bmc_ip.to_owned(),
                mac_address: Some(bmc_mac_address.to_string()),
            })
        }

        _ => Err(Status::invalid_argument(
            "Provide either machine_id or BmcEndpointRequest with at least ip_address",
        )),
    }
}

impl Api {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<CarbideConfig>,
        credential_provider: Arc<dyn CredentialProvider>,
        certificate_provider: Arc<dyn CertificateProvider>,
        database_connection: sqlx::PgPool,
        redfish_pool: Arc<dyn RedfishClientPool>,
        nvmesh_pool: Arc<dyn NvmeshClientPool>,
        eth_data: ethernet_virtualization::EthVirtData,
        common_pools: Arc<CommonPools>,
        ib_fabric_manager: Arc<dyn IBFabricManager>,
        dynamic_settings: dynamic_settings::DynamicSettings,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            certificate_provider,
            redfish_pool,
            nvmesh_pool,
            eth_data,
            common_pools,
            ib_fabric_manager,
            runtime_config: config,
            dpu_health_log_limiter: LogLimiter::new(
                std::time::Duration::from_secs(5 * 60),
                std::time::Duration::from_secs(60 * 60),
            ),
            dynamic_settings,
            endpoint_explorer,
        }
    }

    async fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> CarbideResult<(Machine, sqlx::Transaction<'_, sqlx::Postgres>)> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin load_machine",
                e,
            ))
        })?;
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

    /// Allocate a value from the vpc vni resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    pub(crate) async fn allocate_vpc_vni(
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
    pub(crate) async fn allocate_pkey(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<u16>, CarbideError> {
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

    pub fn log_filter_string(&self) -> String {
        self.dynamic_settings.log_filter.load().to_string()
    }

    async fn clear_bmc_credentials(&self, machine: &Machine) -> Result<(), CarbideError> {
        if let Some(mac_address) = machine.bmc_info().mac {
            tracing::info!(
                "Cleaning up BMC credentials in vault at {} for machine {}",
                mac_address,
                machine.id()
            );
            crate::handlers::credential::delete_bmc_root_credentials_by_mac(self, mac_address)
                .await
                .map_err(CarbideError::from)?;
        }

        Ok(())
    }
}

fn snapshot_map_to_rpc_machines(
    snapshots: HashMap<MachineId, ManagedHostStateSnapshot>,
) -> rpc::MachineList {
    let mut result = rpc::MachineList {
        machines: Vec::with_capacity(snapshots.len()),
    };

    for (machine_id, snapshot) in snapshots.into_iter() {
        if let Some(rpc_machine) =
            snapshot.rpc_machine_state(match machine_id.machine_type().is_dpu() {
                true => Some(&machine_id),
                false => None,
            })
        {
            result.machines.push(rpc_machine);
        }
        // A log message for the None case is already emitted inside
        // managed_host::load_by_machine_ids
    }

    result
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
