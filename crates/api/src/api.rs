/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod metrics;

use std::panic::Location;
use std::pin::Pin;
use std::sync::Arc;

use librms::RmsApi;
use nico_api_db::db_read::PgPoolReader;
use nico_api_db::work_lock_manager::WorkLockManagerHandle;
use nico_api_db::{DatabaseError, DatabaseResult, WithTransaction};
use nico_api_model::machine::Machine;
use nico_api_model::machine::machine_search_config::MachineSearchConfig;
use nico_api_model::resource_pool::common::CommonPools;
pub use nico_rpc::forge;
use nico_rpc::forge::forge_server::Forge;
use nico_rpc::forge::{RemoveSkuRequest, SkuIdList};
use nico_rpc::protos::dns::{
    CreateDomainRequest, DnsResourceRecordLookupRequest, DnsResourceRecordLookupResponse, Domain,
    DomainDeletionRequest, DomainDeletionResult, DomainList, DomainMetadataRequest,
    DomainMetadataResponse, DomainSearchQuery, GetAllDomainsRequest, GetAllDomainsResponse,
    UpdateDomainRequest,
};
use nico_rpc::protos::{measured_boot as measured_boot_pb, mlx_device as mlx_device_pb};
use nico_secrets::certificates::CertificateProvider;
use nico_secrets::credentials::CredentialManager;
use nico_uuid::machine::{MachineId, MachineInterfaceId};
use sqlx::{PgPool, PgTransaction};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use self::metrics::ApiMetricsEmitter;
use crate::cfg::file::CarbideConfig;
use crate::dpf::DpfOperations;
use crate::dynamic_settings::DynamicSettings;
use crate::ethernet_virtualization::EthVirtData;
use crate::ib::IBFabricManager;
use crate::logging::log_limiter::LogLimiter;
use crate::nvlink::NmxmClientPool;
use crate::redfish::RedfishClientPool;
use crate::scout_stream::ConnectionRegistry;
use crate::site_explorer::EndpointExplorer;
use crate::state_controller::controller::Enqueuer;
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::{CarbideError, CarbideResult};

pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    pub(crate) credential_manager: Arc<dyn CredentialManager>,
    pub(crate) certificate_provider: Arc<dyn CertificateProvider>,
    pub(crate) redfish_pool: Arc<dyn RedfishClientPool>,
    pub(crate) eth_data: EthVirtData,
    pub(crate) common_pools: Arc<CommonPools>,
    pub(crate) ib_fabric_manager: Arc<dyn IBFabricManager>,
    pub(crate) runtime_config: Arc<CarbideConfig>,
    pub(crate) dpu_health_log_limiter: LogLimiter<MachineId>,
    pub dynamic_settings: DynamicSettings,
    pub(crate) endpoint_explorer: Arc<dyn EndpointExplorer>,
    pub(crate) scout_stream_registry: ConnectionRegistry,
    #[allow(unused)]
    pub(crate) rms_client: Option<Arc<dyn RmsApi>>,
    pub(crate) nmxm_pool: Arc<dyn NmxmClientPool>,
    pub(crate) work_lock_manager_handle: WorkLockManagerHandle,
    pub(crate) dpf_sdk: Option<Arc<dyn DpfOperations>>,
    pub(crate) machine_state_handler_enqueuer: Enqueuer<MachineStateControllerIO>,
    pub(crate) metric_emitter: ApiMetricsEmitter,
    pub(crate) component_manager: Option<component_manager::component_manager::ComponentManager>,
}

pub(crate) type ScoutStreamType =
    Pin<Box<dyn Stream<Item = Result<forge::ScoutStreamScoutBoundMessage, Status>> + Send>>;

#[tonic::async_trait]
impl Forge for Api {
    type ScoutStreamStream = ScoutStreamType;

    async fn version(
        &self,
        request: Request<forge::VersionRequest>,
    ) -> Result<Response<forge::BuildInfo>, Status> {
        crate::handlers::api::version(self, request)
    }

    async fn create_domain(
        &self,
        request: Request<CreateDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        crate::handlers::domain::create(self, request).await
    }

    async fn update_domain(
        &self,
        request: Request<UpdateDomainRequest>,
    ) -> Result<Response<Domain>, Status> {
        crate::handlers::domain::update(self, request).await
    }

    async fn delete_domain(
        &self,
        request: Request<DomainDeletionRequest>,
    ) -> Result<Response<DomainDeletionResult>, Status> {
        crate::handlers::domain::delete(self, request).await
    }

    async fn find_domain(
        &self,
        request: Request<DomainSearchQuery>,
    ) -> Result<Response<DomainList>, Status> {
        crate::handlers::domain::find(self, request).await
    }

    // Legacy domain methods for backward compatibility
    // TODO: Remove this after clients have migrated
    async fn create_domain_legacy(
        &self,
        request: Request<forge::DomainLegacy>,
    ) -> Result<Response<forge::DomainLegacy>, Status> {
        crate::handlers::domain::create_legacy_compat(self, request).await
    }

    async fn update_domain_legacy(
        &self,
        request: Request<forge::DomainLegacy>,
    ) -> Result<Response<forge::DomainLegacy>, Status> {
        crate::handlers::domain::update_legacy_compat(self, request).await
    }

    async fn delete_domain_legacy(
        &self,
        request: Request<forge::DomainDeletionLegacy>,
    ) -> Result<Response<forge::DomainDeletionResultLegacy>, Status> {
        crate::handlers::domain::delete_legacy_compat(self, request).await
    }

    async fn find_domain_legacy(
        &self,
        request: Request<forge::DomainSearchQueryLegacy>,
    ) -> Result<Response<forge::DomainListLegacy>, Status> {
        crate::handlers::domain::find_legacy_compat(self, request).await
    }

    async fn create_vpc(
        &self,
        request: Request<forge::VpcCreationRequest>,
    ) -> Result<Response<forge::Vpc>, Status> {
        crate::handlers::vpc::create(self, request).await
    }

    async fn update_vpc(
        &self,
        request: Request<forge::VpcUpdateRequest>,
    ) -> Result<Response<forge::VpcUpdateResult>, Status> {
        crate::handlers::vpc::update(self, request).await
    }

    async fn update_vpc_virtualization(
        &self,
        request: Request<forge::VpcUpdateVirtualizationRequest>,
    ) -> Result<Response<forge::VpcUpdateVirtualizationResult>, Status> {
        crate::handlers::vpc::update_virtualization(self, request).await
    }

    async fn delete_vpc(
        &self,
        request: Request<forge::VpcDeletionRequest>,
    ) -> Result<Response<forge::VpcDeletionResult>, Status> {
        crate::handlers::vpc::delete(self, request).await
    }

    async fn find_vpc_ids(
        &self,
        request: Request<forge::VpcSearchFilter>,
    ) -> Result<Response<forge::VpcIdList>, Status> {
        crate::handlers::vpc::find_ids(self, request).await
    }

    async fn find_vpcs_by_ids(
        &self,
        request: Request<forge::VpcsByIdsRequest>,
    ) -> Result<Response<forge::VpcList>, Status> {
        crate::handlers::vpc::find_by_ids(self, request).await
    }

    async fn create_vpc_prefix(
        &self,
        request: Request<forge::VpcPrefixCreationRequest>,
    ) -> Result<Response<forge::VpcPrefix>, Status> {
        crate::handlers::vpc_prefix::create(self, request).await
    }

    async fn search_vpc_prefixes(
        &self,
        request: Request<forge::VpcPrefixSearchQuery>,
    ) -> Result<Response<forge::VpcPrefixIdList>, Status> {
        crate::handlers::vpc_prefix::search(self, request).await
    }

    async fn get_vpc_prefixes(
        &self,
        request: Request<forge::VpcPrefixGetRequest>,
    ) -> Result<Response<forge::VpcPrefixList>, Status> {
        crate::handlers::vpc_prefix::get(self, request).await
    }

    async fn update_vpc_prefix(
        &self,
        request: Request<forge::VpcPrefixUpdateRequest>,
    ) -> Result<Response<forge::VpcPrefix>, Status> {
        crate::handlers::vpc_prefix::update(self, request).await
    }
    async fn delete_vpc_prefix(
        &self,
        request: Request<forge::VpcPrefixDeletionRequest>,
    ) -> Result<Response<forge::VpcPrefixDeletionResult>, Status> {
        crate::handlers::vpc_prefix::delete(self, request).await
    }

    async fn create_vpc_peering(
        &self,
        request: Request<forge::VpcPeeringCreationRequest>,
    ) -> Result<Response<forge::VpcPeering>, Status> {
        crate::handlers::vpc_peering::create(self, request).await
    }

    async fn find_vpc_peering_ids(
        &self,
        request: Request<forge::VpcPeeringSearchFilter>,
    ) -> Result<Response<forge::VpcPeeringIdList>, Status> {
        crate::handlers::vpc_peering::find_ids(self, request).await
    }

    async fn find_vpc_peerings_by_ids(
        &self,
        request: Request<forge::VpcPeeringsByIdsRequest>,
    ) -> Result<Response<forge::VpcPeeringList>, Status> {
        crate::handlers::vpc_peering::find_by_ids(self, request).await
    }

    async fn delete_vpc_peering(
        &self,
        request: Request<forge::VpcPeeringDeletionRequest>,
    ) -> Result<Response<forge::VpcPeeringDeletionResult>, Status> {
        crate::handlers::vpc_peering::delete(self, request).await
    }

    async fn find_ib_partition_ids(
        &self,
        request: Request<forge::IbPartitionSearchFilter>,
    ) -> Result<Response<forge::IbPartitionIdList>, Status> {
        crate::handlers::ib_partition::find_ids(self, request).await
    }

    async fn find_ib_partitions_by_ids(
        &self,
        request: Request<forge::IbPartitionsByIdsRequest>,
    ) -> Result<Response<forge::IbPartitionList>, Status> {
        crate::handlers::ib_partition::find_by_ids(self, request).await
    }

    async fn create_ib_partition(
        &self,
        request: Request<forge::IbPartitionCreationRequest>,
    ) -> Result<Response<forge::IbPartition>, Status> {
        crate::handlers::ib_partition::create(self, request).await
    }

    async fn delete_ib_partition(
        &self,
        request: Request<forge::IbPartitionDeletionRequest>,
    ) -> Result<Response<forge::IbPartitionDeletionResult>, Status> {
        crate::handlers::ib_partition::delete(self, request).await
    }

    async fn update_ib_partition(
        &self,
        request: Request<forge::IbPartitionUpdateRequest>,
    ) -> Result<Response<forge::IbPartition>, Status> {
        crate::handlers::ib_partition::update(self, request).await
    }

    async fn ib_partitions_for_tenant(
        &self,
        request: Request<forge::TenantSearchQuery>,
    ) -> Result<Response<forge::IbPartitionList>, Status> {
        crate::handlers::ib_partition::for_tenant(self, request).await
    }

    async fn find_power_shelves(
        &self,
        request: Request<forge::PowerShelfQuery>,
    ) -> Result<Response<forge::PowerShelfList>, Status> {
        crate::handlers::power_shelf::find_power_shelf(self, request).await
    }

    async fn find_power_shelf_ids(
        &self,
        request: Request<forge::PowerShelfSearchFilter>,
    ) -> Result<Response<forge::PowerShelfIdList>, Status> {
        crate::handlers::power_shelf::find_ids(self, request).await
    }

    async fn find_power_shelves_by_ids(
        &self,
        request: Request<forge::PowerShelvesByIdsRequest>,
    ) -> Result<Response<forge::PowerShelfList>, Status> {
        crate::handlers::power_shelf::find_by_ids(self, request).await
    }

    async fn delete_power_shelf(
        &self,
        request: Request<forge::PowerShelfDeletionRequest>,
    ) -> Result<Response<forge::PowerShelfDeletionResult>, Status> {
        crate::handlers::power_shelf::delete_power_shelf(self, request).await
    }

    async fn find_switches(
        &self,
        request: Request<forge::SwitchQuery>,
    ) -> Result<Response<forge::SwitchList>, Status> {
        crate::handlers::switch::find_switch(self, request).await
    }

    async fn find_switch_ids(
        &self,
        request: Request<forge::SwitchSearchFilter>,
    ) -> Result<Response<forge::SwitchIdList>, Status> {
        crate::handlers::switch::find_ids(self, request).await
    }

    async fn find_switches_by_ids(
        &self,
        request: Request<forge::SwitchesByIdsRequest>,
    ) -> Result<Response<forge::SwitchList>, Status> {
        crate::handlers::switch::find_by_ids(self, request).await
    }

    async fn delete_switch(
        &self,
        request: Request<forge::SwitchDeletionRequest>,
    ) -> Result<Response<forge::SwitchDeletionResult>, Status> {
        crate::handlers::switch::delete_switch(self, request).await
    }

    async fn find_ib_fabric_ids(
        &self,
        request: Request<forge::IbFabricSearchFilter>,
    ) -> Result<Response<forge::IbFabricIdList>, Status> {
        crate::handlers::ib_fabric::find_ids(self, request)
    }

    async fn find_network_segment_ids(
        &self,
        request: Request<forge::NetworkSegmentSearchFilter>,
    ) -> Result<Response<forge::NetworkSegmentIdList>, Status> {
        crate::handlers::network_segment::find_ids(self, request).await
    }

    async fn find_network_segments_by_ids(
        &self,
        request: Request<forge::NetworkSegmentsByIdsRequest>,
    ) -> Result<Response<forge::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::find_by_ids(self, request).await
    }

    async fn create_network_segment(
        &self,
        request: Request<forge::NetworkSegmentCreationRequest>,
    ) -> Result<Response<forge::NetworkSegment>, Status> {
        crate::handlers::network_segment::create(self, request).await
    }

    async fn delete_network_segment(
        &self,
        request: Request<forge::NetworkSegmentDeletionRequest>,
    ) -> Result<Response<forge::NetworkSegmentDeletionResult>, Status> {
        crate::handlers::network_segment::delete(self, request).await
    }

    async fn network_segments_for_vpc(
        &self,
        request: Request<forge::VpcSearchQuery>,
    ) -> Result<Response<forge::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::for_vpc(self, request).await
    }

    async fn allocate_instance(
        &self,
        request: Request<forge::InstanceAllocationRequest>,
    ) -> Result<Response<forge::Instance>, Status> {
        crate::handlers::instance::allocate(self, request).await
    }

    async fn allocate_instances(
        &self,
        request: Request<forge::BatchInstanceAllocationRequest>,
    ) -> Result<Response<forge::BatchInstanceAllocationResponse>, Status> {
        crate::handlers::instance::batch_allocate(self, request).await
    }

    async fn find_instance_ids(
        &self,
        request: Request<forge::InstanceSearchFilter>,
    ) -> Result<Response<forge::InstanceIdList>, Status> {
        crate::handlers::instance::find_ids(self, request).await
    }

    async fn find_instances_by_ids(
        &self,
        request: Request<forge::InstancesByIdsRequest>,
    ) -> Result<Response<forge::InstanceList>, Status> {
        crate::handlers::instance::find_by_ids(self, request).await
    }

    async fn find_instance_by_machine_id(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<forge::InstanceList>, Status> {
        crate::handlers::instance::find_by_machine_id(self, request).await
    }

    async fn release_instance(
        &self,
        request: Request<forge::InstanceReleaseRequest>,
    ) -> Result<Response<forge::InstanceReleaseResult>, Status> {
        crate::handlers::instance::release(self, request).await
    }

    async fn update_instance_phone_home_last_contact(
        &self,
        request: Request<forge::InstancePhoneHomeLastContactRequest>,
    ) -> Result<Response<forge::InstancePhoneHomeLastContactResponse>, Status> {
        crate::handlers::instance::update_phone_home_last_contact(self, request).await
    }

    async fn update_instance_operating_system(
        &self,
        request: Request<forge::InstanceOperatingSystemUpdateRequest>,
    ) -> Result<Response<forge::Instance>, Status> {
        crate::handlers::instance::update_operating_system(self, request).await
    }

    async fn update_instance_config(
        &self,
        request: Request<forge::InstanceConfigUpdateRequest>,
    ) -> Result<Response<forge::Instance>, Status> {
        crate::handlers::instance::update_instance_config(self, request).await
    }

    async fn get_managed_host_network_config(
        &self,
        request: Request<forge::ManagedHostNetworkConfigRequest>,
    ) -> Result<Response<forge::ManagedHostNetworkConfigResponse>, Status> {
        crate::handlers::dpu::get_managed_host_network_config(self, request).await
    }

    async fn update_agent_reported_inventory(
        &self,
        request: Request<forge::DpuAgentInventoryReport>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::update_agent_reported_inventory(self, request).await
    }

    async fn record_dpu_network_status(
        &self,
        request: Request<forge::DpuNetworkStatus>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::record_dpu_network_status(self, request).await
    }

    async fn list_health_report_overrides(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<forge::ListHealthReportOverrideResponse>, Status> {
        crate::handlers::health::list_health_report_overrides(self, request).await
    }

    async fn insert_health_report_override(
        &self,
        request: Request<forge::InsertHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::insert_health_report_override(self, request).await
    }

    async fn remove_health_report_override(
        &self,
        request: Request<forge::RemoveHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::remove_health_report_override(self, request).await
    }

    async fn list_rack_health_report_overrides(
        &self,
        request: Request<forge::ListRackHealthReportOverridesRequest>,
    ) -> Result<Response<forge::ListHealthReportOverrideResponse>, Status> {
        crate::handlers::rack::list_rack_health_report_overrides(self, request).await
    }

    async fn insert_rack_health_report_override(
        &self,
        request: Request<forge::InsertRackHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::rack::insert_rack_health_report_override(self, request).await
    }

    async fn remove_rack_health_report_override(
        &self,
        request: Request<forge::RemoveRackHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::rack::remove_rack_health_report_override(self, request).await
    }

    async fn get_all_domain_metadata(
        &self,
        request: Request<DomainMetadataRequest>,
    ) -> Result<Response<DomainMetadataResponse>, tonic::Status> {
        crate::handlers::dns::get_all_domain_metadata(self, request).await
    }

    async fn get_all_domains(
        &self,
        request: Request<GetAllDomainsRequest>,
    ) -> Result<Response<GetAllDomainsResponse>, tonic::Status> {
        crate::handlers::dns::get_all_domains(self, request).await
    }

    async fn lookup_record(
        &self,
        request: Request<DnsResourceRecordLookupRequest>,
    ) -> Result<Response<DnsResourceRecordLookupResponse>, Status> {
        crate::handlers::dns::lookup_record(self, request).await
    }

    // Legacy DNS lookup method for backward compatibility
    async fn lookup_record_legacy(
        &self,
        request: Request<forge::dns_message::DnsQuestion>,
    ) -> Result<Response<forge::dns_message::DnsResponse>, Status> {
        crate::handlers::dns::lookup_record_legacy_compat(self, request).await
    }

    async fn invoke_instance_power(
        &self,
        request: Request<forge::InstancePowerRequest>,
    ) -> Result<Response<forge::InstancePowerResult>, Status> {
        crate::handlers::instance::invoke_power(self, request).await
    }

    async fn echo(
        &self,
        request: Request<forge::EchoRequest>,
    ) -> Result<Response<forge::EchoResponse>, Status> {
        crate::handlers::api::echo(self, request)
    }

    async fn create_tenant(
        &self,
        request: Request<forge::CreateTenantRequest>,
    ) -> Result<Response<forge::CreateTenantResponse>, Status> {
        crate::handlers::tenant::create(self, request).await
    }

    async fn find_tenant(
        &self,
        request: Request<forge::FindTenantRequest>,
    ) -> Result<Response<forge::FindTenantResponse>, Status> {
        crate::handlers::tenant::find(self, request).await
    }

    async fn update_tenant(
        &self,
        request: Request<forge::UpdateTenantRequest>,
    ) -> Result<Response<forge::UpdateTenantResponse>, Status> {
        crate::handlers::tenant::update(self, request).await
    }

    async fn find_tenants_by_organization_ids(
        &self,
        request: Request<forge::TenantByOrganizationIdsRequest>,
    ) -> Result<Response<forge::TenantList>, Status> {
        crate::handlers::tenant::find_tenants_by_organization_ids(self, request).await
    }

    async fn find_tenant_organization_ids(
        &self,
        request: Request<forge::TenantSearchFilter>,
    ) -> Result<Response<forge::TenantOrganizationIdList>, Status> {
        crate::handlers::tenant::find_tenant_organization_ids(self, request).await
    }

    async fn create_tenant_keyset(
        &self,
        request: Request<forge::CreateTenantKeysetRequest>,
    ) -> Result<Response<forge::CreateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::create(self, request).await
    }

    async fn find_tenant_keyset_ids(
        &self,
        request: Request<forge::TenantKeysetSearchFilter>,
    ) -> Result<Response<forge::TenantKeysetIdList>, Status> {
        crate::handlers::tenant_keyset::find_ids(self, request).await
    }

    async fn find_tenant_keysets_by_ids(
        &self,
        request: Request<forge::TenantKeysetsByIdsRequest>,
    ) -> Result<Response<forge::TenantKeySetList>, Status> {
        crate::handlers::tenant_keyset::find_by_ids(self, request).await
    }

    async fn update_tenant_keyset(
        &self,
        request: Request<forge::UpdateTenantKeysetRequest>,
    ) -> Result<Response<forge::UpdateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::update(self, request).await
    }

    async fn delete_tenant_keyset(
        &self,
        request: Request<forge::DeleteTenantKeysetRequest>,
    ) -> Result<Response<forge::DeleteTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::delete(self, request).await
    }

    async fn validate_tenant_public_key(
        &self,
        request: Request<forge::ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<forge::ValidateTenantPublicKeyResponse>, Status> {
        crate::handlers::tenant_keyset::validate_public_key(self, request).await
    }

    async fn renew_machine_certificate(
        &self,
        request: Request<forge::MachineCertificateRenewRequest>,
    ) -> Result<Response<forge::MachineCertificateResult>, Status> {
        crate::handlers::credential::renew_machine_certificate(self, request).await
    }

    async fn discover_machine(
        &self,
        request: Request<forge::MachineDiscoveryInfo>,
    ) -> Result<Response<forge::MachineDiscoveryResult>, Status> {
        crate::handlers::machine_discovery::discover_machine(self, request).await
    }

    // Host has completed discovery
    async fn discovery_completed(
        &self,
        request: Request<forge::MachineDiscoveryCompletedRequest>,
    ) -> Result<Response<forge::MachineDiscoveryCompletedResponse>, Status> {
        crate::handlers::machine_discovery::discovery_completed(self, request).await
    }

    // Transitions the machine to Ready state.
    // Called by 'forge-scout discovery' once cleanup succeeds.
    async fn cleanup_machine_completed(
        &self,
        request: Request<forge::MachineCleanupInfo>,
    ) -> Result<Response<forge::MachineCleanupResult>, Status> {
        crate::handlers::machine_scout::cleanup_machine_completed(self, request).await
    }

    // Invoked by forge-scout whenever a certain Machine can not be properly acted on
    async fn report_forge_scout_error(
        &self,
        request: Request<forge::ForgeScoutErrorReport>,
    ) -> Result<Response<forge::ForgeScoutErrorReportResult>, Status> {
        crate::handlers::machine_scout::report_forge_scout_error(self, request)
    }

    async fn discover_dhcp(
        &self,
        request: Request<forge::DhcpDiscovery>,
    ) -> Result<Response<forge::DhcpRecord>, Status> {
        log_request_data(&request);

        Ok(crate::dhcp::discover::discover_dhcp(
            self,
            request,
            Some(self.runtime_config.rack_management_enabled),
        )
        .await?)
    }

    async fn expire_dhcp_lease(
        &self,
        request: Request<forge::ExpireDhcpLeaseRequest>,
    ) -> Result<Response<forge::ExpireDhcpLeaseResponse>, Status> {
        log_request_data(&request);
        Ok(crate::dhcp::expire::expire_dhcp_lease(self, request).await?)
    }

    async fn find_machine_ids(
        &self,
        request: Request<forge::MachineSearchConfig>,
    ) -> Result<Response<nico_rpc::common::MachineIdList>, Status> {
        crate::handlers::machine::find_machine_ids(self, request).await
    }

    async fn find_machines_by_ids(
        &self,
        request: Request<forge::MachinesByIdsRequest>,
    ) -> Result<Response<forge::MachineList>, Status> {
        crate::handlers::machine::find_machines_by_ids(self, request).await
    }

    async fn find_machine_state_histories(
        &self,
        request: Request<forge::MachineStateHistoriesRequest>,
    ) -> std::result::Result<Response<forge::MachineStateHistories>, Status> {
        crate::handlers::machine::find_machine_state_histories(self, request).await
    }

    async fn find_power_shelf_state_histories(
        &self,
        _request: Request<forge::PowerShelfStateHistoriesRequest>,
    ) -> Result<Response<forge::PowerShelfStateHistories>, Status> {
        Err(Status::unimplemented(
            "not implemented yet -- under construction",
        ))
    }

    async fn find_rack_state_histories(
        &self,
        request: tonic::Request<forge::RackStateHistoriesRequest>,
    ) -> Result<Response<forge::RackStateHistories>, Status> {
        crate::handlers::rack::find_rack_state_histories(self, request).await
    }

    async fn find_switch_state_histories(
        &self,
        request: Request<forge::SwitchStateHistoriesRequest>,
    ) -> Result<Response<forge::SwitchStateHistories>, Status> {
        crate::handlers::switch::find_switch_state_histories(self, request).await
    }

    async fn find_machine_health_histories(
        &self,
        request: Request<forge::MachineHealthHistoriesRequest>,
    ) -> std::result::Result<Response<forge::HealthHistories>, Status> {
        crate::handlers::machine::find_machine_health_histories(self, request).await
    }

    async fn find_interfaces(
        &self,
        request: Request<forge::InterfaceSearchQuery>,
    ) -> Result<Response<forge::InterfaceList>, Status> {
        crate::handlers::machine_interface::find_interfaces(self, request).await
    }

    async fn delete_interface(
        &self,
        request: Request<forge::InterfaceDeleteQuery>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_interface::delete_interface(self, request).await
    }

    // Fetches BMC Credentials
    async fn get_bmc_credentials(
        &self,
        request: Request<forge::GetBmcCredentialsRequest>,
    ) -> Result<Response<forge::GetBmcCredentialsResponse>, Status> {
        crate::handlers::credential::get_bmc_credentals(self, request).await
    }

    /// Network status of each managed host, as reported by forge-dpu-agent.
    /// For use by forge-admin-cli
    ///
    /// Currently: Status of HBN on each DPU
    async fn get_all_managed_host_network_status(
        &self,
        request: Request<forge::ManagedHostNetworkStatusRequest>,
    ) -> Result<Response<forge::ManagedHostNetworkStatusResponse>, Status> {
        crate::handlers::dpu::get_all_managed_host_network_status(self, request).await
    }

    async fn get_bmc_meta_data(
        &self,
        request: Request<forge::BmcMetaDataGetRequest>,
    ) -> Result<Response<forge::BmcMetaDataGetResponse>, Status> {
        crate::handlers::bmc_metadata::get(self, request).await
    }

    async fn update_machine_credentials(
        &self,
        request: Request<forge::MachineCredentialsUpdateRequest>,
    ) -> Result<Response<forge::MachineCredentialsUpdateResponse>, Status> {
        crate::handlers::credential::update_machine_credentials(self, request).await
    }

    // The carbide pxe server makes this RPC call
    async fn get_pxe_instructions(
        &self,
        request: Request<forge::PxeInstructionRequest>,
    ) -> Result<Response<forge::PxeInstructions>, Status> {
        crate::handlers::pxe::get_pxe_instructions(self, request).await
    }

    async fn get_cloud_init_instructions(
        &self,
        request: Request<forge::CloudInitInstructionsRequest>,
    ) -> Result<Response<forge::CloudInitInstructions>, Status> {
        crate::handlers::pxe::get_cloud_init_instructions(self, request).await
    }

    async fn clear_site_exploration_error(
        &self,
        request: Request<forge::ClearSiteExplorationErrorRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::clear_site_exploration_error(self, request).await
    }

    async fn is_bmc_in_managed_host(
        &self,
        request: Request<forge::BmcEndpointRequest>,
    ) -> Result<Response<forge::IsBmcInManagedHostResponse>, Status> {
        crate::handlers::site_explorer::is_bmc_in_managed_host(self, request).await
    }

    async fn bmc_credential_status(
        &self,
        request: Request<forge::BmcEndpointRequest>,
    ) -> Result<Response<forge::BmcCredentialStatusResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::bmc_credential_status(self, request).await
    }

    async fn re_explore_endpoint(
        &self,
        request: Request<forge::ReExploreEndpointRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::re_explore_endpoint(self, request).await
    }

    async fn delete_explored_endpoint(
        &self,
        request: Request<forge::DeleteExploredEndpointRequest>,
    ) -> Result<Response<forge::DeleteExploredEndpointResponse>, Status> {
        crate::handlers::site_explorer::delete_explored_endpoint(self, request).await
    }

    async fn pause_explored_endpoint_remediation(
        &self,
        request: Request<forge::PauseExploredEndpointRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::pause_explored_endpoint_remediation(self, request).await
    }

    // DEPRECATED: use find_explored_endpoint_ids, find_explored_endpoints_by_ids and find_explored_managed_host_ids, find_explored_managed_hosts_by_ids instead
    async fn get_site_exploration_report(
        &self,
        request: Request<forge::GetSiteExplorationRequest>,
    ) -> Result<Response<nico_rpc::site_explorer::SiteExplorationReport>, Status> {
        crate::handlers::site_explorer::get_site_exploration_report(self, request).await
    }

    async fn find_explored_endpoint_ids(
        &self,
        request: Request<nico_rpc::site_explorer::ExploredEndpointSearchFilter>,
    ) -> Result<Response<nico_rpc::site_explorer::ExploredEndpointIdList>, Status> {
        crate::handlers::site_explorer::find_explored_endpoint_ids(self, request).await
    }

    async fn find_explored_endpoints_by_ids(
        &self,
        request: Request<nico_rpc::site_explorer::ExploredEndpointsByIdsRequest>,
    ) -> Result<Response<nico_rpc::site_explorer::ExploredEndpointList>, Status> {
        crate::handlers::site_explorer::find_explored_endpoints_by_ids(self, request).await
    }

    async fn find_explored_managed_host_ids(
        &self,
        request: Request<nico_rpc::site_explorer::ExploredManagedHostSearchFilter>,
    ) -> Result<Response<nico_rpc::site_explorer::ExploredManagedHostIdList>, Status> {
        crate::handlers::site_explorer::find_explored_managed_host_ids(self, request).await
    }

    async fn find_explored_managed_hosts_by_ids(
        &self,
        request: Request<nico_rpc::site_explorer::ExploredManagedHostsByIdsRequest>,
    ) -> Result<Response<nico_rpc::site_explorer::ExploredManagedHostList>, Status> {
        crate::handlers::site_explorer::find_explored_managed_hosts_by_ids(self, request).await
    }

    async fn update_machine_hardware_info(
        &self,
        request: Request<forge::UpdateMachineHardwareInfoRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_hardware_info::handle_machine_hardware_info_update(self, request)
            .await
    }

    // Ad-hoc BMC exploration
    async fn explore(
        &self,
        request: Request<forge::BmcEndpointRequest>,
    ) -> Result<Response<nico_rpc::site_explorer::EndpointExplorationReport>, Status> {
        crate::handlers::bmc_endpoint_explorer::explore(self, request).await
    }

    // Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    // Tells it whether to discover or cleanup based on current machine state.
    async fn forge_agent_control(
        &self,
        request: Request<forge::ForgeAgentControlRequest>,
    ) -> Result<Response<forge::ForgeAgentControlResponse>, Status> {
        crate::handlers::machine_scout::forge_agent_control(self, request).await
    }

    async fn admin_force_delete_machine(
        &self,
        request: Request<forge::AdminForceDeleteMachineRequest>,
    ) -> Result<Response<forge::AdminForceDeleteMachineResponse>, Status> {
        crate::handlers::machine::admin_force_delete_machine(self, request).await
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
    async fn admin_grow_resource_pool(
        &self,
        request: Request<forge::GrowResourcePoolRequest>,
    ) -> Result<Response<forge::GrowResourcePoolResponse>, Status> {
        crate::handlers::resource_pool::grow(self, request).await
    }

    async fn admin_list_resource_pools(
        &self,
        request: Request<forge::ListResourcePoolsRequest>,
    ) -> Result<Response<forge::ResourcePools>, Status> {
        crate::handlers::resource_pool::list(self, request).await
    }

    async fn update_machine_metadata(
        &self,
        request: Request<forge::MachineMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::machine::update_machine_metadata(self, request).await
    }

    async fn update_rack_metadata(
        &self,
        request: Request<forge::RackMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::rack::update_rack_metadata(self, request).await
    }

    async fn update_switch_metadata(
        &self,
        request: Request<forge::SwitchMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::switch::update_switch_metadata(self, request).await
    }

    async fn update_power_shelf_metadata(
        &self,
        request: Request<forge::PowerShelfMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::power_shelf::update_power_shelf_metadata(self, request).await
    }

    async fn update_machine_nv_link_info(
        &self,
        request: Request<forge::UpdateMachineNvLinkInfoRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::machine::update_machine_nv_link_info(self, request).await
    }

    async fn set_maintenance(
        &self,
        request: Request<forge::MaintenanceRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::managed_host::set_maintenance(self, request).await
    }

    async fn find_ip_address(
        &self,
        request: Request<forge::FindIpAddressRequest>,
    ) -> Result<Response<forge::FindIpAddressResponse>, Status> {
        crate::handlers::finder::find_ip_address(self, request).await
    }

    async fn identify_uuid(
        &self,
        request: Request<forge::IdentifyUuidRequest>,
    ) -> Result<Response<forge::IdentifyUuidResponse>, Status> {
        crate::handlers::finder::identify_uuid(self, request).await
    }

    async fn identify_mac(
        &self,
        request: Request<forge::IdentifyMacRequest>,
    ) -> Result<Response<forge::IdentifyMacResponse>, Status> {
        crate::handlers::finder::identify_mac(self, request).await
    }

    async fn identify_serial(
        &self,
        request: Request<forge::IdentifySerialRequest>,
    ) -> Result<Response<forge::IdentifySerialResponse>, Status> {
        crate::handlers::finder::identify_serial(self, request).await
    }

    async fn get_power_options(
        &self,
        request: Request<forge::PowerOptionRequest>,
    ) -> Result<Response<forge::PowerOptionResponse>, Status> {
        crate::handlers::power_options::get_power_options(self, request).await
    }

    async fn update_power_option(
        &self,
        request: Request<forge::PowerOptionUpdateRequest>,
    ) -> Result<Response<forge::PowerOptionResponse>, Status> {
        crate::handlers::power_options::update_power_option(self, request).await
    }

    async fn get_rack(
        &self,
        request: Request<forge::GetRackRequest>,
    ) -> Result<Response<forge::GetRackResponse>, Status> {
        crate::handlers::rack::get_rack(self, request).await
    }

    async fn find_rack_ids(
        &self,
        request: Request<forge::RackSearchFilter>,
    ) -> Result<Response<forge::RackIdList>, Status> {
        crate::handlers::rack::find_ids(self, request).await
    }

    async fn find_racks_by_ids(
        &self,
        request: Request<forge::RacksByIdsRequest>,
    ) -> Result<Response<forge::RackList>, Status> {
        crate::handlers::rack::find_by_ids(self, request).await
    }

    async fn delete_rack(
        &self,
        request: Request<forge::DeleteRackRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::rack::delete_rack(self, request).await
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: Request<forge::DpuReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::trigger_dpu_reprovisioning(self, request).await
    }

    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: Request<forge::DpuReprovisioningListRequest>,
    ) -> Result<Response<forge::DpuReprovisioningListResponse>, Status> {
        crate::handlers::dpu::list_dpu_waiting_for_reprovisioning(self, request).await
    }

    async fn trigger_host_reprovisioning(
        &self,
        request: Request<forge::HostReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::host_reprovisioning::trigger_host_reprovisioning(self, request).await
    }

    async fn mark_manual_firmware_upgrade_complete(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::host_reprovisioning::mark_manual_firmware_upgrade_complete(self, request)
            .await
    }

    async fn list_hosts_waiting_for_reprovisioning(
        &self,
        request: Request<forge::HostReprovisioningListRequest>,
    ) -> Result<Response<forge::HostReprovisioningListResponse>, Status> {
        crate::handlers::host_reprovisioning::list_hosts_waiting_for_reprovisioning(self, request)
            .await
    }

    /// Retrieves all DPU information including id and loopback IP
    async fn get_dpu_info_list(
        &self,
        request: Request<forge::GetDpuInfoListRequest>,
    ) -> Result<Response<forge::GetDpuInfoListResponse>, Status> {
        crate::handlers::machine::get_dpu_info_list(self, request).await
    }

    async fn get_machine_boot_override(
        &self,
        request: Request<MachineInterfaceId>,
    ) -> Result<Response<forge::MachineBootOverride>, Status> {
        crate::handlers::boot_override::get(self, request).await
    }

    async fn set_machine_boot_override(
        &self,
        request: Request<forge::MachineBootOverride>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::boot_override::set(self, request).await
    }

    async fn clear_machine_boot_override(
        &self,
        request: Request<MachineInterfaceId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::boot_override::clear(self, request).await
    }

    async fn get_network_topology(
        &self,
        request: Request<forge::NetworkTopologyRequest>,
    ) -> Result<Response<forge::NetworkTopologyData>, Status> {
        crate::handlers::network_devices::get_network_topology(self, request).await
    }

    async fn admin_bmc_reset(
        &self,
        request: Request<forge::AdminBmcResetRequest>,
    ) -> Result<Response<forge::AdminBmcResetResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::admin_bmc_reset(self, request).await
    }

    async fn disable_secure_boot(
        &self,
        request: Request<forge::BmcEndpointRequest>,
    ) -> Result<Response<forge::DisableSecureBootResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::disable_secure_boot(self, request).await
    }

    async fn lockdown(
        &self,
        request: Request<forge::LockdownRequest>,
    ) -> Result<Response<forge::LockdownResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::lockdown(self, request).await
    }

    async fn lockdown_status(
        &self,
        request: Request<forge::LockdownStatusRequest>,
    ) -> Result<Response<nico_rpc::site_explorer::LockdownStatus>, Status> {
        crate::handlers::bmc_endpoint_explorer::lockdown_status(self, request).await
    }

    async fn enable_infinite_boot(
        &self,
        request: Request<forge::EnableInfiniteBootRequest>,
    ) -> Result<Response<forge::EnableInfiniteBootResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::enable_infinite_boot(self, request).await
    }

    async fn is_infinite_boot_enabled(
        &self,
        request: Request<forge::IsInfiniteBootEnabledRequest>,
    ) -> Result<Response<forge::IsInfiniteBootEnabledResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::is_infinite_boot_enabled(self, request).await
    }

    async fn machine_setup(
        &self,
        request: Request<forge::MachineSetupRequest>,
    ) -> Result<Response<forge::MachineSetupResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::machine_setup(self, request).await
    }

    async fn set_dpu_first_boot_order(
        &self,
        request: Request<forge::SetDpuFirstBootOrderRequest>,
    ) -> Result<Response<forge::SetDpuFirstBootOrderResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::set_dpu_first_boot_order(self, request).await
    }

    /// Should this DPU upgrade it's forge-dpu-agent?
    /// Once the upgrade is complete record_dpu_network_status will receive the updated
    /// version and write the DB to say our upgrade is complete.
    async fn dpu_agent_upgrade_check(
        &self,
        request: Request<forge::DpuAgentUpgradeCheckRequest>,
    ) -> Result<Response<forge::DpuAgentUpgradeCheckResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_check(self, request).await
    }

    /// Get or set the forge-dpu-agent upgrade policy.
    async fn dpu_agent_upgrade_policy_action(
        &self,
        request: Request<forge::DpuAgentUpgradePolicyRequest>,
    ) -> Result<Response<forge::DpuAgentUpgradePolicyResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_policy_action(self, request).await
    }

    async fn create_credential(
        &self,
        request: Request<forge::CredentialCreationRequest>,
    ) -> Result<Response<forge::CredentialCreationResult>, Status> {
        crate::handlers::credential::create_credential(self, request).await
    }

    async fn delete_credential(
        &self,
        request: Request<forge::CredentialDeletionRequest>,
    ) -> Result<Response<forge::CredentialDeletionResult>, Status> {
        crate::handlers::credential::delete_credential(self, request).await
    }

    /// get_route_servers returns a list of all configured route server
    /// entries for all source types.
    async fn get_route_servers(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::RouteServerEntries>, Status> {
        crate::handlers::route_server::get(self, request).await
    }

    /// add_route_servers adds new route server entries for the
    /// provided source_type, defaulting to admin_api for calls
    /// coming from forge-admin-cli (but can be overridden in
    /// cases where deemed appropriate).
    async fn add_route_servers(
        &self,
        request: Request<forge::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::add(self, request).await
    }

    /// remove_route_servers removes route server entries for the
    /// provided source_type, defaulting to admin_api for calls
    /// coming from forge-admin-cli (but can be overridden in
    /// cases where deemed appropriate).
    async fn remove_route_servers(
        &self,
        request: Request<forge::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::remove(self, request).await
    }

    /// replace_route_servers replaces all route server entries
    /// for the provided source_type with the given list, defaulting
    /// to admin_api for calls coming from forge-admin-cli (but can
    /// be overridden in cases where deemed appropriate).
    async fn replace_route_servers(
        &self,
        request: Request<forge::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::replace(self, request).await
    }

    async fn set_dynamic_config(
        &self,
        request: Request<forge::SetDynamicConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::api::set_dynamic_config(self, request)
    }

    async fn clear_host_uefi_password(
        &self,
        request: Request<forge::ClearHostUefiPasswordRequest>,
    ) -> Result<Response<forge::ClearHostUefiPasswordResponse>, Status> {
        crate::handlers::uefi::clear_host_uefi_password(self, request).await
    }

    async fn set_host_uefi_password(
        &self,
        request: Request<forge::SetHostUefiPasswordRequest>,
    ) -> Result<Response<forge::SetHostUefiPasswordResponse>, Status> {
        crate::handlers::uefi::set_host_uefi_password(self, request).await
    }

    async fn get_expected_machine(
        &self,
        request: Request<forge::ExpectedMachineRequest>,
    ) -> Result<Response<forge::ExpectedMachine>, Status> {
        crate::handlers::expected_machine::get(self, request).await
    }

    async fn add_expected_machine(
        &self,
        request: Request<forge::ExpectedMachine>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::add(self, request).await
    }

    async fn delete_expected_machine(
        &self,
        request: Request<forge::ExpectedMachineRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::delete(self, request).await
    }

    async fn update_expected_machine(
        &self,
        request: Request<forge::ExpectedMachine>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::update(self, request).await
    }

    async fn replace_all_expected_machines(
        &self,
        request: Request<forge::ExpectedMachineList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::replace_all(self, request).await
    }

    async fn get_all_expected_machines(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::ExpectedMachineList>, Status> {
        crate::handlers::expected_machine::get_all(self, request).await
    }

    async fn get_all_expected_machines_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::LinkedExpectedMachineList>, Status> {
        crate::handlers::expected_machine::get_linked(self, request).await
    }

    async fn delete_all_expected_machines(
        &self,
        request: Request<()>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::delete_all(self, request).await
    }

    async fn create_expected_machines(
        &self,
        request: Request<forge::BatchExpectedMachineOperationRequest>,
    ) -> Result<Response<forge::BatchExpectedMachineOperationResponse>, Status> {
        crate::handlers::expected_machine::create_expected_machines(self, request).await
    }

    async fn update_expected_machines(
        &self,
        request: Request<forge::BatchExpectedMachineOperationRequest>,
    ) -> Result<Response<forge::BatchExpectedMachineOperationResponse>, Status> {
        crate::handlers::expected_machine::update_expected_machines(self, request).await
    }

    async fn create_rack_firmware(
        &self,
        request: tonic::Request<forge::RackFirmwareCreateRequest>,
    ) -> Result<Response<forge::RackFirmware>, tonic::Status> {
        crate::handlers::rack_firmware::create(self, request).await
    }

    async fn get_rack_firmware(
        &self,
        request: tonic::Request<forge::RackFirmwareGetRequest>,
    ) -> Result<Response<forge::RackFirmware>, tonic::Status> {
        crate::handlers::rack_firmware::get(self, request).await
    }

    async fn list_rack_firmware(
        &self,
        request: tonic::Request<forge::RackFirmwareListRequest>,
    ) -> Result<Response<forge::RackFirmwareList>, tonic::Status> {
        crate::handlers::rack_firmware::list(self, request).await
    }

    async fn delete_rack_firmware(
        &self,
        request: tonic::Request<forge::RackFirmwareDeleteRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::rack_firmware::delete(self, request).await
    }

    async fn apply_rack_firmware(
        &self,
        request: tonic::Request<forge::RackFirmwareApplyRequest>,
    ) -> Result<Response<forge::RackFirmwareApplyResponse>, tonic::Status> {
        crate::handlers::rack_firmware::apply(self, request).await
    }

    async fn get_rack_firmware_job_status(
        &self,
        request: tonic::Request<forge::RackFirmwareJobStatusRequest>,
    ) -> Result<Response<forge::RackFirmwareJobStatusResponse>, tonic::Status> {
        crate::handlers::rack_firmware::get_job_status(self, request).await
    }

    async fn get_rack_firmware_history(
        &self,
        request: tonic::Request<forge::RackFirmwareHistoryRequest>,
    ) -> Result<Response<forge::RackFirmwareHistoryResponse>, tonic::Status> {
        crate::handlers::rack_firmware::get_history(self, request).await
    }

    async fn get_expected_power_shelf(
        &self,
        request: Request<forge::ExpectedPowerShelfRequest>,
    ) -> Result<Response<forge::ExpectedPowerShelf>, Status> {
        crate::handlers::expected_power_shelf::get_expected_power_shelf(self, request).await
    }

    async fn add_expected_power_shelf(
        &self,
        request: Request<forge::ExpectedPowerShelf>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::add_expected_power_shelf(self, request).await
    }

    async fn delete_expected_power_shelf(
        &self,
        request: Request<forge::ExpectedPowerShelfRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::delete_expected_power_shelf(self, request).await
    }

    async fn update_expected_power_shelf(
        &self,
        request: Request<forge::ExpectedPowerShelf>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::update_expected_power_shelf(self, request).await
    }

    async fn replace_all_expected_power_shelves(
        &self,
        request: Request<forge::ExpectedPowerShelfList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::replace_all_expected_power_shelves(self, request)
            .await
    }

    async fn get_all_expected_power_shelves(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::ExpectedPowerShelfList>, Status> {
        crate::handlers::expected_power_shelf::get_all_expected_power_shelves(self, request).await
    }

    async fn get_all_expected_power_shelves_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::LinkedExpectedPowerShelfList>, Status> {
        crate::handlers::expected_power_shelf::get_all_expected_power_shelves_linked(self, request)
            .await
    }

    async fn delete_all_expected_power_shelves(
        &self,
        request: Request<()>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::delete_all_expected_power_shelves(self, request)
            .await
    }

    async fn get_expected_switch(
        &self,
        request: Request<forge::ExpectedSwitchRequest>,
    ) -> Result<Response<forge::ExpectedSwitch>, Status> {
        crate::handlers::expected_switch::get_expected_switch(self, request).await
    }

    async fn add_expected_switch(
        &self,
        request: Request<forge::ExpectedSwitch>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::add_expected_switch(self, request).await
    }

    async fn delete_expected_switch(
        &self,
        request: Request<forge::ExpectedSwitchRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::delete_expected_switch(self, request).await
    }

    async fn update_expected_switch(
        &self,
        request: Request<forge::ExpectedSwitch>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::update_expected_switch(self, request).await
    }

    async fn replace_all_expected_switches(
        &self,
        request: Request<forge::ExpectedSwitchList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::replace_all_expected_switches(self, request).await
    }

    async fn get_all_expected_switches(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::ExpectedSwitchList>, Status> {
        crate::handlers::expected_switch::get_all_expected_switches(self, request).await
    }

    async fn get_all_expected_switches_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::LinkedExpectedSwitchList>, Status> {
        crate::handlers::expected_switch::get_all_expected_switches_linked(self, request).await
    }

    async fn delete_all_expected_switches(
        &self,
        request: Request<()>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::delete_all_expected_switches(self, request).await
    }

    async fn add_expected_rack(
        &self,
        request: Request<forge::ExpectedRack>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_rack::add_expected_rack(self, request).await
    }

    async fn delete_expected_rack(
        &self,
        request: Request<forge::ExpectedRackRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_rack::delete_expected_rack(self, request).await
    }

    async fn update_expected_rack(
        &self,
        request: Request<forge::ExpectedRack>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_rack::update_expected_rack(self, request).await
    }

    async fn get_expected_rack(
        &self,
        request: Request<forge::ExpectedRackRequest>,
    ) -> Result<Response<forge::ExpectedRack>, Status> {
        crate::handlers::expected_rack::get_expected_rack(self, request).await
    }

    async fn get_all_expected_racks(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::ExpectedRackList>, Status> {
        crate::handlers::expected_rack::get_all_expected_racks(self, request).await
    }

    async fn replace_all_expected_racks(
        &self,
        request: Request<forge::ExpectedRackList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_rack::replace_all_expected_racks(self, request).await
    }

    async fn delete_all_expected_racks(
        &self,
        request: Request<()>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_rack::delete_all_expected_racks(self, request).await
    }

    async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: Request<nico_rpc::common::MachineIdList>,
    ) -> Result<Response<forge::ConnectedDeviceList>, Status> {
        crate::handlers::network_devices::find_connected_devices_by_dpu_machine_ids(self, request)
            .await
    }

    async fn find_network_devices_by_device_ids(
        &self,
        request: Request<forge::NetworkDeviceIdList>,
    ) -> Result<Response<forge::NetworkTopologyData>, Status> {
        crate::handlers::network_devices::find_network_devices_by_device_ids(self, request).await
    }

    async fn find_machine_ids_by_bmc_ips(
        &self,
        request: Request<forge::BmcIpList>,
    ) -> Result<Response<forge::MachineIdBmcIpPairs>, Status> {
        crate::handlers::machine::find_machine_ids_by_bmc_ips(self, request).await
    }

    async fn find_mac_address_by_bmc_ip(
        &self,
        request: Request<forge::BmcIp>,
    ) -> Result<Response<forge::MacAddressBmcIp>, Status> {
        crate::handlers::machine_interface::find_mac_address_by_bmc_ip(self, request).await
    }

    async fn attest_quote(
        &self,
        request: Request<forge::AttestQuoteRequest>,
    ) -> std::result::Result<Response<forge::AttestQuoteResponse>, Status> {
        crate::handlers::attestation::attest_quote(self, request).await
    }

    async fn create_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementSystemProfileResponse>, Status> {
        crate::handlers::measured_boot::create_system_profile(self, request).await
    }

    async fn delete_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementSystemProfileResponse>, Status> {
        crate::handlers::measured_boot::delete_system_profile(self, request).await
    }

    async fn rename_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementSystemProfileResponse>, Status> {
        crate::handlers::measured_boot::rename_system_profile(self, request).await
    }

    async fn show_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfileResponse>, Status> {
        crate::handlers::measured_boot::show_system_profile(self, request).await
    }

    async fn show_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfilesResponse>, Status> {
        crate::handlers::measured_boot::show_system_profiles(self, request).await
    }

    async fn list_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfilesResponse>, Status> {
        crate::handlers::measured_boot::list_system_profiles(self, request).await
    }

    async fn list_measurement_system_profile_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileBundlesResponse>, Status>
    {
        crate::handlers::measured_boot::list_system_profile_bundles(self, request).await
    }

    async fn list_measurement_system_profile_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileMachinesResponse>, Status>
    {
        crate::handlers::measured_boot::list_system_profile_machines(self, request).await
    }

    async fn create_measurement_report(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::create_report(self, request).await
    }

    async fn delete_measurement_report(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::delete_report(self, request).await
    }

    async fn promote_measurement_report(
        &self,
        request: Request<measured_boot_pb::PromoteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::PromoteMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::promote_report(self, request).await
    }

    async fn revoke_measurement_report(
        &self,
        request: Request<measured_boot_pb::RevokeMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::RevokeMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::revoke_report(self, request).await
    }

    async fn show_measurement_report_for_id(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportForIdRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportForIdResponse>, Status> {
        crate::handlers::measured_boot::show_report_for_id(self, request).await
    }

    async fn show_measurement_reports_for_machine(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsForMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsForMachineResponse>, Status> {
        crate::handlers::measured_boot::show_reports_for_machine(self, request).await
    }

    async fn show_measurement_reports(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsResponse>, Status> {
        crate::handlers::measured_boot::show_reports(self, request).await
    }

    async fn list_measurement_report(
        &self,
        request: Request<measured_boot_pb::ListMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::list_report(self, request).await
    }

    async fn match_measurement_report(
        &self,
        request: Request<measured_boot_pb::MatchMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::MatchMeasurementReportResponse>, Status> {
        crate::handlers::measured_boot::match_report(self, request).await
    }

    async fn create_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::create_bundle(self, request).await
    }

    async fn delete_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::delete_bundle(self, request).await
    }

    async fn rename_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::rename_bundle(self, request).await
    }

    async fn update_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::UpdateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::UpdateMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::update_bundle(self, request).await
    }

    async fn show_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::show_bundle(self, request).await
    }

    async fn show_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundlesResponse>, Status> {
        crate::handlers::measured_boot::show_bundles(self, request).await
    }

    async fn list_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundlesResponse>, Status> {
        crate::handlers::measured_boot::list_bundles(self, request).await
    }

    async fn list_measurement_bundle_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundleMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundleMachinesResponse>, Status> {
        crate::handlers::measured_boot::list_bundle_machines(self, request).await
    }

    async fn find_closest_bundle_match(
        &self,
        request: Request<measured_boot_pb::FindClosestBundleMatchRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        crate::handlers::measured_boot::find_closest_bundle_match(self, request).await
    }

    async fn delete_measurement_journal(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementJournalResponse>, Status> {
        crate::handlers::measured_boot::delete_journal(self, request).await
    }

    async fn show_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalResponse>, Status> {
        crate::handlers::measured_boot::show_journal(self, request).await
    }

    async fn show_measurement_journals(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalsResponse>, Status> {
        crate::handlers::measured_boot::show_journals(self, request).await
    }

    async fn list_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ListMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementJournalResponse>, Status> {
        crate::handlers::measured_boot::list_journal(self, request).await
    }

    async fn attest_candidate_machine(
        &self,
        request: Request<measured_boot_pb::AttestCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AttestCandidateMachineResponse>, Status> {
        crate::handlers::measured_boot::attest_candidate_machine(self, request).await
    }

    async fn show_candidate_machine(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachineResponse>, Status> {
        crate::handlers::measured_boot::show_candidate_machine(self, request).await
    }

    async fn show_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachinesResponse>, Status> {
        crate::handlers::measured_boot::show_candidate_machines(self, request).await
    }

    async fn list_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ListCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListCandidateMachinesResponse>, Status> {
        crate::handlers::measured_boot::list_candidate_machines(self, request).await
    }

    async fn import_site_measurements(
        &self,
        request: Request<measured_boot_pb::ImportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ImportSiteMeasurementsResponse>, Status> {
        crate::handlers::measured_boot::import_site_measurements(self, request).await
    }

    async fn export_site_measurements(
        &self,
        request: Request<measured_boot_pb::ExportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ExportSiteMeasurementsResponse>, Status> {
        crate::handlers::measured_boot::export_site_measurements(self, request).await
    }

    async fn add_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedMachineResponse>, Status> {
        crate::handlers::measured_boot::add_trusted_machine(self, request).await
    }

    async fn remove_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedMachineResponse>, Status> {
        crate::handlers::measured_boot::remove_trusted_machine(self, request).await
    }

    async fn list_measurement_trusted_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedMachinesResponse>, Status> {
        crate::handlers::measured_boot::list_trusted_machines(self, request).await
    }

    async fn add_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedProfileResponse>, Status> {
        crate::handlers::measured_boot::add_trusted_profile(self, request).await
    }

    async fn remove_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedProfileResponse>, Status> {
        crate::handlers::measured_boot::remove_trusted_profile(self, request).await
    }

    async fn list_measurement_trusted_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedProfilesResponse>, Status> {
        crate::handlers::measured_boot::list_trusted_profiles(self, request).await
    }

    async fn list_attestation_summary(
        &self,
        request: Request<measured_boot_pb::ListAttestationSummaryRequest>,
    ) -> Result<Response<measured_boot_pb::ListAttestationSummaryResponse>, Status> {
        crate::handlers::measured_boot::list_attestation_summary(self, request).await
    }

    // Host has rebooted
    async fn reboot_completed(
        &self,
        request: Request<forge::MachineRebootCompletedRequest>,
    ) -> Result<Response<forge::MachineRebootCompletedResponse>, Status> {
        crate::handlers::machine_scout::reboot_completed(self, request).await
    }

    // machine has completed validation
    async fn machine_validation_completed(
        &self,
        request: Request<forge::MachineValidationCompletedRequest>,
    ) -> Result<Response<forge::MachineValidationCompletedResponse>, Status> {
        crate::handlers::machine_validation::mark_machine_validation_complete(self, request).await
    }

    async fn persist_validation_result(
        &self,
        request: Request<forge::MachineValidationResultPostRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::persist_validation_result(self, request).await
    }

    async fn get_machine_validation_results(
        &self,
        request: Request<forge::MachineValidationGetRequest>,
    ) -> Result<Response<forge::MachineValidationResultList>, Status> {
        crate::handlers::machine_validation::get_machine_validation_results(self, request).await
    }

    async fn machine_set_auto_update(
        &self,
        request: Request<forge::MachineSetAutoUpdateRequest>,
    ) -> Result<Response<forge::MachineSetAutoUpdateResponse>, Status> {
        crate::handlers::machine::machine_set_auto_update(self, request).await
    }

    async fn get_machine_validation_external_config(
        &self,
        request: Request<forge::GetMachineValidationExternalConfigRequest>,
    ) -> Result<Response<forge::GetMachineValidationExternalConfigResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_external_config(self, request)
            .await
    }

    async fn get_machine_validation_external_configs(
        &self,
        request: Request<forge::GetMachineValidationExternalConfigsRequest>,
    ) -> Result<Response<forge::GetMachineValidationExternalConfigsResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_external_configs(self, request)
            .await
    }

    async fn add_update_machine_validation_external_config(
        &self,
        request: Request<forge::AddUpdateMachineValidationExternalConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::add_update_machine_validation_external_config(
            self, request,
        )
        .await
    }

    async fn create_os_image(
        &self,
        request: Request<forge::OsImageAttributes>,
    ) -> Result<Response<forge::OsImage>, Status> {
        crate::storage::create_os_image(self, request).await
    }

    async fn list_os_image(
        &self,
        request: Request<forge::ListOsImageRequest>,
    ) -> Result<Response<forge::ListOsImageResponse>, Status> {
        crate::storage::list_os_image(self, request).await
    }

    async fn get_os_image(
        &self,
        request: Request<nico_rpc::Uuid>,
    ) -> Result<Response<forge::OsImage>, Status> {
        crate::storage::get_os_image(self, request).await
    }

    async fn delete_os_image(
        &self,
        request: Request<forge::DeleteOsImageRequest>,
    ) -> Result<Response<forge::DeleteOsImageResponse>, Status> {
        crate::storage::delete_os_image(self, request).await
    }

    async fn update_os_image(
        &self,
        request: Request<forge::OsImageAttributes>,
    ) -> Result<Response<forge::OsImage>, Status> {
        crate::storage::update_os_image(self, request).await
    }
    async fn get_machine_validation_runs(
        &self,
        request: Request<forge::MachineValidationRunListGetRequest>,
    ) -> Result<Response<forge::MachineValidationRunList>, Status> {
        crate::handlers::machine_validation::get_machine_validation_runs(self, request).await
    }

    async fn admin_power_control(
        &self,
        request: Request<forge::AdminPowerControlRequest>,
    ) -> Result<Response<forge::AdminPowerControlResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::admin_power_control(self, request).await
    }

    async fn on_demand_machine_validation(
        &self,
        request: Request<forge::MachineValidationOnDemandRequest>,
    ) -> Result<Response<forge::MachineValidationOnDemandResponse>, Status> {
        crate::handlers::machine_validation::on_demand_machine_validation(self, request).await
    }

    async fn tpm_add_ca_cert(
        &self,
        request: Request<forge::TpmCaCert>,
    ) -> Result<Response<forge::TpmCaAddedCaStatus>, Status> {
        crate::handlers::tpm_ca::tpm_add_ca_cert(self, request).await
    }

    async fn tpm_show_ca_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::TpmCaCertDetailCollection>, Status> {
        crate::handlers::tpm_ca::tpm_show_ca_certs(self, &request).await
    }

    async fn tpm_show_unmatched_ek_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::TpmEkCertStatusCollection>, Status> {
        crate::handlers::tpm_ca::tpm_show_unmatched_ek_certs(self, &request).await
    }

    async fn tpm_delete_ca_cert(
        &self,
        request: Request<forge::TpmCaCertId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::tpm_ca::tpm_delete_ca_cert(self, request).await
    }

    async fn remove_machine_validation_external_config(
        &self,
        request: Request<forge::RemoveMachineValidationExternalConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::remove_machine_validation_external_config(
            self, request,
        )
        .await
    }

    async fn get_machine_validation_tests(
        &self,
        request: Request<forge::MachineValidationTestsGetRequest>,
    ) -> Result<Response<forge::MachineValidationTestsGetResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_tests(self, request).await
    }

    async fn update_machine_validation_test(
        &self,
        request: Request<forge::MachineValidationTestUpdateRequest>,
    ) -> Result<Response<forge::MachineValidationTestAddUpdateResponse>, Status> {
        crate::handlers::machine_validation::update_machine_validation_test(self, request).await
    }
    async fn add_machine_validation_test(
        &self,
        request: Request<forge::MachineValidationTestAddRequest>,
    ) -> Result<Response<forge::MachineValidationTestAddUpdateResponse>, Status> {
        crate::handlers::machine_validation::add_machine_validation_test(self, request).await
    }

    async fn machine_validation_test_verfied(
        &self,
        request: Request<forge::MachineValidationTestVerfiedRequest>,
    ) -> Result<Response<forge::MachineValidationTestVerfiedResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_verfied(self, request).await
    }

    async fn machine_validation_test_next_version(
        &self,
        request: Request<forge::MachineValidationTestNextVersionRequest>,
    ) -> Result<Response<forge::MachineValidationTestNextVersionResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_next_version(self, request)
            .await
    }

    async fn machine_validation_test_enable_disable_test(
        &self,
        request: Request<forge::MachineValidationTestEnableDisableTestRequest>,
    ) -> Result<Response<forge::MachineValidationTestEnableDisableTestResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_enable_disable_test(
            self, request,
        )
        .await
    }
    async fn update_machine_validation_run(
        &self,
        request: Request<forge::MachineValidationRunRequest>,
    ) -> Result<Response<forge::MachineValidationRunResponse>, Status> {
        crate::handlers::machine_validation::update_machine_validation_run(self, request).await
    }

    async fn create_instance_type(
        &self,
        request: Request<forge::CreateInstanceTypeRequest>,
    ) -> Result<Response<forge::CreateInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::create(self, request).await
    }

    async fn find_instance_type_ids(
        &self,
        request: Request<forge::FindInstanceTypeIdsRequest>,
    ) -> Result<Response<forge::FindInstanceTypeIdsResponse>, Status> {
        crate::handlers::instance_type::find_ids(self, request).await
    }

    async fn find_instance_types_by_ids(
        &self,
        request: Request<forge::FindInstanceTypesByIdsRequest>,
    ) -> Result<Response<forge::FindInstanceTypesByIdsResponse>, Status> {
        crate::handlers::instance_type::find_by_ids(self, request).await
    }

    async fn delete_instance_type(
        &self,
        request: Request<forge::DeleteInstanceTypeRequest>,
    ) -> Result<Response<forge::DeleteInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::delete(self, request).await
    }

    async fn update_instance_type(
        &self,
        request: Request<forge::UpdateInstanceTypeRequest>,
    ) -> Result<Response<forge::UpdateInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::update(self, request).await
    }

    async fn associate_machines_with_instance_type(
        &self,
        request: Request<forge::AssociateMachinesWithInstanceTypeRequest>,
    ) -> Result<Response<forge::AssociateMachinesWithInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::associate_machines(self, request).await
    }

    async fn remove_machine_instance_type_association(
        &self,
        request: Request<forge::RemoveMachineInstanceTypeAssociationRequest>,
    ) -> Result<Response<forge::RemoveMachineInstanceTypeAssociationResponse>, Status> {
        crate::handlers::instance_type::remove_machine_association(self, request).await
    }

    async fn redfish_browse(
        &self,
        request: Request<forge::RedfishBrowseRequest>,
    ) -> Result<Response<forge::RedfishBrowseResponse>, Status> {
        crate::handlers::redfish::redfish_browse(self, request).await
    }

    async fn redfish_list_actions(
        &self,
        request: Request<forge::RedfishListActionsRequest>,
    ) -> Result<Response<forge::RedfishListActionsResponse>, Status> {
        crate::handlers::redfish::redfish_list_actions(self, request).await
    }

    async fn redfish_create_action(
        &self,
        request: Request<forge::RedfishCreateActionRequest>,
    ) -> Result<Response<forge::RedfishCreateActionResponse>, Status> {
        crate::handlers::redfish::redfish_create_action(self, request).await
    }

    async fn redfish_approve_action(
        &self,
        request: Request<forge::RedfishActionId>,
    ) -> Result<Response<forge::RedfishApproveActionResponse>, Status> {
        crate::handlers::redfish::redfish_approve_action(self, request).await
    }
    async fn redfish_apply_action(
        &self,
        request: Request<forge::RedfishActionId>,
    ) -> Result<Response<forge::RedfishApplyActionResponse>, Status> {
        crate::handlers::redfish::redfish_apply_action(self, request).await
    }

    async fn redfish_cancel_action(
        &self,
        request: Request<forge::RedfishActionId>,
    ) -> Result<Response<forge::RedfishCancelActionResponse>, Status> {
        crate::handlers::redfish::redfish_cancel_action(self, request).await
    }

    async fn ufm_browse(
        &self,
        request: Request<forge::UfmBrowseRequest>,
    ) -> Result<Response<forge::UfmBrowseResponse>, Status> {
        crate::handlers::ib_fabric::ufm_browse(self, request).await
    }

    async fn create_network_security_group(
        &self,
        request: Request<forge::CreateNetworkSecurityGroupRequest>,
    ) -> Result<Response<forge::CreateNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::create(self, request).await
    }

    async fn find_network_security_group_ids(
        &self,
        request: Request<forge::FindNetworkSecurityGroupIdsRequest>,
    ) -> Result<Response<forge::FindNetworkSecurityGroupIdsResponse>, Status> {
        crate::handlers::network_security_group::find_ids(self, request).await
    }

    async fn find_network_security_groups_by_ids(
        &self,
        request: Request<forge::FindNetworkSecurityGroupsByIdsRequest>,
    ) -> Result<Response<forge::FindNetworkSecurityGroupsByIdsResponse>, Status> {
        crate::handlers::network_security_group::find_by_ids(self, request).await
    }

    async fn delete_network_security_group(
        &self,
        request: Request<forge::DeleteNetworkSecurityGroupRequest>,
    ) -> Result<Response<forge::DeleteNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::delete(self, request).await
    }

    async fn update_network_security_group(
        &self,
        request: Request<forge::UpdateNetworkSecurityGroupRequest>,
    ) -> Result<Response<forge::UpdateNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::update(self, request).await
    }

    async fn get_network_security_group_propagation_status(
        &self,
        request: Request<forge::GetNetworkSecurityGroupPropagationStatusRequest>,
    ) -> Result<Response<forge::GetNetworkSecurityGroupPropagationStatusResponse>, Status> {
        crate::handlers::network_security_group::get_propagation_status(self, request).await
    }

    async fn get_network_security_group_attachments(
        &self,
        request: Request<forge::GetNetworkSecurityGroupAttachmentsRequest>,
    ) -> Result<Response<forge::GetNetworkSecurityGroupAttachmentsResponse>, Status> {
        crate::handlers::network_security_group::get_attachments(self, request).await
    }
    async fn create_compute_allocation(
        &self,
        request: tonic::Request<forge::CreateComputeAllocationRequest>,
    ) -> Result<tonic::Response<forge::CreateComputeAllocationResponse>, Status> {
        crate::handlers::compute_allocation::create(self, request).await
    }
    async fn find_compute_allocation_ids(
        &self,
        request: tonic::Request<forge::FindComputeAllocationIdsRequest>,
    ) -> Result<tonic::Response<forge::FindComputeAllocationIdsResponse>, Status> {
        crate::handlers::compute_allocation::find_ids(self, request).await
    }
    async fn find_compute_allocations_by_ids(
        &self,
        request: tonic::Request<forge::FindComputeAllocationsByIdsRequest>,
    ) -> Result<tonic::Response<forge::FindComputeAllocationsByIdsResponse>, Status> {
        crate::handlers::compute_allocation::find_by_ids(self, request).await
    }
    async fn delete_compute_allocation(
        &self,
        request: tonic::Request<forge::DeleteComputeAllocationRequest>,
    ) -> Result<tonic::Response<forge::DeleteComputeAllocationResponse>, Status> {
        crate::handlers::compute_allocation::delete(self, request).await
    }
    async fn update_compute_allocation(
        &self,
        request: tonic::Request<forge::UpdateComputeAllocationRequest>,
    ) -> Result<tonic::Response<forge::UpdateComputeAllocationResponse>, Status> {
        crate::handlers::compute_allocation::update(self, request).await
    }
    async fn get_desired_firmware_versions(
        &self,
        request: Request<forge::GetDesiredFirmwareVersionsRequest>,
    ) -> Result<Response<forge::GetDesiredFirmwareVersionsResponse>, Status> {
        crate::handlers::firmware::get_desired_firmware_versions(self, request)
    }

    async fn create_sku(
        &self,
        request: Request<forge::SkuList>,
    ) -> Result<Response<forge::SkuIdList>, Status> {
        crate::handlers::sku::create(self, request).await
    }

    async fn delete_sku(&self, request: Request<SkuIdList>) -> Result<Response<()>, Status> {
        crate::handlers::sku::delete(self, request).await
    }

    async fn generate_sku_from_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<forge::Sku>, Status> {
        crate::handlers::sku::generate_from_machine(self, request).await
    }

    async fn verify_sku_for_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::sku::verify_for_machine(self, request).await
    }

    async fn assign_sku_to_machine(
        &self,
        request: Request<forge::SkuMachinePair>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::sku::assign_to_machine(self, request).await
    }

    async fn remove_sku_association(
        &self,
        request: Request<RemoveSkuRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::sku::remove_sku_association(self, request).await
    }

    async fn get_all_sku_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::SkuIdList>, Status> {
        crate::handlers::sku::get_all_ids(self, request).await
    }

    async fn find_skus_by_ids(
        &self,
        request: Request<forge::SkusByIdsRequest>,
    ) -> Result<Response<forge::SkuList>, Status> {
        crate::handlers::sku::find_skus_by_ids(self, request).await
    }

    async fn update_sku_metadata(
        &self,
        request: Request<forge::SkuUpdateMetadataRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::sku::update_sku_metadata(self, request).await
    }

    async fn replace_sku(
        &self,
        request: Request<forge::Sku>,
    ) -> Result<Response<forge::Sku>, Status> {
        crate::handlers::sku::replace_sku(self, request).await
    }

    async fn set_managed_host_quarantine_state(
        &self,
        request: Request<forge::SetManagedHostQuarantineStateRequest>,
    ) -> Result<Response<forge::SetManagedHostQuarantineStateResponse>, Status> {
        crate::handlers::machine_quarantine::set_managed_host_quarantine_state(self, request).await
    }

    async fn get_managed_host_quarantine_state(
        &self,
        request: Request<forge::GetManagedHostQuarantineStateRequest>,
    ) -> Result<Response<forge::GetManagedHostQuarantineStateResponse>, Status> {
        crate::handlers::machine_quarantine::get_managed_host_quarantine_state(self, request).await
    }

    async fn clear_managed_host_quarantine_state(
        &self,
        request: Request<forge::ClearManagedHostQuarantineStateRequest>,
    ) -> Result<Response<forge::ClearManagedHostQuarantineStateResponse>, Status> {
        crate::handlers::machine_quarantine::clear_managed_host_quarantine_state(self, request)
            .await
    }

    async fn reset_host_reprovisioning(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::host_reprovisioning::reset_host_reprovisioning(self, request).await
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        request: Request<forge::CopyBfbToDpuRshimRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::bmc_endpoint_explorer::copy_bfb_to_dpu_rshim(self, request).await
    }

    async fn find_nv_link_partition_ids(
        &self,
        request: Request<forge::NvLinkPartitionSearchFilter>,
    ) -> Result<Response<forge::NvLinkPartitionIdList>, Status> {
        crate::handlers::nvl_partition::find_ids(self, request).await
    }

    async fn find_nv_link_partitions_by_ids(
        &self,
        request: Request<forge::NvLinkPartitionsByIdsRequest>,
    ) -> Result<Response<forge::NvLinkPartitionList>, Status> {
        crate::handlers::nvl_partition::find_by_ids(self, request).await
    }

    async fn nv_link_partitions_for_tenant(
        &self,
        request: Request<forge::TenantSearchQuery>,
    ) -> Result<Response<forge::NvLinkPartitionList>, Status> {
        crate::handlers::nvl_partition::for_tenant(self, request).await
    }

    async fn find_nv_link_logical_partition_ids(
        &self,
        request: Request<forge::NvLinkLogicalPartitionSearchFilter>,
    ) -> Result<Response<forge::NvLinkLogicalPartitionIdList>, Status> {
        crate::handlers::logical_partition::find_ids(self, request).await
    }

    async fn find_nv_link_logical_partitions_by_ids(
        &self,
        request: Request<forge::NvLinkLogicalPartitionsByIdsRequest>,
    ) -> Result<Response<forge::NvLinkLogicalPartitionList>, Status> {
        crate::handlers::logical_partition::find_by_ids(self, request).await
    }

    async fn create_nv_link_logical_partition(
        &self,
        request: Request<forge::NvLinkLogicalPartitionCreationRequest>,
    ) -> Result<Response<forge::NvLinkLogicalPartition>, Status> {
        crate::handlers::logical_partition::create(self, request).await
    }

    async fn delete_nv_link_logical_partition(
        &self,
        request: Request<forge::NvLinkLogicalPartitionDeletionRequest>,
    ) -> Result<Response<forge::NvLinkLogicalPartitionDeletionResult>, Status> {
        crate::handlers::logical_partition::delete(self, request).await
    }

    async fn nv_link_logical_partitions_for_tenant(
        &self,
        request: Request<forge::TenantSearchQuery>,
    ) -> Result<Response<forge::NvLinkLogicalPartitionList>, Status> {
        crate::handlers::logical_partition::for_tenant(self, request).await
    }

    async fn update_nv_link_logical_partition(
        &self,
        request: Request<forge::NvLinkLogicalPartitionUpdateRequest>,
    ) -> Result<Response<forge::NvLinkLogicalPartitionUpdateResult>, Status> {
        crate::handlers::logical_partition::update(self, request).await
    }

    async fn nmxm_browse(
        &self,
        request: Request<forge::NmxmBrowseRequest>,
    ) -> Result<Response<forge::NmxmBrowseResponse>, Status> {
        crate::handlers::nvl_partition::nmxm_browse(self, request).await
    }

    // Return a Vector of all the DPA interface IDs
    async fn get_all_dpa_interface_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::DpaInterfaceIdList>, Status> {
        crate::handlers::dpa::get_all_ids(self, request).await
    }

    // Given a Vector of DPA Interface IDs, return the corresponding
    // DPA Interfaces in a Vector
    async fn find_dpa_interfaces_by_ids(
        &self,
        request: Request<forge::DpaInterfacesByIdsRequest>,
    ) -> Result<Response<forge::DpaInterfaceList>, Status> {
        crate::handlers::dpa::find_dpa_interfaces_by_ids(self, request).await
    }

    async fn ensure_dpa_interface(
        &self,
        request: Request<forge::DpaInterfaceCreationRequest>,
    ) -> Result<Response<forge::DpaInterface>, Status> {
        crate::handlers::dpa::ensure(self, request).await
    }

    // create_dpa_interface is mainly for debugging purposes. In practice,
    // when the scout reports its inventory, we will create DPA interfaces
    // for DPA NICs reported in the inventory.
    async fn create_dpa_interface(
        &self,
        request: Request<forge::DpaInterfaceCreationRequest>,
    ) -> Result<Response<forge::DpaInterface>, Status> {
        crate::handlers::dpa::create(self, request).await
    }

    // delete_dpa_interface is mainly for debugging purposes.
    async fn delete_dpa_interface(
        &self,
        request: Request<forge::DpaInterfaceDeletionRequest>,
    ) -> Result<Response<forge::DpaInterfaceDeletionResult>, Status> {
        crate::handlers::dpa::delete(self, request).await
    }

    // set_dpa_network_observaction_status is for debugging purposes.
    // In practice, the MQTT subscriber running in Carbide will update
    // the observation status
    async fn set_dpa_network_observation_status(
        &self,
        request: Request<forge::DpaNetworkObservationSetRequest>,
    ) -> Result<Response<forge::DpaInterface>, Status> {
        crate::handlers::dpa::set_dpa_network_observation_status(self, request).await
    }

    async fn create_bmc_user(
        &self,
        request: Request<forge::CreateBmcUserRequest>,
    ) -> Result<Response<forge::CreateBmcUserResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::create_bmc_user(self, request).await
    }

    async fn delete_bmc_user(
        &self,
        request: Request<forge::DeleteBmcUserRequest>,
    ) -> Result<Response<forge::DeleteBmcUserResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::delete_bmc_user(self, request).await
    }

    async fn set_firmware_update_time_window(
        &self,
        request: Request<forge::SetFirmwareUpdateTimeWindowRequest>,
    ) -> Result<Response<forge::SetFirmwareUpdateTimeWindowResponse>, Status> {
        crate::handlers::firmware::set_firmware_update_time_window(self, request).await
    }

    async fn list_host_firmware(
        &self,
        request: Request<forge::ListHostFirmwareRequest>,
    ) -> Result<Response<forge::ListHostFirmwareResponse>, Status> {
        crate::handlers::firmware::list_host_firmware(self, request)
    }

    // Scout is telling Carbide the mlx device configuration in its machine
    async fn publish_mlx_device_report(
        &self,
        request: Request<mlx_device_pb::PublishMlxDeviceReportRequest>,
    ) -> Result<Response<mlx_device_pb::PublishMlxDeviceReportResponse>, Status> {
        crate::handlers::dpa::publish_mlx_device_report(self, request).await
    }

    // Scout is telling carbide the observed status (locking status, card mode) of the
    // mlx devices in its host
    async fn publish_mlx_observation_report(
        &self,
        request: Request<mlx_device_pb::PublishMlxObservationReportRequest>,
    ) -> Result<Response<mlx_device_pb::PublishMlxObservationReportResponse>, Status> {
        crate::handlers::dpa::publish_mlx_observation_report(self, request).await
    }

    async fn trim_table(
        &self,
        request: Request<forge::TrimTableRequest>,
    ) -> Result<Response<forge::TrimTableResponse>, Status> {
        crate::handlers::db::trim_table(self, request).await
    }

    async fn create_remediation(
        &self,
        request: Request<forge::CreateRemediationRequest>,
    ) -> Result<Response<forge::CreateRemediationResponse>, Status> {
        crate::handlers::dpu_remediation::create(self, request).await
    }

    async fn approve_remediation(
        &self,
        request: Request<forge::ApproveRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::approve(self, request).await
    }

    async fn revoke_remediation(
        &self,
        request: Request<forge::RevokeRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::revoke(self, request).await
    }

    async fn enable_remediation(
        &self,
        request: Request<forge::EnableRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::enable(self, request).await
    }

    async fn disable_remediation(
        &self,
        request: Request<forge::DisableRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::disable(self, request).await
    }

    async fn find_remediation_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<forge::RemediationIdList>, Status> {
        crate::handlers::dpu_remediation::find_remediation_ids(self, request).await
    }

    async fn find_remediations_by_ids(
        &self,
        request: Request<forge::RemediationIdList>,
    ) -> Result<Response<forge::RemediationList>, Status> {
        crate::handlers::dpu_remediation::find_remediations_by_ids(self, request).await
    }

    async fn find_applied_remediation_ids(
        &self,
        request: Request<forge::FindAppliedRemediationIdsRequest>,
    ) -> Result<Response<forge::AppliedRemediationIdList>, Status> {
        crate::handlers::dpu_remediation::find_applied_remediation_ids(self, request).await
    }

    async fn find_applied_remediations(
        &self,
        request: Request<forge::FindAppliedRemediationsRequest>,
    ) -> Result<Response<forge::AppliedRemediationList>, Status> {
        crate::handlers::dpu_remediation::find_applied_remediations(self, request).await
    }

    async fn get_next_remediation_for_machine(
        &self,
        request: Request<forge::GetNextRemediationForMachineRequest>,
    ) -> Result<Response<forge::GetNextRemediationForMachineResponse>, Status> {
        crate::handlers::dpu_remediation::get_next_remediation_for_machine(self, request).await
    }

    async fn remediation_applied(
        &self,
        request: Request<forge::RemediationAppliedRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::remediation_applied(self, request).await
    }

    async fn set_primary_dpu(
        &self,
        request: Request<forge::SetPrimaryDpuRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::managed_host::set_primary_dpu(self, request).await
    }

    async fn create_dpu_extension_service(
        &self,
        request: Request<forge::CreateDpuExtensionServiceRequest>,
    ) -> Result<Response<forge::DpuExtensionService>, Status> {
        crate::handlers::extension_service::create(self, request).await
    }

    async fn update_dpu_extension_service(
        &self,
        request: Request<forge::UpdateDpuExtensionServiceRequest>,
    ) -> Result<Response<forge::DpuExtensionService>, Status> {
        crate::handlers::extension_service::update(self, request).await
    }

    async fn delete_dpu_extension_service(
        &self,
        request: Request<forge::DeleteDpuExtensionServiceRequest>,
    ) -> Result<Response<forge::DeleteDpuExtensionServiceResponse>, Status> {
        crate::handlers::extension_service::delete(self, request).await
    }

    async fn find_dpu_extension_service_ids(
        &self,
        request: Request<forge::DpuExtensionServiceSearchFilter>,
    ) -> Result<Response<forge::DpuExtensionServiceIdList>, Status> {
        crate::handlers::extension_service::find_ids(self, request).await
    }

    async fn find_dpu_extension_services_by_ids(
        &self,
        request: Request<forge::DpuExtensionServicesByIdsRequest>,
    ) -> Result<Response<forge::DpuExtensionServiceList>, Status> {
        crate::handlers::extension_service::find_by_ids(self, request).await
    }

    async fn get_dpu_extension_service_versions_info(
        &self,
        request: Request<forge::GetDpuExtensionServiceVersionsInfoRequest>,
    ) -> Result<Response<forge::DpuExtensionServiceVersionInfoList>, Status> {
        crate::handlers::extension_service::get_versions_info(self, request).await
    }

    async fn find_instances_by_dpu_extension_service(
        &self,
        request: Request<forge::FindInstancesByDpuExtensionServiceRequest>,
    ) -> Result<Response<forge::FindInstancesByDpuExtensionServiceResponse>, Status> {
        crate::handlers::extension_service::find_instances_by_extension_service(self, request).await
    }

    async fn trigger_machine_attestation(
        &self,
        request: tonic::Request<forge::AttestationData>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::attestation::trigger_machine_attestation(self, request).await
    }

    async fn cancel_machine_attestation(
        &self,
        request: tonic::Request<forge::AttestationData>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::attestation::cancel_machine_attestation(self, request).await
    }

    async fn find_machines_under_attestation(
        &self,
        request: tonic::Request<forge::AttestationMachineList>,
    ) -> Result<tonic::Response<forge::AttestationResponse>, Status> {
        crate::handlers::attestation::list_machines_under_attestation(self, request).await
    }

    async fn find_machine_ids_under_attestation(
        &self,
        request: tonic::Request<forge::AttestationIdsRequest>,
    ) -> Result<Response<nico_rpc::common::MachineIdList>, Status> {
        crate::handlers::attestation::list_machine_ids_under_attestation(self, request).await
    }

    async fn sign_machine_identity(
        &self,
        _request: tonic::Request<forge::MachineIdentityRequest>,
    ) -> Result<Response<forge::MachineIdentityResponse>, Status> {
        // TODO: enable after implementing this function fully
        //return crate::handlers::machine_identity::sign_machine_identity(self, request).await;
        Err(tonic::Status::unimplemented(
            "machine identity API is temporarily disabled",
        ))
    }

    async fn get_identity_configuration(
        &self,
        request: Request<forge::GetIdentityConfigRequest>,
    ) -> Result<Response<forge::IdentityConfigResponse>, Status> {
        crate::handlers::identity_config::get_identity_configuration(self, request).await
    }

    async fn set_identity_configuration(
        &self,
        request: tonic::Request<forge::IdentityConfigRequest>,
    ) -> Result<Response<forge::IdentityConfigResponse>, Status> {
        crate::handlers::identity_config::set_identity_configuration(self, request).await
    }

    async fn delete_identity_configuration(
        &self,
        request: Request<forge::GetIdentityConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::identity_config::delete_identity_configuration(self, request).await
    }

    async fn get_token_delegation(
        &self,
        request: Request<forge::GetTokenDelegationRequest>,
    ) -> Result<Response<forge::TokenDelegationResponse>, Status> {
        crate::handlers::identity_config::get_token_delegation(self, request).await
    }

    async fn set_token_delegation(
        &self,
        request: Request<forge::TokenDelegationRequest>,
    ) -> Result<Response<forge::TokenDelegationResponse>, Status> {
        crate::handlers::identity_config::set_token_delegation(self, request).await
    }

    async fn delete_token_delegation(
        &self,
        request: Request<forge::GetTokenDelegationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::identity_config::delete_token_delegation(self, request).await
    }

    async fn modify_dpf_state(
        &self,
        request: Request<forge::ModifyDpfStateRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpf::modify_dpf_state(self, request).await
    }

    async fn get_dpf_state(
        &self,
        request: Request<forge::GetDpfStateRequest>,
    ) -> Result<Response<forge::DpfStateResponse>, Status> {
        crate::handlers::dpf::get_dpf_state(self, request).await
    }

    // scout_stream handles the bidirectional streaming connection from scout agents.
    // scout agents call scout_stream and send an Init message, and then carbide-api
    // will send down "request" messages to connected agent(s) to either instruct them
    // or ask them for information (sometimes for state changes, other times for
    // feeding data back to administrative CLI/UI calls).
    async fn scout_stream(
        &self,
        request: Request<Streaming<forge::ScoutStreamApiBoundMessage>>,
    ) -> Result<Response<Self::ScoutStreamStream>, Status> {
        crate::handlers::scout_stream::scout_stream(self, request).await
    }

    // scout_stream_show_connections lists all active scout agent
    // connections by building up some ScoutStreamConnectionInfo
    // messages using the data from the scout_stream_registry.
    async fn scout_stream_show_connections(
        &self,
        request: Request<forge::ScoutStreamShowConnectionsRequest>,
    ) -> Result<Response<forge::ScoutStreamShowConnectionsResponse>, Status> {
        crate::handlers::scout_stream::show_connections(self, request).await
    }

    // scout_stream_disconnect is used to disconnect the
    // given MachineId's ScoutStream connection.
    async fn scout_stream_disconnect(
        &self,
        request: Request<forge::ScoutStreamDisconnectRequest>,
    ) -> Result<Response<forge::ScoutStreamDisconnectResponse>, Status> {
        crate::handlers::scout_stream::disconnect(self, request).await
    }

    // scout_stream_ping is used to ping the
    // given MachineId's ScoutStream connection.
    async fn scout_stream_ping(
        &self,
        request: Request<forge::ScoutStreamAdminPingRequest>,
    ) -> Result<Response<forge::ScoutStreamAdminPingResponse>, Status> {
        crate::handlers::scout_stream::ping(self, request).await
    }

    async fn mlx_admin_profile_sync(
        &self,
        request: Request<mlx_device_pb::MlxAdminProfileSyncRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminProfileSyncResponse>, Status> {
        crate::handlers::mlx_admin::profile_sync(self, request).await
    }

    async fn mlx_admin_profile_show(
        &self,
        request: Request<mlx_device_pb::MlxAdminProfileShowRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminProfileShowResponse>, Status> {
        crate::handlers::mlx_admin::profile_show(self, request)
    }

    async fn mlx_admin_profile_compare(
        &self,
        request: Request<mlx_device_pb::MlxAdminProfileCompareRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminProfileCompareResponse>, Status> {
        crate::handlers::mlx_admin::profile_compare(self, request).await
    }

    async fn mlx_admin_profile_list(
        &self,
        request: Request<mlx_device_pb::MlxAdminProfileListRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminProfileListResponse>, Status> {
        crate::handlers::mlx_admin::profile_list(self, request)
    }

    async fn mlx_admin_lockdown_lock(
        &self,
        request: Request<mlx_device_pb::MlxAdminLockdownLockRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminLockdownLockResponse>, Status> {
        crate::handlers::mlx_admin::lockdown_lock(self, request).await
    }

    async fn mlx_admin_lockdown_unlock(
        &self,
        request: Request<mlx_device_pb::MlxAdminLockdownUnlockRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminLockdownUnlockResponse>, Status> {
        crate::handlers::mlx_admin::lockdown_unlock(self, request).await
    }

    async fn mlx_admin_lockdown_status(
        &self,
        request: Request<mlx_device_pb::MlxAdminLockdownStatusRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminLockdownStatusResponse>, Status> {
        crate::handlers::mlx_admin::lockdown_status(self, request).await
    }

    async fn mlx_admin_show_device(
        &self,
        request: Request<mlx_device_pb::MlxAdminDeviceInfoRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminDeviceInfoResponse>, Status> {
        crate::handlers::mlx_admin::show_device_info(self, request).await
    }

    async fn mlx_admin_show_machine(
        &self,
        request: Request<mlx_device_pb::MlxAdminDeviceReportRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminDeviceReportResponse>, Status> {
        crate::handlers::mlx_admin::show_device_report(self, request).await
    }

    async fn mlx_admin_registry_list(
        &self,
        request: Request<mlx_device_pb::MlxAdminRegistryListRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminRegistryListResponse>, Status> {
        crate::handlers::mlx_admin::registry_list(self, request).await
    }

    async fn mlx_admin_registry_show(
        &self,
        request: Request<mlx_device_pb::MlxAdminRegistryShowRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminRegistryShowResponse>, Status> {
        crate::handlers::mlx_admin::registry_show(self, request).await
    }

    async fn mlx_admin_config_query(
        &self,
        request: Request<mlx_device_pb::MlxAdminConfigQueryRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminConfigQueryResponse>, Status> {
        crate::handlers::mlx_admin::config_query(self, request).await
    }

    async fn mlx_admin_config_set(
        &self,
        request: Request<mlx_device_pb::MlxAdminConfigSetRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminConfigSetResponse>, Status> {
        crate::handlers::mlx_admin::config_set(self, request).await
    }

    async fn mlx_admin_config_sync(
        &self,
        request: Request<mlx_device_pb::MlxAdminConfigSyncRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminConfigSyncResponse>, Status> {
        crate::handlers::mlx_admin::config_sync(self, request).await
    }

    async fn mlx_admin_config_compare(
        &self,
        request: Request<mlx_device_pb::MlxAdminConfigCompareRequest>,
    ) -> Result<Response<mlx_device_pb::MlxAdminConfigCompareResponse>, Status> {
        crate::handlers::mlx_admin::config_compare(self, request).await
    }

    async fn get_machine_position_info(
        &self,
        request: Request<forge::MachinePositionQuery>,
    ) -> Result<Response<forge::MachinePositionInfoList>, Status> {
        crate::handlers::machine::get_machine_position_info(self, request).await
    }

    async fn determine_machine_ingestion_state(
        &self,
        request: tonic::Request<forge::BmcEndpointRequest>,
    ) -> Result<tonic::Response<forge::MachineIngestionStateResponse>, Status> {
        crate::api::log_request_data(&request);

        crate::handlers::power_options::determine_machine_ingestion_state(
            self,
            &request.into_inner(),
        )
        .await
    }

    async fn allow_ingestion_and_power_on(
        &self,
        request: tonic::Request<forge::BmcEndpointRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::api::log_request_data(&request);

        crate::handlers::power_options::allow_ingestion_and_power_on(self, &request.into_inner())
            .await
    }

    async fn component_power_control(
        &self,
        request: Request<forge::ComponentPowerControlRequest>,
    ) -> Result<Response<forge::ComponentPowerControlResponse>, Status> {
        crate::handlers::component_manager::component_power_control(self, request).await
    }

    async fn get_component_inventory(
        &self,
        request: Request<forge::GetComponentInventoryRequest>,
    ) -> Result<Response<forge::GetComponentInventoryResponse>, Status> {
        crate::handlers::component_manager::get_component_inventory(self, request).await
    }

    async fn update_component_firmware(
        &self,
        request: Request<forge::UpdateComponentFirmwareRequest>,
    ) -> Result<Response<forge::UpdateComponentFirmwareResponse>, Status> {
        crate::handlers::component_manager::update_component_firmware(self, request).await
    }

    async fn get_component_firmware_status(
        &self,
        request: Request<forge::GetComponentFirmwareStatusRequest>,
    ) -> Result<Response<forge::GetComponentFirmwareStatusResponse>, Status> {
        crate::handlers::component_manager::get_component_firmware_status(self, request).await
    }

    async fn list_component_firmware_versions(
        &self,
        request: Request<forge::ListComponentFirmwareVersionsRequest>,
    ) -> Result<Response<forge::ListComponentFirmwareVersionsResponse>, Status> {
        crate::handlers::component_manager::list_component_firmware_versions(self, request).await
    }
}

pub(crate) fn log_request_data<T: std::fmt::Debug>(request: &Request<T>) {
    tracing::Span::current().record(
        "request",
        truncate(
            format!("{:?}", request.get_ref()),
            nico_rpc::MAX_ERR_MSG_SIZE as usize,
        ),
    );
}

/// Logs a pre-redacted request string (e.g. for requests containing secrets).
pub(crate) fn log_request_data_redacted(s: impl AsRef<str>) {
    tracing::Span::current().record(
        "request",
        truncate(s.as_ref().to_string(), nico_rpc::MAX_ERR_MSG_SIZE as usize),
    );
}

/// Logs the Machine ID in the current tracing span
pub(crate) fn log_machine_id(machine_id: &MachineId) {
    tracing::Span::current().record("forge.machine_id", machine_id.to_string());
}

pub(crate) fn log_tenant_organization_id(organization_id: &str) {
    tracing::Span::current().record("tenant.organization_id", organization_id);
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

pub trait TransactionVending {
    fn txn_begin(
        &self,
    ) -> impl Future<Output = Result<nico_api_db::Transaction<'_>, DatabaseError>>;
}

impl TransactionVending for PgPool {
    #[track_caller]
    // This returns an `impl Future` instead of being async, so that we can use #[track_caller],
    // which is unsupported with async fn's.
    fn txn_begin(
        &self,
    ) -> impl Future<Output = Result<nico_api_db::Transaction<'_>, DatabaseError>> {
        nico_api_db::Transaction::begin(self)
    }
}

impl Api {
    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn txn_begin(
        &self,
    ) -> impl Future<Output = Result<nico_api_db::Transaction<'_>, DatabaseError>> {
        let loc = Location::caller();
        nico_api_db::Transaction::begin_with_location(&self.database_connection, loc)
    }

    pub fn db_reader(&self) -> PgPoolReader {
        self.database_connection.clone().into()
    }

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub(crate) fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> impl Future<Output = CarbideResult<(Machine, nico_api_db::Transaction<'_>)>> {
        let loc = Location::caller();
        let machine_id = *machine_id;
        async move {
            let mut txn =
                nico_api_db::Transaction::begin_with_location(&self.database_connection, loc)
                    .await?;

            let machine =
                match nico_api_db::machine::find_one(&mut txn, &machine_id, search_config).await {
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
    }

    pub fn log_filter_string(&self) -> String {
        self.dynamic_settings.log_filter.to_string()
    }
}

impl WithTransaction for Api {
    #[track_caller]
    fn with_txn<'pool, T, E>(
        &'pool self,
        f: impl for<'txn> FnOnce(
            &'txn mut PgTransaction<'pool>,
        ) -> futures::future::BoxFuture<'txn, Result<T, E>>
        + Send,
    ) -> impl Future<Output = DatabaseResult<Result<T, E>>>
    where
        T: Send,
        E: Send,
    {
        self.database_connection.with_txn(f)
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
