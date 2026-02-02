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
use std::panic::Location;
use std::pin::Pin;
use std::sync::Arc;

pub use ::rpc::forge as rpc;
use ::rpc::forge::{RemoveSkuRequest, SkuIdList};
use ::rpc::protos::dns::{
    CreateDomainRequest, DnsResourceRecordLookupRequest, DnsResourceRecordLookupResponse, Domain,
    DomainDeletionRequest, DomainDeletionResult, DomainList, DomainMetadataRequest,
    DomainMetadataResponse, DomainSearchQuery, GetAllDomainsRequest, GetAllDomainsResponse,
    UpdateDomainRequest,
};
use ::rpc::protos::{measured_boot as measured_boot_pb, mlx_device as mlx_device_pb};
use carbide_dpf::KubeImpl;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use db::work_lock_manager::WorkLockManagerHandle;
use db::{DatabaseError, DatabaseResult, WithTransaction};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use model::machine::Machine;
use model::machine::machine_search_config::MachineSearchConfig;
use model::resource_pool::common::CommonPools;
use sqlx::{PgPool, PgTransaction};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use self::rpc::forge_server::Forge;
use crate::cfg::file::CarbideConfig;
use crate::dynamic_settings::DynamicSettings;
use crate::ethernet_virtualization::EthVirtData;
use crate::ib::IBFabricManager;
use crate::logging::log_limiter::LogLimiter;
use crate::nvlink::NmxmClientPool;
use crate::rack::rms_client::RmsApi;
use crate::redfish::RedfishClientPool;
use crate::scout_stream::ConnectionRegistry;
use crate::site_explorer::EndpointExplorer;
use crate::state_controller::controller::Enqueuer;
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::{CarbideError, CarbideResult};

pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    pub(crate) credential_provider: Arc<dyn CredentialProvider>,
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
    pub(crate) kube_client_provider: Arc<dyn KubeImpl>,
    pub(crate) machine_state_handler_enqueuer: Enqueuer<MachineStateControllerIO>,
}

pub(crate) type ScoutStreamType =
    Pin<Box<dyn Stream<Item = Result<rpc::ScoutStreamScoutBoundMessage, Status>> + Send>>;

#[tonic::async_trait]
impl Forge for Api {
    type ScoutStreamStream = ScoutStreamType;

    async fn version(
        &self,
        request: Request<rpc::VersionRequest>,
    ) -> Result<Response<rpc::BuildInfo>, Status> {
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
        request: Request<rpc::DomainLegacy>,
    ) -> Result<Response<rpc::DomainLegacy>, Status> {
        crate::handlers::domain::create_legacy_compat(self, request).await
    }

    async fn update_domain_legacy(
        &self,
        request: Request<rpc::DomainLegacy>,
    ) -> Result<Response<rpc::DomainLegacy>, Status> {
        crate::handlers::domain::update_legacy_compat(self, request).await
    }

    async fn delete_domain_legacy(
        &self,
        request: Request<rpc::DomainDeletionLegacy>,
    ) -> Result<Response<rpc::DomainDeletionResultLegacy>, Status> {
        crate::handlers::domain::delete_legacy_compat(self, request).await
    }

    async fn find_domain_legacy(
        &self,
        request: Request<rpc::DomainSearchQueryLegacy>,
    ) -> Result<Response<rpc::DomainListLegacy>, Status> {
        crate::handlers::domain::find_legacy_compat(self, request).await
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

    async fn create_vpc_peering(
        &self,
        request: Request<rpc::VpcPeeringCreationRequest>,
    ) -> Result<Response<rpc::VpcPeering>, Status> {
        crate::handlers::vpc_peering::create(self, request).await
    }

    async fn find_vpc_peering_ids(
        &self,
        request: Request<rpc::VpcPeeringSearchFilter>,
    ) -> Result<Response<rpc::VpcPeeringIdList>, Status> {
        crate::handlers::vpc_peering::find_ids(self, request).await
    }

    async fn find_vpc_peerings_by_ids(
        &self,
        request: Request<rpc::VpcPeeringsByIdsRequest>,
    ) -> Result<Response<rpc::VpcPeeringList>, Status> {
        crate::handlers::vpc_peering::find_by_ids(self, request).await
    }

    async fn delete_vpc_peering(
        &self,
        request: Request<rpc::VpcPeeringDeletionRequest>,
    ) -> Result<Response<rpc::VpcPeeringDeletionResult>, Status> {
        crate::handlers::vpc_peering::delete(self, request).await
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

    async fn find_power_shelves(
        &self,
        request: Request<rpc::PowerShelfQuery>,
    ) -> Result<Response<rpc::PowerShelfList>, Status> {
        crate::handlers::power_shelf::find_power_shelf(self, request).await
    }

    async fn delete_power_shelf(
        &self,
        request: Request<rpc::PowerShelfDeletionRequest>,
    ) -> Result<Response<rpc::PowerShelfDeletionResult>, Status> {
        crate::handlers::power_shelf::delete_power_shelf(self, request).await
    }

    async fn find_switches(
        &self,
        request: Request<rpc::SwitchQuery>,
    ) -> Result<Response<rpc::SwitchList>, Status> {
        crate::handlers::switch::find_switch(self, request).await
    }

    async fn delete_switch(
        &self,
        request: Request<rpc::SwitchDeletionRequest>,
    ) -> Result<Response<rpc::SwitchDeletionResult>, Status> {
        crate::handlers::switch::delete_switch(self, request).await
    }

    async fn find_ib_fabric_ids(
        &self,
        request: Request<rpc::IbFabricSearchFilter>,
    ) -> Result<Response<rpc::IbFabricIdList>, Status> {
        crate::handlers::ib_fabric::find_ids(self, request)
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

    async fn allocate_instances(
        &self,
        request: Request<rpc::BatchInstanceAllocationRequest>,
    ) -> Result<Response<rpc::BatchInstanceAllocationResponse>, Status> {
        crate::handlers::instance::batch_allocate(self, request).await
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

    async fn find_instance_by_machine_id(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        crate::handlers::instance::find_by_machine_id(self, request).await
    }

    async fn release_instance(
        &self,
        request: Request<rpc::InstanceReleaseRequest>,
    ) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
        crate::handlers::instance::release(self, request).await
    }

    async fn update_instance_phone_home_last_contact(
        &self,
        request: Request<rpc::InstancePhoneHomeLastContactRequest>,
    ) -> Result<Response<rpc::InstancePhoneHomeLastContactResponse>, Status> {
        crate::handlers::instance::update_phone_home_last_contact(self, request).await
    }

    async fn update_instance_operating_system(
        &self,
        request: Request<rpc::InstanceOperatingSystemUpdateRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        crate::handlers::instance::update_operating_system(self, request).await
    }

    async fn update_instance_config(
        &self,
        request: Request<rpc::InstanceConfigUpdateRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        crate::handlers::instance::update_instance_config(self, request).await
    }

    async fn get_managed_host_network_config(
        &self,
        request: Request<rpc::ManagedHostNetworkConfigRequest>,
    ) -> Result<Response<rpc::ManagedHostNetworkConfigResponse>, Status> {
        crate::handlers::dpu::get_managed_host_network_config(self, request).await
    }

    async fn update_agent_reported_inventory(
        &self,
        request: Request<rpc::DpuAgentInventoryReport>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::update_agent_reported_inventory(self, request).await
    }

    async fn record_dpu_network_status(
        &self,
        request: Request<rpc::DpuNetworkStatus>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::record_dpu_network_status(self, request).await
    }

    async fn record_hardware_health_report(
        &self,
        request: Request<rpc::HardwareHealthReport>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::record_hardware_health_report(self, request).await
    }

    async fn get_hardware_health_report(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::OptionalHealthReport>, Status> {
        crate::handlers::health::get_hardware_health_report(self, request).await
    }

    async fn record_log_parser_health_report(
        &self,
        request: Request<rpc::HardwareHealthReport>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::record_log_parser_health_report(self, request).await
    }

    async fn list_health_report_overrides(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::ListHealthReportOverrideResponse>, Status> {
        crate::handlers::health::list_health_report_overrides(self, request).await
    }

    async fn insert_health_report_override(
        &self,
        request: Request<rpc::InsertHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::insert_health_report_override(self, request).await
    }

    async fn remove_health_report_override(
        &self,
        request: Request<rpc::RemoveHealthReportOverrideRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::health::remove_health_report_override(self, request).await
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
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        crate::handlers::dns::lookup_record_legacy_compat(self, request).await
    }

    async fn invoke_instance_power(
        &self,
        request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        crate::handlers::instance::invoke_power(self, request).await
    }

    async fn echo(
        &self,
        request: Request<rpc::EchoRequest>,
    ) -> Result<Response<rpc::EchoResponse>, Status> {
        crate::handlers::api::echo(self, request)
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

    async fn find_tenants_by_organization_ids(
        &self,
        request: Request<rpc::TenantByOrganizationIdsRequest>,
    ) -> Result<Response<rpc::TenantList>, Status> {
        crate::handlers::tenant::find_tenants_by_organization_ids(self, request).await
    }

    async fn find_tenant_organization_ids(
        &self,
        request: Request<rpc::TenantSearchFilter>,
    ) -> Result<Response<rpc::TenantOrganizationIdList>, Status> {
        crate::handlers::tenant::find_tenant_organization_ids(self, request).await
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
        crate::handlers::credential::renew_machine_certificate(self, request).await
    }

    async fn discover_machine(
        &self,
        request: Request<rpc::MachineDiscoveryInfo>,
    ) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
        crate::handlers::machine_discovery::discover_machine(self, request).await
    }

    // Host has completed discovery
    async fn discovery_completed(
        &self,
        request: Request<rpc::MachineDiscoveryCompletedRequest>,
    ) -> Result<Response<rpc::MachineDiscoveryCompletedResponse>, Status> {
        crate::handlers::machine_discovery::discovery_completed(self, request).await
    }

    // Transitions the machine to Ready state.
    // Called by 'forge-scout discovery' once cleanup succeeds.
    async fn cleanup_machine_completed(
        &self,
        request: Request<rpc::MachineCleanupInfo>,
    ) -> Result<Response<rpc::MachineCleanupResult>, Status> {
        crate::handlers::machine_scout::cleanup_machine_completed(self, request).await
    }

    // Invoked by forge-scout whenever a certain Machine can not be properly acted on
    async fn report_forge_scout_error(
        &self,
        request: Request<rpc::ForgeScoutErrorReport>,
    ) -> Result<Response<rpc::ForgeScoutErrorReportResult>, Status> {
        crate::handlers::machine_scout::report_forge_scout_error(self, request)
    }

    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        log_request_data(&request);

        Ok(crate::dhcp::discover::discover_dhcp(
            self,
            request,
            Some(self.runtime_config.rack_management_enabled),
        )
        .await?)
    }

    async fn find_machine_ids(
        &self,
        request: Request<rpc::MachineSearchConfig>,
    ) -> Result<Response<::rpc::common::MachineIdList>, Status> {
        crate::handlers::machine::find_machine_ids(self, request).await
    }

    async fn find_machines_by_ids(
        &self,
        request: Request<::rpc::forge::MachinesByIdsRequest>,
    ) -> Result<Response<::rpc::MachineList>, Status> {
        crate::handlers::machine::find_machines_by_ids(self, request).await
    }

    async fn find_machine_state_histories(
        &self,
        request: Request<rpc::MachineStateHistoriesRequest>,
    ) -> std::result::Result<Response<rpc::MachineStateHistories>, Status> {
        crate::handlers::machine::find_machine_state_histories(self, request).await
    }

    async fn find_power_shelf_state_histories(
        &self,
        _request: Request<rpc::PowerShelfStateHistoriesRequest>,
    ) -> Result<Response<rpc::PowerShelfStateHistories>, Status> {
        Err(Status::unimplemented(
            "not implemented yet -- under construction",
        ))
    }

    async fn find_switch_state_histories(
        &self,
        _request: Request<rpc::SwitchStateHistoriesRequest>,
    ) -> Result<Response<rpc::SwitchStateHistories>, Status> {
        Err(Status::unimplemented(
            "not implemented yet -- under construction",
        ))
    }

    async fn find_machine_health_histories(
        &self,
        request: Request<rpc::MachineHealthHistoriesRequest>,
    ) -> std::result::Result<Response<rpc::MachineHealthHistories>, Status> {
        log_request_data(&request);
        let request_inner = request.into_inner();

        // Check if time range filtering is requested
        if let (Some(start_time), Some(end_time)) =
            (request_inner.start_time, request_inner.end_time)
        {
            // Time-filtered query path
            let machine_id = request_inner.machine_ids.first().ok_or_else(|| {
                CarbideError::InvalidArgument("machine_id is required".to_string())
            })?;

            // Convert protobuf timestamps to chrono DateTime
            let start_dt = chrono::DateTime::<chrono::Utc>::from_timestamp(
                start_time.seconds,
                start_time.nanos as u32,
            )
            .ok_or_else(|| {
                CarbideError::InvalidArgument("Invalid start_time timestamp".to_string())
            })?;
            let end_dt = chrono::DateTime::<chrono::Utc>::from_timestamp(
                end_time.seconds,
                end_time.nanos as u32,
            )
            .ok_or_else(|| {
                CarbideError::InvalidArgument("Invalid end_time timestamp".to_string())
            })?;

            // Start database transaction
            let mut txn = self.txn_begin().await?;

            // Call database function to get health history records with time filter
            let db_records = db::machine_health_history::find_by_time_range(
                &mut txn, machine_id, &start_dt, &end_dt,
            )
            .await?;

            // Convert database records to MachineHealthHistories format
            let response_records: Vec<rpc::MachineHealthHistoryRecord> = db_records
                .into_iter()
                .map(|db_rec| rpc::MachineHealthHistoryRecord {
                    health: Some(db_rec.health.into()),
                    time: Some(db_rec.time.into()),
                })
                .collect();

            // Put records in a map keyed by machine ID string
            let machine_id_str = machine_id.to_string();
            let mut histories = HashMap::new();
            histories.insert(
                machine_id_str,
                rpc::MachineHealthHistoryRecords {
                    records: response_records,
                },
            );

            txn.commit().await?;

            Ok(Response::new(rpc::MachineHealthHistories { histories }))
        } else {
            // Original behavior: no time filtering
            crate::handlers::machine::find_machine_health_histories(
                self,
                Request::new(request_inner),
            )
            .await
        }
    }

    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        crate::handlers::machine_interface::find_interfaces(self, request).await
    }

    async fn delete_interface(
        &self,
        request: Request<rpc::InterfaceDeleteQuery>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_interface::delete_interface(self, request).await
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

    async fn update_machine_credentials(
        &self,
        request: Request<rpc::MachineCredentialsUpdateRequest>,
    ) -> Result<Response<rpc::MachineCredentialsUpdateResponse>, Status> {
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
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::clear_site_exploration_error(self, request).await
    }

    async fn is_bmc_in_managed_host(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<rpc::IsBmcInManagedHostResponse>, Status> {
        crate::handlers::site_explorer::is_bmc_in_managed_host(self, request).await
    }

    async fn bmc_credential_status(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<rpc::BmcCredentialStatusResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::bmc_credential_status(self, request).await
    }

    async fn re_explore_endpoint(
        &self,
        request: Request<rpc::ReExploreEndpointRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::re_explore_endpoint(self, request).await
    }

    async fn delete_explored_endpoint(
        &self,
        request: Request<rpc::DeleteExploredEndpointRequest>,
    ) -> Result<Response<rpc::DeleteExploredEndpointResponse>, Status> {
        crate::handlers::site_explorer::delete_explored_endpoint(self, request).await
    }

    async fn pause_explored_endpoint_remediation(
        &self,
        request: Request<rpc::PauseExploredEndpointRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::site_explorer::pause_explored_endpoint_remediation(self, request).await
    }

    // DEPRECATED: use find_explored_endpoint_ids, find_explored_endpoints_by_ids and find_explored_managed_host_ids, find_explored_managed_hosts_by_ids instead
    async fn get_site_exploration_report(
        &self,
        request: Request<::rpc::forge::GetSiteExplorationRequest>,
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

    async fn update_machine_hardware_info(
        &self,
        request: Request<::rpc::forge::UpdateMachineHardwareInfoRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_hardware_info::handle_machine_hardware_info_update(self, request)
            .await
    }

    // Ad-hoc BMC exploration
    async fn explore(
        &self,
        request: Request<::rpc::forge::BmcEndpointRequest>,
    ) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
        crate::handlers::bmc_endpoint_explorer::explore(self, request).await
    }

    // Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    // Tells it whether to discover or cleanup based on current machine state.
    async fn forge_agent_control(
        &self,
        request: Request<rpc::ForgeAgentControlRequest>,
    ) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
        crate::handlers::machine_scout::forge_agent_control(self, request).await
    }

    async fn admin_force_delete_machine(
        &self,
        request: Request<rpc::AdminForceDeleteMachineRequest>,
    ) -> Result<Response<rpc::AdminForceDeleteMachineResponse>, Status> {
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
    ) -> Result<Response<rpc::ResourcePools>, Status> {
        crate::handlers::resource_pool::list(self, request).await
    }

    async fn update_machine_metadata(
        &self,
        request: Request<rpc::MachineMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::machine::update_machine_metadata(self, request).await
    }

    async fn set_maintenance(
        &self,
        request: Request<rpc::MaintenanceRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::managed_host::set_maintenance(self, request).await
    }

    async fn find_ip_address(
        &self,
        request: Request<rpc::FindIpAddressRequest>,
    ) -> Result<Response<rpc::FindIpAddressResponse>, Status> {
        crate::handlers::finder::find_ip_address(self, request).await
    }

    async fn identify_uuid(
        &self,
        request: Request<rpc::IdentifyUuidRequest>,
    ) -> Result<Response<rpc::IdentifyUuidResponse>, Status> {
        crate::handlers::finder::identify_uuid(self, request).await
    }

    async fn identify_mac(
        &self,
        request: Request<rpc::IdentifyMacRequest>,
    ) -> Result<Response<rpc::IdentifyMacResponse>, Status> {
        crate::handlers::finder::identify_mac(self, request).await
    }

    async fn identify_serial(
        &self,
        request: Request<rpc::IdentifySerialRequest>,
    ) -> Result<Response<rpc::IdentifySerialResponse>, Status> {
        crate::handlers::finder::identify_serial(self, request).await
    }

    async fn get_power_options(
        &self,
        request: Request<rpc::PowerOptionRequest>,
    ) -> Result<Response<rpc::PowerOptionResponse>, Status> {
        crate::handlers::power_options::get_power_options(self, request).await
    }

    async fn update_power_option(
        &self,
        request: Request<rpc::PowerOptionUpdateRequest>,
    ) -> Result<Response<rpc::PowerOptionResponse>, Status> {
        crate::handlers::power_options::update_power_option(self, request).await
    }

    async fn get_rack(
        &self,
        request: Request<rpc::GetRackRequest>,
    ) -> Result<Response<rpc::GetRackResponse>, Status> {
        crate::handlers::rack::get_rack(self, request).await
    }

    async fn delete_rack(
        &self,
        request: Request<rpc::DeleteRackRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::rack::delete_rack(self, request).await
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: Request<rpc::DpuReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::trigger_dpu_reprovisioning(self, request).await
    }

    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: Request<rpc::DpuReprovisioningListRequest>,
    ) -> Result<Response<rpc::DpuReprovisioningListResponse>, Status> {
        crate::handlers::dpu::list_dpu_waiting_for_reprovisioning(self, request).await
    }

    async fn trigger_host_reprovisioning(
        &self,
        request: Request<rpc::HostReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::host_reprovisioning::trigger_host_reprovisioning(self, request).await
    }

    async fn list_hosts_waiting_for_reprovisioning(
        &self,
        request: Request<rpc::HostReprovisioningListRequest>,
    ) -> Result<Response<rpc::HostReprovisioningListResponse>, Status> {
        crate::handlers::host_reprovisioning::list_hosts_waiting_for_reprovisioning(self, request)
            .await
    }

    /// Retrieves all DPU information including id and loopback IP
    async fn get_dpu_info_list(
        &self,
        request: Request<rpc::GetDpuInfoListRequest>,
    ) -> Result<Response<rpc::GetDpuInfoListResponse>, Status> {
        crate::handlers::machine::get_dpu_info_list(self, request).await
    }

    async fn get_machine_boot_override(
        &self,
        request: Request<MachineInterfaceId>,
    ) -> Result<Response<rpc::MachineBootOverride>, Status> {
        crate::handlers::boot_override::get(self, request).await
    }

    async fn set_machine_boot_override(
        &self,
        request: Request<rpc::MachineBootOverride>,
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
        request: Request<rpc::NetworkTopologyRequest>,
    ) -> Result<Response<rpc::NetworkTopologyData>, Status> {
        crate::handlers::network_devices::get_network_topology(self, request).await
    }

    async fn admin_bmc_reset(
        &self,
        request: Request<rpc::AdminBmcResetRequest>,
    ) -> Result<Response<rpc::AdminBmcResetResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::admin_bmc_reset(self, request).await
    }

    async fn disable_secure_boot(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<::rpc::forge::DisableSecureBootResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::disable_secure_boot(self, request).await
    }

    async fn lockdown(
        &self,
        request: Request<rpc::LockdownRequest>,
    ) -> Result<Response<::rpc::forge::LockdownResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::lockdown(self, request).await
    }

    async fn lockdown_status(
        &self,
        request: Request<rpc::LockdownStatusRequest>,
    ) -> Result<Response<::rpc::site_explorer::LockdownStatus>, Status> {
        crate::handlers::bmc_endpoint_explorer::lockdown_status(self, request).await
    }

    async fn enable_infinite_boot(
        &self,
        request: Request<rpc::EnableInfiniteBootRequest>,
    ) -> Result<Response<::rpc::forge::EnableInfiniteBootResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::enable_infinite_boot(self, request).await
    }

    async fn is_infinite_boot_enabled(
        &self,
        request: Request<rpc::IsInfiniteBootEnabledRequest>,
    ) -> Result<Response<::rpc::forge::IsInfiniteBootEnabledResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::is_infinite_boot_enabled(self, request).await
    }

    async fn machine_setup(
        &self,
        request: Request<rpc::MachineSetupRequest>,
    ) -> Result<Response<::rpc::forge::MachineSetupResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::machine_setup(self, request).await
    }

    async fn set_dpu_first_boot_order(
        &self,
        request: Request<rpc::SetDpuFirstBootOrderRequest>,
    ) -> Result<Response<::rpc::forge::SetDpuFirstBootOrderResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::set_dpu_first_boot_order(self, request).await
    }

    /// Should this DPU upgrade it's forge-dpu-agent?
    /// Once the upgrade is complete record_dpu_network_status will receive the updated
    /// version and write the DB to say our upgrade is complete.
    async fn dpu_agent_upgrade_check(
        &self,
        request: Request<rpc::DpuAgentUpgradeCheckRequest>,
    ) -> Result<Response<rpc::DpuAgentUpgradeCheckResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_check(self, request).await
    }

    /// Get or set the forge-dpu-agent upgrade policy.
    async fn dpu_agent_upgrade_policy_action(
        &self,
        request: Request<rpc::DpuAgentUpgradePolicyRequest>,
    ) -> Result<Response<rpc::DpuAgentUpgradePolicyResponse>, Status> {
        crate::handlers::dpu::dpu_agent_upgrade_policy_action(self, request).await
    }

    async fn create_credential(
        &self,
        request: Request<rpc::CredentialCreationRequest>,
    ) -> Result<Response<rpc::CredentialCreationResult>, Status> {
        crate::handlers::credential::create_credential(self, request).await
    }

    async fn delete_credential(
        &self,
        request: Request<rpc::CredentialDeletionRequest>,
    ) -> Result<Response<rpc::CredentialDeletionResult>, Status> {
        crate::handlers::credential::delete_credential(self, request).await
    }

    /// get_route_servers returns a list of all configured route server
    /// entries for all source types.
    async fn get_route_servers(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::RouteServerEntries>, Status> {
        crate::handlers::route_server::get(self, request).await
    }

    /// add_route_servers adds new route server entries for the
    /// provided source_type, defaulting to admin_api for calls
    /// coming from forge-admin-cli (but can be overridden in
    /// cases where deemed appropriate).
    async fn add_route_servers(
        &self,
        request: Request<rpc::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::add(self, request).await
    }

    /// remove_route_servers removes route server entries for the
    /// provided source_type, defaulting to admin_api for calls
    /// coming from forge-admin-cli (but can be overridden in
    /// cases where deemed appropriate).
    async fn remove_route_servers(
        &self,
        request: Request<rpc::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::remove(self, request).await
    }

    /// replace_route_servers replaces all route server entries
    /// for the provided source_type with the given list, defaulting
    /// to admin_api for calls coming from forge-admin-cli (but can
    /// be overridden in cases where deemed appropriate).
    async fn replace_route_servers(
        &self,
        request: Request<rpc::RouteServers>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::route_server::replace(self, request).await
    }

    async fn set_dynamic_config(
        &self,
        request: Request<rpc::SetDynamicConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::api::set_dynamic_config(self, request)
    }

    async fn clear_host_uefi_password(
        &self,
        request: Request<rpc::ClearHostUefiPasswordRequest>,
    ) -> Result<Response<rpc::ClearHostUefiPasswordResponse>, Status> {
        crate::handlers::uefi::clear_host_uefi_password(self, request).await
    }

    async fn set_host_uefi_password(
        &self,
        request: Request<rpc::SetHostUefiPasswordRequest>,
    ) -> Result<Response<rpc::SetHostUefiPasswordResponse>, Status> {
        crate::handlers::uefi::set_host_uefi_password(self, request).await
    }

    async fn get_expected_machine(
        &self,
        request: Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<rpc::ExpectedMachine>, Status> {
        crate::handlers::expected_machine::get(self, request).await
    }

    async fn add_expected_machine(
        &self,
        request: Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::add(self, request).await
    }

    async fn delete_expected_machine(
        &self,
        request: Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::delete(self, request).await
    }

    async fn update_expected_machine(
        &self,
        request: Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::update(self, request).await
    }

    async fn replace_all_expected_machines(
        &self,
        request: Request<rpc::ExpectedMachineList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_machine::replace_all(self, request).await
    }

    async fn get_all_expected_machines(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::ExpectedMachineList>, Status> {
        crate::handlers::expected_machine::get_all(self, request).await
    }

    async fn get_all_expected_machines_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::LinkedExpectedMachineList>, Status> {
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
        request: Request<rpc::BatchExpectedMachineOperationRequest>,
    ) -> Result<Response<rpc::BatchExpectedMachineOperationResponse>, Status> {
        crate::handlers::expected_machine::create_expected_machines(self, request).await
    }

    async fn update_expected_machines(
        &self,
        request: Request<rpc::BatchExpectedMachineOperationRequest>,
    ) -> Result<Response<rpc::BatchExpectedMachineOperationResponse>, Status> {
        crate::handlers::expected_machine::update_expected_machines(self, request).await
    }

    async fn create_rack_firmware(
        &self,
        request: tonic::Request<rpc::RackFirmwareCreateRequest>,
    ) -> Result<Response<rpc::RackFirmware>, tonic::Status> {
        crate::handlers::rack_firmware::create(self, request).await
    }

    async fn get_rack_firmware(
        &self,
        request: tonic::Request<rpc::RackFirmwareGetRequest>,
    ) -> Result<Response<rpc::RackFirmware>, tonic::Status> {
        crate::handlers::rack_firmware::get(self, request).await
    }

    async fn list_rack_firmware(
        &self,
        request: tonic::Request<rpc::RackFirmwareListRequest>,
    ) -> Result<Response<rpc::RackFirmwareList>, tonic::Status> {
        crate::handlers::rack_firmware::list(self, request).await
    }

    async fn delete_rack_firmware(
        &self,
        request: tonic::Request<rpc::RackFirmwareDeleteRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        crate::handlers::rack_firmware::delete(self, request).await
    }

    async fn apply_rack_firmware(
        &self,
        request: tonic::Request<rpc::RackFirmwareApplyRequest>,
    ) -> Result<Response<rpc::RackFirmwareApplyResponse>, tonic::Status> {
        crate::handlers::rack_firmware::apply(self, request).await
    }

    async fn get_expected_power_shelf(
        &self,
        request: Request<rpc::ExpectedPowerShelfRequest>,
    ) -> Result<Response<rpc::ExpectedPowerShelf>, Status> {
        crate::handlers::expected_power_shelf::get_expected_power_shelf(self, request).await
    }

    async fn add_expected_power_shelf(
        &self,
        request: Request<rpc::ExpectedPowerShelf>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::add_expected_power_shelf(self, request).await
    }

    async fn delete_expected_power_shelf(
        &self,
        request: Request<rpc::ExpectedPowerShelfRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::delete_expected_power_shelf(self, request).await
    }

    async fn update_expected_power_shelf(
        &self,
        request: Request<rpc::ExpectedPowerShelf>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::update_expected_power_shelf(self, request).await
    }

    async fn replace_all_expected_power_shelves(
        &self,
        request: Request<rpc::ExpectedPowerShelfList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_power_shelf::replace_all_expected_power_shelves(self, request)
            .await
    }

    async fn get_all_expected_power_shelves(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::ExpectedPowerShelfList>, Status> {
        crate::handlers::expected_power_shelf::get_all_expected_power_shelves(self, request).await
    }

    async fn get_all_expected_power_shelves_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::LinkedExpectedPowerShelfList>, Status> {
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
        request: Request<rpc::ExpectedSwitchRequest>,
    ) -> Result<Response<rpc::ExpectedSwitch>, Status> {
        crate::handlers::expected_switch::get_expected_switch(self, request).await
    }

    async fn add_expected_switch(
        &self,
        request: Request<rpc::ExpectedSwitch>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::add_expected_switch(self, request).await
    }

    async fn delete_expected_switch(
        &self,
        request: Request<rpc::ExpectedSwitchRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::delete_expected_switch(self, request).await
    }

    async fn update_expected_switch(
        &self,
        request: Request<rpc::ExpectedSwitch>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::update_expected_switch(self, request).await
    }

    async fn replace_all_expected_switches(
        &self,
        request: Request<rpc::ExpectedSwitchList>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::replace_all_expected_switches(self, request).await
    }

    async fn get_all_expected_switches(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::ExpectedSwitchList>, Status> {
        crate::handlers::expected_switch::get_all_expected_switches(self, request).await
    }

    async fn get_all_expected_switches_linked(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::LinkedExpectedSwitchList>, Status> {
        crate::handlers::expected_switch::get_all_expected_switches_linked(self, request).await
    }

    async fn delete_all_expected_switches(
        &self,
        request: Request<()>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::expected_switch::delete_all_expected_switches(self, request).await
    }

    async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: Request<::rpc::common::MachineIdList>,
    ) -> Result<Response<rpc::ConnectedDeviceList>, Status> {
        crate::handlers::network_devices::find_connected_devices_by_dpu_machine_ids(self, request)
            .await
    }

    async fn find_network_devices_by_device_ids(
        &self,
        request: Request<rpc::NetworkDeviceIdList>,
    ) -> Result<Response<rpc::NetworkTopologyData>, Status> {
        crate::handlers::network_devices::find_network_devices_by_device_ids(self, request).await
    }

    async fn find_machine_ids_by_bmc_ips(
        &self,
        request: Request<rpc::BmcIpList>,
    ) -> Result<Response<rpc::MachineIdBmcIpPairs>, Status> {
        crate::handlers::machine::find_machine_ids_by_bmc_ips(self, request).await
    }

    async fn find_mac_address_by_bmc_ip(
        &self,
        request: Request<rpc::BmcIp>,
    ) -> Result<Response<rpc::MacAddressBmcIp>, Status> {
        crate::handlers::machine_interface::find_mac_address_by_bmc_ip(self, request).await
    }

    async fn attest_quote(
        &self,
        request: Request<rpc::AttestQuoteRequest>,
    ) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
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
        request: Request<rpc::MachineRebootCompletedRequest>,
    ) -> Result<Response<rpc::MachineRebootCompletedResponse>, Status> {
        crate::handlers::machine_scout::reboot_completed(self, request).await
    }

    // machine has completed validation
    async fn machine_validation_completed(
        &self,
        request: Request<rpc::MachineValidationCompletedRequest>,
    ) -> Result<Response<rpc::MachineValidationCompletedResponse>, Status> {
        crate::handlers::machine_validation::mark_machine_validation_complete(self, request).await
    }

    async fn persist_validation_result(
        &self,
        request: Request<rpc::MachineValidationResultPostRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::persist_validation_result(self, request).await
    }

    async fn get_machine_validation_results(
        &self,
        request: Request<rpc::MachineValidationGetRequest>,
    ) -> Result<Response<rpc::MachineValidationResultList>, Status> {
        crate::handlers::machine_validation::get_machine_validation_results(self, request).await
    }

    async fn machine_set_auto_update(
        &self,
        request: Request<rpc::MachineSetAutoUpdateRequest>,
    ) -> Result<Response<rpc::MachineSetAutoUpdateResponse>, Status> {
        crate::handlers::machine::machine_set_auto_update(self, request).await
    }

    async fn get_machine_validation_external_config(
        &self,
        request: Request<rpc::GetMachineValidationExternalConfigRequest>,
    ) -> Result<Response<rpc::GetMachineValidationExternalConfigResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_external_config(self, request)
            .await
    }

    async fn get_machine_validation_external_configs(
        &self,
        request: Request<rpc::GetMachineValidationExternalConfigsRequest>,
    ) -> Result<Response<rpc::GetMachineValidationExternalConfigsResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_external_configs(self, request)
            .await
    }

    async fn add_update_machine_validation_external_config(
        &self,
        request: Request<rpc::AddUpdateMachineValidationExternalConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::add_update_machine_validation_external_config(
            self, request,
        )
        .await
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
        request: Request<rpc::MachineValidationRunListGetRequest>,
    ) -> Result<Response<rpc::MachineValidationRunList>, Status> {
        crate::handlers::machine_validation::get_machine_validation_runs(self, request).await
    }

    async fn admin_power_control(
        &self,
        request: Request<rpc::AdminPowerControlRequest>,
    ) -> Result<Response<rpc::AdminPowerControlResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::admin_power_control(self, request).await
    }

    async fn on_demand_machine_validation(
        &self,
        request: Request<rpc::MachineValidationOnDemandRequest>,
    ) -> Result<Response<rpc::MachineValidationOnDemandResponse>, Status> {
        crate::handlers::machine_validation::on_demand_machine_validation(self, request).await
    }

    async fn tpm_add_ca_cert(
        &self,
        request: Request<rpc::TpmCaCert>,
    ) -> Result<Response<rpc::TpmCaAddedCaStatus>, Status> {
        crate::handlers::tpm_ca::tpm_add_ca_cert(self, request).await
    }

    async fn tpm_show_ca_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::TpmCaCertDetailCollection>, Status> {
        crate::handlers::tpm_ca::tpm_show_ca_certs(self, &request).await
    }

    async fn tpm_show_unmatched_ek_certs(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::TpmEkCertStatusCollection>, Status> {
        crate::handlers::tpm_ca::tpm_show_unmatched_ek_certs(self, &request).await
    }

    async fn tpm_delete_ca_cert(
        &self,
        request: Request<rpc::TpmCaCertId>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::tpm_ca::tpm_delete_ca_cert(self, request).await
    }

    async fn remove_machine_validation_external_config(
        &self,
        request: Request<rpc::RemoveMachineValidationExternalConfigRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::machine_validation::remove_machine_validation_external_config(
            self, request,
        )
        .await
    }

    async fn get_machine_validation_tests(
        &self,
        request: Request<rpc::MachineValidationTestsGetRequest>,
    ) -> Result<Response<rpc::MachineValidationTestsGetResponse>, Status> {
        crate::handlers::machine_validation::get_machine_validation_tests(self, request).await
    }

    async fn update_machine_validation_test(
        &self,
        request: Request<rpc::MachineValidationTestUpdateRequest>,
    ) -> Result<Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
        crate::handlers::machine_validation::update_machine_validation_test(self, request).await
    }
    async fn add_machine_validation_test(
        &self,
        request: Request<rpc::MachineValidationTestAddRequest>,
    ) -> Result<Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
        crate::handlers::machine_validation::add_machine_validation_test(self, request).await
    }

    async fn machine_validation_test_verfied(
        &self,
        request: Request<rpc::MachineValidationTestVerfiedRequest>,
    ) -> Result<Response<rpc::MachineValidationTestVerfiedResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_verfied(self, request).await
    }

    async fn machine_validation_test_next_version(
        &self,
        request: Request<rpc::MachineValidationTestNextVersionRequest>,
    ) -> Result<Response<rpc::MachineValidationTestNextVersionResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_next_version(self, request)
            .await
    }

    async fn machine_validation_test_enable_disable_test(
        &self,
        request: Request<rpc::MachineValidationTestEnableDisableTestRequest>,
    ) -> Result<Response<rpc::MachineValidationTestEnableDisableTestResponse>, Status> {
        crate::handlers::machine_validation::machine_validation_test_enable_disable_test(
            self, request,
        )
        .await
    }
    async fn update_machine_validation_run(
        &self,
        request: Request<rpc::MachineValidationRunRequest>,
    ) -> Result<Response<rpc::MachineValidationRunResponse>, Status> {
        crate::handlers::machine_validation::update_machine_validation_run(self, request).await
    }

    async fn create_instance_type(
        &self,
        request: Request<rpc::CreateInstanceTypeRequest>,
    ) -> Result<Response<rpc::CreateInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::create(self, request).await
    }

    async fn find_instance_type_ids(
        &self,
        request: Request<rpc::FindInstanceTypeIdsRequest>,
    ) -> Result<Response<rpc::FindInstanceTypeIdsResponse>, Status> {
        crate::handlers::instance_type::find_ids(self, request).await
    }

    async fn find_instance_types_by_ids(
        &self,
        request: Request<rpc::FindInstanceTypesByIdsRequest>,
    ) -> Result<Response<rpc::FindInstanceTypesByIdsResponse>, Status> {
        crate::handlers::instance_type::find_by_ids(self, request).await
    }

    async fn delete_instance_type(
        &self,
        request: Request<rpc::DeleteInstanceTypeRequest>,
    ) -> Result<Response<rpc::DeleteInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::delete(self, request).await
    }

    async fn update_instance_type(
        &self,
        request: Request<rpc::UpdateInstanceTypeRequest>,
    ) -> Result<Response<rpc::UpdateInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::update(self, request).await
    }

    async fn associate_machines_with_instance_type(
        &self,
        request: Request<rpc::AssociateMachinesWithInstanceTypeRequest>,
    ) -> Result<Response<rpc::AssociateMachinesWithInstanceTypeResponse>, Status> {
        crate::handlers::instance_type::associate_machines(self, request).await
    }

    async fn remove_machine_instance_type_association(
        &self,
        request: Request<rpc::RemoveMachineInstanceTypeAssociationRequest>,
    ) -> Result<Response<rpc::RemoveMachineInstanceTypeAssociationResponse>, Status> {
        crate::handlers::instance_type::remove_machine_association(self, request).await
    }

    async fn redfish_browse(
        &self,
        request: Request<rpc::RedfishBrowseRequest>,
    ) -> Result<Response<rpc::RedfishBrowseResponse>, Status> {
        crate::handlers::redfish::redfish_browse(self, request).await
    }

    async fn redfish_list_actions(
        &self,
        request: Request<rpc::RedfishListActionsRequest>,
    ) -> Result<Response<rpc::RedfishListActionsResponse>, Status> {
        crate::handlers::redfish::redfish_list_actions(self, request).await
    }

    async fn redfish_create_action(
        &self,
        request: Request<rpc::RedfishCreateActionRequest>,
    ) -> Result<Response<rpc::RedfishCreateActionResponse>, Status> {
        crate::handlers::redfish::redfish_create_action(self, request).await
    }

    async fn redfish_approve_action(
        &self,
        request: Request<rpc::RedfishActionId>,
    ) -> Result<Response<rpc::RedfishApproveActionResponse>, Status> {
        crate::handlers::redfish::redfish_approve_action(self, request).await
    }
    async fn redfish_apply_action(
        &self,
        request: Request<rpc::RedfishActionId>,
    ) -> Result<Response<rpc::RedfishApplyActionResponse>, Status> {
        crate::handlers::redfish::redfish_apply_action(self, request).await
    }

    async fn redfish_cancel_action(
        &self,
        request: Request<rpc::RedfishActionId>,
    ) -> Result<Response<rpc::RedfishCancelActionResponse>, Status> {
        crate::handlers::redfish::redfish_cancel_action(self, request).await
    }

    async fn ufm_browse(
        &self,
        request: Request<rpc::UfmBrowseRequest>,
    ) -> Result<Response<rpc::UfmBrowseResponse>, Status> {
        crate::handlers::ib_fabric::ufm_browse(self, request).await
    }

    async fn create_network_security_group(
        &self,
        request: Request<rpc::CreateNetworkSecurityGroupRequest>,
    ) -> Result<Response<rpc::CreateNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::create(self, request).await
    }

    async fn find_network_security_group_ids(
        &self,
        request: Request<rpc::FindNetworkSecurityGroupIdsRequest>,
    ) -> Result<Response<rpc::FindNetworkSecurityGroupIdsResponse>, Status> {
        crate::handlers::network_security_group::find_ids(self, request).await
    }

    async fn find_network_security_groups_by_ids(
        &self,
        request: Request<rpc::FindNetworkSecurityGroupsByIdsRequest>,
    ) -> Result<Response<rpc::FindNetworkSecurityGroupsByIdsResponse>, Status> {
        crate::handlers::network_security_group::find_by_ids(self, request).await
    }

    async fn delete_network_security_group(
        &self,
        request: Request<rpc::DeleteNetworkSecurityGroupRequest>,
    ) -> Result<Response<rpc::DeleteNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::delete(self, request).await
    }

    async fn update_network_security_group(
        &self,
        request: Request<rpc::UpdateNetworkSecurityGroupRequest>,
    ) -> Result<Response<rpc::UpdateNetworkSecurityGroupResponse>, Status> {
        crate::handlers::network_security_group::update(self, request).await
    }

    async fn get_network_security_group_propagation_status(
        &self,
        request: Request<rpc::GetNetworkSecurityGroupPropagationStatusRequest>,
    ) -> Result<Response<rpc::GetNetworkSecurityGroupPropagationStatusResponse>, Status> {
        crate::handlers::network_security_group::get_propagation_status(self, request).await
    }

    async fn get_network_security_group_attachments(
        &self,
        request: Request<rpc::GetNetworkSecurityGroupAttachmentsRequest>,
    ) -> Result<Response<rpc::GetNetworkSecurityGroupAttachmentsResponse>, Status> {
        crate::handlers::network_security_group::get_attachments(self, request).await
    }

    async fn get_desired_firmware_versions(
        &self,
        request: Request<rpc::GetDesiredFirmwareVersionsRequest>,
    ) -> Result<Response<rpc::GetDesiredFirmwareVersionsResponse>, Status> {
        crate::handlers::firmware::get_desired_firmware_versions(self, request)
    }

    async fn create_sku(
        &self,
        request: Request<rpc::SkuList>,
    ) -> Result<Response<rpc::SkuIdList>, Status> {
        crate::handlers::sku::create(self, request).await
    }

    async fn delete_sku(&self, request: Request<SkuIdList>) -> Result<Response<()>, Status> {
        crate::handlers::sku::delete(self, request).await
    }

    async fn generate_sku_from_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::Sku>, Status> {
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
        request: Request<::rpc::forge::SkuMachinePair>,
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
    ) -> Result<Response<rpc::SkuIdList>, Status> {
        crate::handlers::sku::get_all_ids(self, request).await
    }

    async fn find_skus_by_ids(
        &self,
        request: Request<rpc::SkusByIdsRequest>,
    ) -> Result<Response<rpc::SkuList>, Status> {
        crate::handlers::sku::find_skus_by_ids(self, request).await
    }

    async fn update_sku_metadata(
        &self,
        request: Request<rpc::SkuUpdateMetadataRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::sku::update_sku_metadata(self, request).await
    }

    async fn replace_sku(&self, request: Request<rpc::Sku>) -> Result<Response<rpc::Sku>, Status> {
        crate::handlers::sku::replace_sku(self, request).await
    }

    async fn set_managed_host_quarantine_state(
        &self,
        request: Request<rpc::SetManagedHostQuarantineStateRequest>,
    ) -> Result<Response<rpc::SetManagedHostQuarantineStateResponse>, Status> {
        crate::handlers::machine_quarantine::set_managed_host_quarantine_state(self, request).await
    }

    async fn get_managed_host_quarantine_state(
        &self,
        request: Request<rpc::GetManagedHostQuarantineStateRequest>,
    ) -> Result<Response<rpc::GetManagedHostQuarantineStateResponse>, Status> {
        crate::handlers::machine_quarantine::get_managed_host_quarantine_state(self, request).await
    }

    async fn clear_managed_host_quarantine_state(
        &self,
        request: Request<rpc::ClearManagedHostQuarantineStateRequest>,
    ) -> Result<Response<rpc::ClearManagedHostQuarantineStateResponse>, Status> {
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
        request: Request<rpc::CopyBfbToDpuRshimRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::bmc_endpoint_explorer::copy_bfb_to_dpu_rshim(self, request).await
    }

    async fn find_nv_link_partition_ids(
        &self,
        request: Request<rpc::NvLinkPartitionSearchFilter>,
    ) -> Result<Response<rpc::NvLinkPartitionIdList>, Status> {
        crate::handlers::nvl_partition::find_ids(self, request).await
    }

    async fn find_nv_link_partitions_by_ids(
        &self,
        request: Request<rpc::NvLinkPartitionsByIdsRequest>,
    ) -> Result<Response<rpc::NvLinkPartitionList>, Status> {
        crate::handlers::nvl_partition::find_by_ids(self, request).await
    }

    async fn nv_link_partitions_for_tenant(
        &self,
        request: Request<rpc::TenantSearchQuery>,
    ) -> Result<Response<rpc::NvLinkPartitionList>, Status> {
        crate::handlers::nvl_partition::for_tenant(self, request).await
    }

    async fn find_nv_link_logical_partition_ids(
        &self,
        request: Request<rpc::NvLinkLogicalPartitionSearchFilter>,
    ) -> Result<Response<rpc::NvLinkLogicalPartitionIdList>, Status> {
        crate::handlers::logical_partition::find_ids(self, request).await
    }

    async fn find_nv_link_logical_partitions_by_ids(
        &self,
        request: Request<rpc::NvLinkLogicalPartitionsByIdsRequest>,
    ) -> Result<Response<rpc::NvLinkLogicalPartitionList>, Status> {
        crate::handlers::logical_partition::find_by_ids(self, request).await
    }

    async fn create_nv_link_logical_partition(
        &self,
        request: Request<rpc::NvLinkLogicalPartitionCreationRequest>,
    ) -> Result<Response<rpc::NvLinkLogicalPartition>, Status> {
        crate::handlers::logical_partition::create(self, request).await
    }

    async fn delete_nv_link_logical_partition(
        &self,
        request: Request<rpc::NvLinkLogicalPartitionDeletionRequest>,
    ) -> Result<Response<rpc::NvLinkLogicalPartitionDeletionResult>, Status> {
        crate::handlers::logical_partition::delete(self, request).await
    }

    async fn nv_link_logical_partitions_for_tenant(
        &self,
        request: Request<rpc::TenantSearchQuery>,
    ) -> Result<Response<rpc::NvLinkLogicalPartitionList>, Status> {
        crate::handlers::logical_partition::for_tenant(self, request).await
    }

    async fn update_nv_link_logical_partition(
        &self,
        request: Request<rpc::NvLinkLogicalPartitionUpdateRequest>,
    ) -> Result<Response<rpc::NvLinkLogicalPartitionUpdateResult>, Status> {
        crate::handlers::logical_partition::update(self, request).await
    }

    async fn nmxm_browse(
        &self,
        request: Request<rpc::NmxmBrowseRequest>,
    ) -> Result<Response<rpc::NmxmBrowseResponse>, Status> {
        crate::handlers::nvl_partition::nmxm_browse(self, request).await
    }

    // Return a Vector of all the DPA interface IDs
    async fn get_all_dpa_interface_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::DpaInterfaceIdList>, Status> {
        crate::handlers::dpa::get_all_ids(self, request).await
    }

    // Given a Vector of DPA Interface IDs, return the corresponding
    // DPA Interfaces in a Vector
    async fn find_dpa_interfaces_by_ids(
        &self,
        request: Request<rpc::DpaInterfacesByIdsRequest>,
    ) -> Result<Response<rpc::DpaInterfaceList>, Status> {
        crate::handlers::dpa::find_dpa_interfaces_by_ids(self, request).await
    }

    // create_dpa_interface is mainly for debugging purposes. In practice,
    // when the scout reports its inventory, we will create DPA interfaces
    // for DPA NICs reported in the inventory.
    async fn create_dpa_interface(
        &self,
        request: Request<rpc::DpaInterfaceCreationRequest>,
    ) -> Result<Response<rpc::DpaInterface>, Status> {
        crate::handlers::dpa::create(self, request).await
    }

    // delete_dpa_interface is mainly for debugging purposes.
    async fn delete_dpa_interface(
        &self,
        request: Request<rpc::DpaInterfaceDeletionRequest>,
    ) -> Result<Response<rpc::DpaInterfaceDeletionResult>, Status> {
        crate::handlers::dpa::delete(self, request).await
    }

    // set_dpa_network_observaction_status is for debugging purposes.
    // In practice, the MQTT subscriber running in Carbide will update
    // the observation status
    async fn set_dpa_network_observation_status(
        &self,
        request: Request<rpc::DpaNetworkObservationSetRequest>,
    ) -> Result<Response<rpc::DpaInterface>, Status> {
        crate::handlers::dpa::set_dpa_network_observation_status(self, request).await
    }

    async fn create_bmc_user(
        &self,
        request: Request<rpc::CreateBmcUserRequest>,
    ) -> Result<Response<rpc::CreateBmcUserResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::create_bmc_user(self, request).await
    }

    async fn delete_bmc_user(
        &self,
        request: Request<rpc::DeleteBmcUserRequest>,
    ) -> Result<Response<rpc::DeleteBmcUserResponse>, Status> {
        crate::handlers::bmc_endpoint_explorer::delete_bmc_user(self, request).await
    }

    async fn set_firmware_update_time_window(
        &self,
        request: Request<rpc::SetFirmwareUpdateTimeWindowRequest>,
    ) -> Result<Response<rpc::SetFirmwareUpdateTimeWindowResponse>, Status> {
        crate::handlers::firmware::set_firmware_update_time_window(self, request).await
    }

    async fn list_host_firmware(
        &self,
        request: Request<rpc::ListHostFirmwareRequest>,
    ) -> Result<Response<rpc::ListHostFirmwareResponse>, Status> {
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
        request: Request<rpc::TrimTableRequest>,
    ) -> Result<Response<rpc::TrimTableResponse>, Status> {
        crate::handlers::db::trim_table(self, request).await
    }

    async fn create_remediation(
        &self,
        request: Request<rpc::CreateRemediationRequest>,
    ) -> Result<Response<rpc::CreateRemediationResponse>, Status> {
        crate::handlers::dpu_remediation::create(self, request).await
    }

    async fn approve_remediation(
        &self,
        request: Request<rpc::ApproveRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::approve(self, request).await
    }

    async fn revoke_remediation(
        &self,
        request: Request<rpc::RevokeRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::revoke(self, request).await
    }

    async fn enable_remediation(
        &self,
        request: Request<rpc::EnableRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::enable(self, request).await
    }

    async fn disable_remediation(
        &self,
        request: Request<rpc::DisableRemediationRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::disable(self, request).await
    }

    async fn find_remediation_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::RemediationIdList>, Status> {
        crate::handlers::dpu_remediation::find_remediation_ids(self, request).await
    }

    async fn find_remediations_by_ids(
        &self,
        request: Request<rpc::RemediationIdList>,
    ) -> Result<Response<rpc::RemediationList>, Status> {
        crate::handlers::dpu_remediation::find_remediations_by_ids(self, request).await
    }

    async fn find_applied_remediation_ids(
        &self,
        request: Request<rpc::FindAppliedRemediationIdsRequest>,
    ) -> Result<Response<rpc::AppliedRemediationIdList>, Status> {
        crate::handlers::dpu_remediation::find_applied_remediation_ids(self, request).await
    }

    async fn find_applied_remediations(
        &self,
        request: Request<rpc::FindAppliedRemediationsRequest>,
    ) -> Result<Response<rpc::AppliedRemediationList>, Status> {
        crate::handlers::dpu_remediation::find_applied_remediations(self, request).await
    }

    async fn get_next_remediation_for_machine(
        &self,
        request: Request<rpc::GetNextRemediationForMachineRequest>,
    ) -> Result<Response<rpc::GetNextRemediationForMachineResponse>, Status> {
        crate::handlers::dpu_remediation::get_next_remediation_for_machine(self, request).await
    }

    async fn remediation_applied(
        &self,
        request: Request<rpc::RemediationAppliedRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu_remediation::remediation_applied(self, request).await
    }

    async fn set_primary_dpu(
        &self,
        request: Request<rpc::SetPrimaryDpuRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::managed_host::set_primary_dpu(self, request).await
    }

    async fn create_dpu_extension_service(
        &self,
        request: Request<rpc::CreateDpuExtensionServiceRequest>,
    ) -> Result<Response<rpc::DpuExtensionService>, Status> {
        crate::handlers::extension_service::create(self, request).await
    }

    async fn update_dpu_extension_service(
        &self,
        request: Request<rpc::UpdateDpuExtensionServiceRequest>,
    ) -> Result<Response<rpc::DpuExtensionService>, Status> {
        crate::handlers::extension_service::update(self, request).await
    }

    async fn delete_dpu_extension_service(
        &self,
        request: Request<rpc::DeleteDpuExtensionServiceRequest>,
    ) -> Result<Response<rpc::DeleteDpuExtensionServiceResponse>, Status> {
        crate::handlers::extension_service::delete(self, request).await
    }

    async fn find_dpu_extension_service_ids(
        &self,
        request: Request<rpc::DpuExtensionServiceSearchFilter>,
    ) -> Result<Response<rpc::DpuExtensionServiceIdList>, Status> {
        crate::handlers::extension_service::find_ids(self, request).await
    }

    async fn find_dpu_extension_services_by_ids(
        &self,
        request: Request<rpc::DpuExtensionServicesByIdsRequest>,
    ) -> Result<Response<rpc::DpuExtensionServiceList>, Status> {
        crate::handlers::extension_service::find_by_ids(self, request).await
    }

    async fn get_dpu_extension_service_versions_info(
        &self,
        request: Request<rpc::GetDpuExtensionServiceVersionsInfoRequest>,
    ) -> Result<Response<rpc::DpuExtensionServiceVersionInfoList>, Status> {
        crate::handlers::extension_service::get_versions_info(self, request).await
    }

    async fn find_instances_by_dpu_extension_service(
        &self,
        request: Request<rpc::FindInstancesByDpuExtensionServiceRequest>,
    ) -> Result<Response<rpc::FindInstancesByDpuExtensionServiceResponse>, Status> {
        crate::handlers::extension_service::find_instances_by_extension_service(self, request).await
    }

    async fn trigger_machine_attestation(
        &self,
        request: tonic::Request<rpc::AttestationData>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::attestation::trigger_machine_attestation(self, request).await
    }

    async fn cancel_machine_attestation(
        &self,
        request: tonic::Request<rpc::AttestationData>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::attestation::cancel_machine_attestation(self, request).await
    }

    async fn find_machines_under_attestation(
        &self,
        request: tonic::Request<rpc::AttestationMachineList>,
    ) -> Result<tonic::Response<rpc::AttestationResponse>, Status> {
        crate::handlers::attestation::list_machines_under_attestation(self, request).await
    }

    async fn find_machine_ids_under_attestation(
        &self,
        request: tonic::Request<rpc::AttestationIdsRequest>,
    ) -> Result<Response<::rpc::common::MachineIdList>, Status> {
        crate::handlers::attestation::list_machine_ids_under_attestation(self, request).await
    }

    async fn modify_dpf_state(
        &self,
        request: Request<rpc::ModifyDpfStateRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpf::modify_dpf_state(self, request).await
    }

    async fn get_dpf_state(
        &self,
        request: Request<rpc::GetDpfStateRequest>,
    ) -> Result<Response<rpc::DpfStateResponse>, Status> {
        crate::handlers::dpf::get_dpf_state(self, request).await
    }

    // scout_stream handles the bidirectional streaming connection from scout agents.
    // scout agents call scout_stream and send an Init message, and then carbide-api
    // will send down "request" messages to connected agent(s) to either instruct them
    // or ask them for information (sometimes for state changes, other times for
    // feeding data back to administrative CLI/UI calls).
    async fn scout_stream(
        &self,
        request: Request<Streaming<rpc::ScoutStreamApiBoundMessage>>,
    ) -> Result<Response<Self::ScoutStreamStream>, Status> {
        crate::handlers::scout_stream::scout_stream(self, request).await
    }

    // scout_stream_show_connections lists all active scout agent
    // connections by building up some ScoutStreamConnectionInfo
    // messages using the data from the scout_stream_registry.
    async fn scout_stream_show_connections(
        &self,
        request: Request<rpc::ScoutStreamShowConnectionsRequest>,
    ) -> Result<Response<rpc::ScoutStreamShowConnectionsResponse>, Status> {
        crate::handlers::scout_stream::show_connections(self, request).await
    }

    // scout_stream_disconnect is used to disconnect the
    // given MachineId's ScoutStream connection.
    async fn scout_stream_disconnect(
        &self,
        request: Request<rpc::ScoutStreamDisconnectRequest>,
    ) -> Result<Response<rpc::ScoutStreamDisconnectResponse>, Status> {
        crate::handlers::scout_stream::disconnect(self, request).await
    }

    // scout_stream_ping is used to ping the
    // given MachineId's ScoutStream connection.
    async fn scout_stream_ping(
        &self,
        request: Request<rpc::ScoutStreamAdminPingRequest>,
    ) -> Result<Response<rpc::ScoutStreamAdminPingResponse>, Status> {
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
        request: Request<rpc::MachinePositionQuery>,
    ) -> Result<Response<rpc::MachinePositionInfoList>, Status> {
        crate::handlers::machine::get_machine_position_info(self, request).await
    }

    async fn determine_machine_ingestion_state(
        &self,
        request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
    ) -> Result<tonic::Response<::rpc::forge::MachineIngestionStateResponse>, Status> {
        crate::api::log_request_data(&request);

        crate::handlers::power_options::determine_machine_ingestion_state(
            self,
            &request.into_inner(),
        )
        .await
    }

    async fn allow_ingestion_and_power_on(
        &self,
        request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::api::log_request_data(&request);

        crate::handlers::power_options::allow_ingestion_and_power_on(self, &request.into_inner())
            .await
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
    fn txn_begin(&self) -> impl Future<Output = Result<db::Transaction<'_>, DatabaseError>>;
}

impl TransactionVending for PgPool {
    #[track_caller]
    // This returns an `impl Future` instead of being async, so that we can use #[track_caller],
    // which is unsupported with async fn's.
    fn txn_begin(&self) -> impl Future<Output = Result<db::Transaction<'_>, DatabaseError>> {
        db::Transaction::begin(self)
    }
}

impl Api {
    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn txn_begin(&self) -> impl Future<Output = Result<db::Transaction<'_>, DatabaseError>> {
        let loc = Location::caller();
        db::Transaction::begin_with_location(&self.database_connection, loc)
    }

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub(crate) fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> impl Future<Output = CarbideResult<(Machine, db::Transaction<'_>)>> {
        let loc = Location::caller();
        let machine_id = *machine_id;
        async move {
            let mut txn =
                db::Transaction::begin_with_location(&self.database_connection, loc).await?;

            let machine = match db::machine::find_one(&mut txn, &machine_id, search_config).await {
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
