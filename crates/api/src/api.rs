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

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub use ::rpc::forge as rpc;
use ::rpc::forge::{BmcEndpointRequest, SkuIdList};
use ::rpc::forge_agent_control_response::forge_agent_control_extra_info::KeyValuePair;
use ::rpc::protos::{measured_boot as measured_boot_pb, mlx_device as mlx_device_pb};
use chrono::TimeZone;
use db::machine::{self};
use db::network_devices::NetworkDeviceSearchConfig;
use db::{DatabaseError, ObjectFilter, attestation as db_attest};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialProvider};
use forge_uuid::machine::{MachineId, MachineInterfaceId};
use itertools::Itertools;
use libredfish::{RoleId, SystemPowerControl};
use mac_address::MacAddress;
use mlxconfig_device::report::MlxDeviceReport;
use model::firmware::DesiredFirmwareVersions;
use model::machine::machine_id::try_parse_machine_id;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BomValidating, CleanupState, FailureCause, FailureDetails, FailureSource, LoadSnapshotOptions,
    Machine, MachineState, MachineValidatingState, ManagedHostState, MeasuringState,
    ValidationState, get_action_for_dpu_state,
};
use model::machine_validation::{MachineValidationState, MachineValidationStatus};
use model::resource_pool::common::CommonPools;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};
#[cfg(feature = "linux-build")]
use tss_esapi::{
    structures::{Attest, Public as TssPublic, Signature},
    traits::UnMarshall,
};
use utils::HostPortPair;

use self::rpc::forge_server::Forge;
#[cfg(feature = "linux-build")]
use crate::attestation as attest;
use crate::cfg::file::CarbideConfig;
use crate::handlers::utils::convert_and_log_machine_id;
use crate::ib::IBFabricManager;
use crate::logging::log_limiter::LogLimiter;
use crate::redfish::{RedfishAuth, RedfishClientPool};
use crate::site_explorer::EndpointExplorer;
use crate::{
    CarbideError, CarbideResult, auth, dynamic_settings, ethernet_virtualization, measured_boot,
};

pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    pub(crate) credential_provider: Arc<dyn CredentialProvider>,
    pub(crate) certificate_provider: Arc<dyn CertificateProvider>,
    pub(crate) redfish_pool: Arc<dyn RedfishClientPool>,
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
        request: Request<rpc::VersionRequest>,
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
                Some(self.runtime_config.redacted().into())
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

    async fn find_ib_fabric_ids(
        &self,
        request: Request<rpc::IbFabricSearchFilter>,
    ) -> Result<Response<rpc::IbFabricIdList>, Status> {
        crate::handlers::ib_fabric::find_ids(self, request).await
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

    async fn echo(
        &self,
        request: Request<rpc::EchoRequest>,
    ) -> Result<Response<rpc::EchoResponse>, Status> {
        log_request_data(&request);

        let reply = rpc::EchoResponse {
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
                .get_certificate(machine_identity, None, None)
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
        log_request_data(&request);

        let cleanup_info = request.into_inner();
        tracing::info!(?cleanup_info, "cleanup_machine_completed");

        let machine_id = convert_and_log_machine_id(cleanup_info.machine_id.as_ref())?;

        // Load machine from DB
        let (machine, mut txn) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig::default(),
                "cleanup_machine_completed",
            )
            .await?;
        db::machine::update_cleanup_time(&machine, &mut txn).await?;

        if let Some(nvme_result) = cleanup_info.nvme
            && rpc::machine_cleanup_info::CleanupResult::Error as i32 == nvme_result.result
        {
            // NVME Cleanup failed. Move machine to failed state.
            db::machine::update_failure_details(
                &machine,
                &mut txn,
                FailureDetails {
                    cause: FailureCause::NVMECleanFailed {
                        err: nvme_result.message.to_string(),
                    },
                    failed_at: chrono::Utc::now(),
                    source: FailureSource::Scout,
                },
            )
            .await?;
        }

        txn.commit().await?;

        // State handler should mark Machine as Adopted and reboot host for bios/bmc lockdown.
        Ok(Response::new(rpc::MachineCleanupResult {}))
    }

    /// Invoked by forge-scout whenever a certain Machine can not be properly acted on
    async fn report_forge_scout_error(
        &self,
        request: Request<rpc::ForgeScoutErrorReport>,
    ) -> Result<Response<rpc::ForgeScoutErrorReportResult>, Status> {
        log_request_data(&request);
        let _machine_id = convert_and_log_machine_id(request.into_inner().machine_id.as_ref())?;

        // `log_request_data` will already provide us the error message
        // Therefore we don't have to do anything else
        Ok(Response::new(rpc::ForgeScoutErrorReportResult {}))
    }

    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        log_request_data(&request);

        Ok(crate::dhcp::discover::discover_dhcp(self, request).await?)
    }

    async fn get_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::Machine>, Status> {
        crate::handlers::machine::get_machine(self, request).await
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

    async fn find_machine_health_histories(
        &self,
        request: Request<rpc::MachineHealthHistoriesRequest>,
    ) -> std::result::Result<Response<rpc::MachineHealthHistories>, Status> {
        crate::handlers::machine::find_machine_health_histories(self, request).await
    }

    // DEPRECATED: use find_machine_ids and find_machines_by_ids instead
    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        crate::handlers::machine::find_machines(self, request).await
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

    #[allow(rustdoc::invalid_html_tags)]
    /// Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    /// Tells it whether to discover or cleanup based on current machine state.
    async fn forge_agent_control(
        &self,
        request: Request<rpc::ForgeAgentControlRequest>,
    ) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
        log_request_data(&request);

        use ::rpc::forge_agent_control_response::Action;

        let machine_id = convert_and_log_machine_id(request.into_inner().machine_id.as_ref())?;

        let (machine, mut txn) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig::default(),
                "forge_agent_control",
            )
            .await?;

        let is_dpu = machine.is_dpu();
        let host_machine = if !is_dpu {
            machine.clone()
        } else {
            db::machine::find_host_by_dpu_machine_id(&mut txn, &machine_id)
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?
        };

        if !is_dpu {
            db::machine::update_scout_contact_time(&machine_id, &mut txn).await?;
        }

        // Respond based on machine current state
        let state = host_machine.current_state();
        let (action, action_data) = if is_dpu {
            get_action_for_dpu_state(state, &machine_id).map_err(CarbideError::from)?
        } else {
            match state {
                ManagedHostState::HostInit {
                    machine_state: MachineState::Init,
                } => (Action::Retry, None),
                ManagedHostState::Validation {
                    validation_state:
                        ValidationState::MachineValidation {
                            machine_validation:
                                MachineValidatingState::MachineValidating {
                                    context,
                                    id,
                                    completed,
                                    total,
                                    is_enabled,
                                },
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
                    if *is_enabled {
                        db::machine_validation::update_status(
                            &mut txn,
                            id,
                            MachineValidationStatus {
                                state: MachineValidationState::InProgress,
                                ..MachineValidationStatus::default()
                            },
                        )
                        .await?;
                        let machine_validation =
                            db::machine_validation::find_by_id(&mut txn, id).await?;
                        (
                            Action::MachineValidation,
                            Some(
                                rpc::forge_agent_control_response::ForgeAgentControlExtraInfo {
                                    pair: [
                                        KeyValuePair {
                                            key: "Context".to_string(),
                                            value: context.clone(),
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
                // If the API is configured with attestation_enabled, and
                // the machine has been Discovered (and progressed on to the
                // point where it is WaitingForMeasurements), then let Scout (or
                // whoever the caller is) know that it's time for measurements
                // to be sent.
                ManagedHostState::Measuring {
                    measuring_state: MeasuringState::WaitingForMeasurements,
                } => (Action::Measure, None),
                ManagedHostState::WaitingForCleanup {
                    cleanup_state: CleanupState::HostCleanup { .. },
                }
                | ManagedHostState::Failed {
                    details:
                        FailureDetails {
                            cause: FailureCause::NVMECleanFailed { .. },
                            ..
                        },
                    ..
                } => {
                    let last_cleanup_time = host_machine.last_cleanup_time;
                    let state_version = host_machine.state.version;
                    tracing::info!(
                        "last_cleanup_time: {:?}, state_version: {:?}",
                        last_cleanup_time,
                        state_version
                    );
                    // Check scout has already cleaned up the machine
                    if last_cleanup_time.unwrap_or_default() > state_version.timestamp() {
                        tracing::info!("Cleanup is already done");
                        (Action::Noop, None)
                    } else {
                        (Action::Reset, None)
                    }
                }
                ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::UpdatingInventory(_),
                } => {
                    tracing::info!(
                        "Request Discovery {} < {}",
                        machine.last_discovery_time.unwrap_or_default(),
                        machine.current_version().timestamp()
                    );
                    if machine.last_discovery_time.unwrap_or_default()
                        < machine.current_version().timestamp()
                    {
                        (Action::Discovery, None)
                    } else {
                        (Action::Noop, None)
                    }
                }
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    tracing::info!(
                        machine_id = %machine.id,
                        machine_type = "Host",
                        %state,
                        "forge agent control",
                    );
                    (Action::Noop, None)
                }
            }
        };
        tracing::info!(
            machine_id = %machine.id,
            action = action.as_str_name(),
            "forge agent control",
        );

        txn.commit().await?;

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

        let mut txn = self.txn_begin("admin_force_delete_machine").await?;

        let machine = match db::machine::find_by_query(&mut txn, &query).await? {
            Some(machine) => machine,
            None => {
                // If the machine was already deleted, then there is nothing to do
                // and this is a success
                return Ok(Response::new(response));
            }
        };
        log_machine_id(&machine.id);

        if machine.instance_type_id.is_some() {
            return Err(CarbideError::FailedPrecondition(format!(
                "association with instance type must be removed before deleting machine {}",
                &machine.id
            ))
            .into());
        }

        // TODO: This should maybe just use the snapshot loading functionality that the
        // state controller will use - which already contains the combined state
        let host_machine;
        let dpu_machines;
        if machine.is_dpu() {
            if let Some(host) =
                db::machine::find_host_by_dpu_machine_id(&mut txn, &machine.id).await?
            {
                tracing::info!("Found host Machine {:?}", machine.id.to_string());
                // Get all DPUs attached to this host, in case there are more than one.
                dpu_machines =
                    db::machine::find_dpus_by_host_machine_id(&mut txn, &host.id).await?;
                host_machine = Some(host);
            } else {
                host_machine = None;
                dpu_machines = vec![machine];
            }
        } else {
            dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine.id).await?;
            tracing::info!(
                "Found dpu Machines {:?}",
                dpu_machines.iter().map(|m| m.id.to_string()).join(", ")
            );
            host_machine = Some(machine);
        }

        let mut instance_id = None;
        if let Some(host_machine) = &host_machine {
            instance_id = db::instance::find_id_by_machine_id(&mut txn, &host_machine.id).await?;
        }

        if let Some(host_machine) = &host_machine {
            response.managed_host_machine_id = host_machine.id.to_string();
            if let Some(iface) = host_machine.interfaces.first() {
                response.managed_host_machine_interface_id = iface.id.to_string();
            }
            if let Some(ip) = host_machine.bmc_info.ip.as_ref() {
                response.managed_host_bmc_ip = ip.to_string();
            }
        }
        if let Some(dpu_machine) = dpu_machines.first() {
            response.dpu_machine_ids = dpu_machines.iter().map(|m| m.id.to_string()).collect();
            // deprecated field:
            response.dpu_machine_id = dpu_machine.id.to_string();

            let dpu_interfaces = dpu_machines
                .iter()
                .flat_map(|m| m.interfaces.clone())
                .collect::<Vec<_>>();
            if let Some(iface) = dpu_interfaces.first() {
                response.dpu_machine_interface_ids =
                    dpu_interfaces.iter().map(|i| i.id.to_string()).collect();
                // deprecated field:
                response.dpu_machine_interface_id = iface.id.to_string();
            }
            if let Some(ip) = dpu_machine.bmc_info.ip.as_ref() {
                response.dpu_bmc_ip = ip.to_string();
            }
        }
        if let Some(instance_id) = &instance_id {
            response.instance_id = instance_id.to_string();
        }

        // So far we only inspected state - now we start the deletion process
        // TODO: In the new model we might just need to move one Machine to this state
        if let Some(host_machine) = &host_machine {
            db::machine::advance(
                host_machine,
                &mut txn,
                &ManagedHostState::ForceDeletion,
                None,
            )
            .await?;
        }
        for dpu_machine in dpu_machines.iter() {
            db::machine::advance(
                dpu_machine,
                &mut txn,
                &ManagedHostState::ForceDeletion,
                None,
            )
            .await?;
        }

        txn.commit().await?;

        // We start a new transaction
        // This makeas the ForceDeletion state visible to other consumers

        // Note: The following deletion steps are all ordered in an idempotent fashion

        let mut txn = self
            .txn_begin("delete host and instance in admin_force_delete_machine")
            .await?;

        if let Some(instance_id) = instance_id {
            crate::handlers::instance::force_delete_instance(
                instance_id,
                &self.ib_fabric_manager,
                &self.common_pools,
                &mut response,
                &mut txn,
            )
            .await?;
        }

        if let Some(machine) = &host_machine {
            if let Some(ip) = machine.bmc_info.ip.as_deref() {
                if let Some(bmc_mac_address) = machine.bmc_info.mac {
                    tracing::info!(
                        ip,
                        machine_id = %machine.id,
                        "BMC IP and MAC address for machine was found. Trying to perform Bios unlock",
                    );

                    match self
                        .redfish_pool
                        .create_client(
                            ip,
                            machine.bmc_info.port,
                            RedfishAuth::Key(CredentialKey::BmcCredentials {
                                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                            }),
                            true,
                        )
                        .await
                    {
                        Ok(client) => {
                            let machine_id = machine.id;
                            let mut host_restart_needed = false;
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
                                    // Dell, at least, needs a reboot after disabling lockdown.  Safest to just do this for everything.
                                    host_restart_needed = true;
                                }
                                Err(e) => {
                                    tracing::warn!(%machine_id, error = %e, "Failed to fetch lockdown status");
                                    response.initial_lockdown_state = "".to_string();
                                    response.machine_unlocked = false;
                                }
                            }

                            if machine.bios_password_set_time.is_some() {
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
                                    host_restart_needed = true;
                                }
                            }

                            if host_restart_needed
                                && let Err(e) = client.power(SystemPowerControl::ForceRestart).await
                            {
                                tracing::warn!(%machine_id, error = %e, "Failed to reboot host while force deleting machine");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                machine_id = %machine.id,
                                error = %e,
                                "Failed to create Redfish client. Skipping bios unlock",
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Failed to unlock this host because Forge could not retrieve the BMC MAC address for machine {}",
                        machine.id
                    );
                }
            } else {
                tracing::warn!(
                    "Failed to unlock this host because Forge could not retrieve the BMC IP address for machine {}",
                    machine.id
                );
            }
        }

        if let Some(machine) = &host_machine {
            if request.delete_bmc_interfaces
                && let Some(bmc_ip) = &machine.bmc_info.ip
            {
                response.host_bmc_interface_associated = true;
                if let Ok(ip_addr) = IpAddr::from_str(bmc_ip)
                    && db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                        .await?
                        .is_some()
                {
                    response.host_bmc_interface_deleted = true;
                }
            }
            db::machine::force_cleanup(&mut txn, &machine.id).await?;

            if request.delete_interfaces {
                for interface in &machine.interfaces {
                    db::machine_interface::delete(&interface.id, &mut txn).await?;
                }
                response.host_interfaces_deleted = true;
            }

            if let Some(addr) = &machine.bmc_info.ip
                && let Ok(addr) = IpAddr::from_str(addr)
            {
                tracing::info!("Cleaning up explored endpoint at {addr} {}", machine.id);

                db::explored_endpoints::delete(&mut txn, addr).await?;

                db::explored_managed_host::delete_by_host_bmc_addr(&mut txn, addr).await?;
            }

            if request.delete_bmc_credentials {
                self.clear_bmc_credentials(machine).await?;
            }

            if let Err(e) =
                db_attest::ek_cert_verification_status::delete_ca_verification_status_by_machine_id(
                    &mut txn,
                    &machine.id,
                )
                .await
            {
                // just log the error and carry on
                tracing::error!(
                    "Could not remove EK cert status for machine with id {}: {}",
                    machine.id,
                    e
                );
            }
        }

        txn.commit().await?;

        for dpu_machine in dpu_machines.iter() {
            let mut txn = self
                .txn_begin("delete dpu in admin_force_delete_machine")
                .await?;

            // Free up all loopback IPs allocated for this DPU.
            db::vpc_dpu_loopback::delete_and_deallocate(
                &self.common_pools,
                &dpu_machine.id,
                &mut txn,
                true,
            )
            .await?;

            if let Some(loopback_ip) = dpu_machine.network_config.loopback_ip {
                db::resource_pool::release(
                    &self.common_pools.ethernet.pool_loopback_ip,
                    &mut txn,
                    loopback_ip,
                )
                .await?
            }
            db::network_devices::dpu_to_network_device_map::delete(&mut txn, &dpu_machine.id)
                .await?;

            if request.delete_bmc_interfaces
                && let Some(bmc_ip) = &dpu_machine.bmc_info.ip
            {
                response.dpu_bmc_interface_associated = true;
                if let Ok(ip_addr) = IpAddr::from_str(bmc_ip)
                    && db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                        .await?
                        .is_some()
                {
                    response.dpu_bmc_interface_deleted = true;
                }
            }
            if let Some(asn) = dpu_machine.asn {
                db::resource_pool::release(&self.common_pools.ethernet.pool_fnn_asn, &mut txn, asn)
                    .await?;
            }
            db::machine::force_cleanup(&mut txn, &dpu_machine.id).await?;

            if request.delete_interfaces {
                for interface in &dpu_machine.interfaces {
                    db::machine_interface::delete(&interface.id, &mut txn).await?;
                }
                response.dpu_interfaces_deleted = true;
            }

            if let Some(addr) = &dpu_machine.bmc_info.ip
                && let Ok(addr) = IpAddr::from_str(addr)
            {
                tracing::info!("Cleaning up explored endpoint at {addr} {}", dpu_machine.id);

                db::explored_endpoints::delete(&mut txn, addr).await?;
            }

            if request.delete_bmc_credentials {
                self.clear_bmc_credentials(dpu_machine).await?;
            }

            txn.commit().await?;
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
    ) -> Result<Response<rpc::ResourcePools>, Status> {
        crate::handlers::resource_pool::list(self, request).await
    }

    async fn update_machine_metadata(
        &self,
        request: Request<rpc::MachineMetadataUpdateRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        crate::handlers::machine::update_machine_metadata(self, request).await
    }

    /// Maintenance mode: Put a machine into maintenance mode or take it out.
    /// Switching a host into maintenance mode prevents an instance being assigned to it.
    async fn set_maintenance(
        &self,
        request: Request<rpc::MaintenanceRequest>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);
        let req = request.into_inner();
        let machine_id = convert_and_log_machine_id(req.host_id.as_ref())?;

        let (host_machine, mut txn) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig::default(),
                "maintenance handler",
            )
            .await?;
        if host_machine.is_dpu() {
            return Err(Status::invalid_argument(
                "DPU ID provided. Need managed host.",
            ));
        }
        let dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine_id).await?;

        // We set status on both host and dpu machine to make them easier to query from DB
        match req.operation() {
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
                    Request::new(rpc::InsertHealthReportOverrideRequest {
                        machine_id: req.host_id,
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
                                        health_report::HealthAlertClassification::suppress_external_alerting(),
                                    ],
                                }],
                            }
                            .into()),
                            mode: ::rpc::forge::OverrideMode::Merge.into(),
                        }),
                    }),
                )
                .await?;
            }
            rpc::MaintenanceOperation::Disable => {
                for dpu_machine in dpu_machines.iter() {
                    if dpu_machine.reprovision_requested.is_some() {
                        return Err(Status::invalid_argument(format!(
                            "Reprovisioning request is set on DPU: {}. Clear it first.",
                            &dpu_machine.id
                        )));
                    }
                }

                match crate::handlers::health::remove_health_report_override(
                    self,
                    Request::new(rpc::RemoveHealthReportOverrideRequest {
                        machine_id: req.host_id,
                        source: "maintenance".to_string(),
                    }),
                )
                .await
                {
                    Ok(_) => (),
                    Err(status) if status.code() == tonic::Code::NotFound => (),
                    Err(status) => return Err(status),
                };
            }
        };

        txn.commit().await?;

        Ok(Response::new(()))
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
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.txn_begin("get_power_options").await?;
        let power_options = if req.machine_id.is_empty() {
            db::power_options::get_all(&mut txn).await
        } else {
            db::power_options::get_by_ids(&req.machine_id, &mut txn).await
        }?;

        txn.commit().await?;

        Ok(Response::new(rpc::PowerOptionResponse {
            response: power_options
                .into_iter()
                .map(|x| x.into())
                .collect::<Vec<rpc::PowerOptions>>(),
        }))
    }

    async fn update_power_option(
        &self,
        request: Request<rpc::PowerOptionUpdateRequest>,
    ) -> Result<Response<rpc::PowerOptionResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let machine_id = req
            .machine_id
            .ok_or_else(|| Status::invalid_argument("Machine ID is missing"))?;

        if machine_id.machine_type().is_dpu() {
            return Err(Status::invalid_argument("Only host id is expected!!"));
        }

        log_machine_id(&machine_id);

        let mut txn = self.txn_begin("update_power_options").await?;

        let current_power_state = db::power_options::get_by_ids(&[machine_id], &mut txn).await?;

        // This should never happen until machine is not forced-deleted or does not exist.
        let Some(current_power_options) = current_power_state.first() else {
            return Err(Status::invalid_argument("Only host id is expected!!"));
        };

        let desired_power_state = req.power_state();

        // if desired_state == Off, maintenance must be set.
        if matches!(desired_power_state, rpc::PowerState::Off) {
            let snapshot = db::managed_host::load_snapshot(
                &mut txn,
                &machine_id,
                LoadSnapshotOptions {
                    include_history: false,
                    include_instance_data: false,
                    host_health_config: self.runtime_config.host_health,
                },
            )
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

            // Start reprovisioning only if the host has an HostUpdateInProgress health alert
            let update_alert = snapshot
                .aggregate_health
                .alerts
                .iter()
                .find(|a| a.id == health_report::HealthProbeId::internal_maintenance());
            if !update_alert.is_some_and(|alert| {
                alert.classifications.contains(
                    &health_report::HealthAlertClassification::suppress_external_alerting(),
                )
            }) {
                return Err(Status::invalid_argument(
                    "Machine must have a 'Maintenance' Health Alert with 'SupressExternalAlerting' classification.",
                ));
            }
        }

        // To avoid unnecessary version increment.
        let desired_power_state = desired_power_state.into();
        if desired_power_state == current_power_options.desired_power_state {
            return Err(Status::invalid_argument(format!(
                "Power State is already set as {desired_power_state:?}. No change is performed."
            )));
        }

        let updated_value = db::power_options::update_desired_state(
            &machine_id,
            desired_power_state,
            &current_power_options.desired_power_state_version,
            &mut txn,
        )
        .await?;

        txn.commit().await?;

        Ok(Response::new(rpc::PowerOptionResponse {
            response: vec![updated_value.into()],
        }))
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: Request<rpc::DpuReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        crate::handlers::dpu::trigger_dpu_reprovisioning(self, request).await
    }

    /// List DPUs waiting for reprovisioning
    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: Request<rpc::DpuReprovisioningListRequest>,
    ) -> Result<Response<rpc::DpuReprovisioningListResponse>, Status> {
        log_request_data(&request);

        let mut txn = self
            .txn_begin("list_dpu_waiting_for_reprovisioning")
            .await?;

        let dpus = db::machine::list_machines_requested_for_reprovisioning(&mut txn)
            .await?
            .into_iter()
            .map(
                |x| rpc::dpu_reprovisioning_list_response::DpuReprovisioningListItem {
                    id: Some(x.id),
                    state: x.current_state().to_string(),
                    requested_at: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.requested_at.into()),
                    initiator: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.initiator.clone())
                        .unwrap_or_default(),
                    update_firmware: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.update_firmware)
                        .unwrap_or_default(),
                    initiated_at: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.started_at.map(|x| x.into()))
                        .unwrap_or_default(),
                    user_approval_received: x
                        .reprovision_requested
                        .as_ref()
                        .map(|x| x.user_approval_received)
                        .unwrap_or_default(),
                },
            )
            .collect_vec();

        Ok(Response::new(rpc::DpuReprovisioningListResponse { dpus }))
    }

    async fn trigger_host_reprovisioning(
        &self,
        request: Request<rpc::HostReprovisioningRequest>,
    ) -> Result<Response<()>, Status> {
        use ::rpc::forge::host_reprovisioning_request::Mode;

        log_request_data(&request);
        let req = request.into_inner();
        let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

        let mut txn = self.txn_begin("trigger_host_reprovisioning").await?;

        let snapshot =
            db::managed_host::load_snapshot(&mut txn, &machine_id, LoadSnapshotOptions::default())
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?;

        if let Some(request) = snapshot.host_snapshot.reprovision_requested
            && request.started_at.is_some()
        {
            return Err(
                CarbideError::internal("Reprovisioning is already started.".to_string()).into(),
            );
        }

        match req.mode() {
            Mode::Set => {
                let initiator = req.initiator().as_str_name();
                db::host_machine_update::trigger_host_reprovisioning_request(
                    &mut txn,
                    initiator,
                    &machine_id,
                )
                .await?;
            }
            Mode::Clear => {
                db::host_machine_update::clear_host_reprovisioning_request(&mut txn, &machine_id)
                    .await?;
            }
        }

        txn.commit().await?;

        Ok(Response::new(()))
    }

    async fn list_hosts_waiting_for_reprovisioning(
        &self,
        request: Request<rpc::HostReprovisioningListRequest>,
    ) -> Result<Response<rpc::HostReprovisioningListResponse>, Status> {
        log_request_data(&request);

        let mut txn = self
            .txn_begin("list_hosts_waiting_for_reprovisioning")
            .await?;

        let hosts = db::machine::list_machines_requested_for_host_reprovisioning(&mut txn)
            .await?
            .into_iter()
            .map(
                |x| rpc::host_reprovisioning_list_response::HostReprovisioningListItem {
                    id: Some(x.id),
                    state: x.current_state().to_string(),
                    requested_at: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.requested_at.into()),
                    initiator: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.initiator.clone())
                        .unwrap_or_default(),
                    initiated_at: x
                        .reprovision_requested
                        .as_ref()
                        .map(|a| a.started_at.map(|x| x.into()))
                        .unwrap_or_default(),
                    user_approval_received: x
                        .reprovision_requested
                        .as_ref()
                        .map(|x| x.user_approval_received)
                        .unwrap_or_default(),
                },
            )
            .collect_vec();

        Ok(Response::new(rpc::HostReprovisioningListResponse { hosts }))
    }

    /// Retrieves all DPU information including id and loopback IP
    async fn get_dpu_info_list(
        &self,
        request: Request<rpc::GetDpuInfoListRequest>,
    ) -> Result<Response<rpc::GetDpuInfoListResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.txn_begin("get_dpu_info_list").await?;

        let dpu_list = db::machine::find_dpu_ids_and_loopback_ips(&mut txn).await?;

        txn.commit().await?;

        let response = rpc::GetDpuInfoListResponse { dpu_list };
        Ok(Response::new(response))
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
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.txn_begin("get_network_topology").await?;

        let query = match &req.id {
            Some(x) => ObjectFilter::One(x.as_str()),
            None => ObjectFilter::All,
        };

        let data = db::network_devices::get_topology(&mut txn, query).await?;

        txn.commit().await?;

        Ok(Response::new(data.into()))
    }

    async fn admin_bmc_reset(
        &self,
        request: Request<rpc::AdminBmcResetRequest>,
    ) -> Result<Response<rpc::AdminBmcResetResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: AdminBmcResetRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("admin_bmc_reset").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

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

    async fn disable_secure_boot(
        &self,
        request: Request<rpc::BmcEndpointRequest>,
    ) -> Result<Response<::rpc::forge::DisableSecureBootResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.txn_begin("disable_secure_boot").await?;

        let (bmc_endpoint_request, _) =
            validate_and_complete_bmc_endpoint_request(&mut txn, Some(req), None).await?;

        txn.commit().await?;

        crate::handlers::bmc_endpoint_explorer::disable_secure_boot(
            self,
            bmc_endpoint_request.clone(),
        )
        .await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();
        tracing::info!(
            "disable_secure_boot request succeeded to {}",
            endpoint_address
        );

        Ok(Response::new(rpc::DisableSecureBootResponse {}))
    }

    async fn lockdown(
        &self,
        request: Request<rpc::LockdownRequest>,
    ) -> Result<Response<::rpc::forge::LockdownResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();
        let action = req.action();
        let action = match action {
            ::rpc::forge::LockdownAction::Enable => libredfish::EnabledDisabled::Enabled,
            ::rpc::forge::LockdownAction::Disable => libredfish::EnabledDisabled::Disabled,
        };

        let mut txn = self.txn_begin("lockdown").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await?;

        crate::handlers::bmc_endpoint_explorer::lockdown(
            self,
            bmc_endpoint_request.clone(),
            action,
        )
        .await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();
        tracing::info!(
            "lockdown {} request succeeded to {}",
            action.to_string().to_lowercase(),
            endpoint_address
        );

        Ok(Response::new(rpc::LockdownResponse {}))
    }

    async fn lockdown_status(
        &self,
        request: Request<rpc::LockdownStatusRequest>,
    ) -> Result<Response<::rpc::site_explorer::LockdownStatus>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.txn_begin("lockdown_status").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            req.machine_id,
        )
        .await?;

        txn.commit().await?;

        let response = crate::handlers::bmc_endpoint_explorer::lockdown_status(
            self,
            bmc_endpoint_request.clone(),
        )
        .await?;

        Ok(response)
    }

    async fn enable_infinite_boot(
        &self,
        request: Request<rpc::EnableInfiniteBootRequest>,
    ) -> Result<Response<::rpc::forge::EnableInfiniteBootResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: EnableInfiniteBootRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("enable_infinite_boot").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        crate::handlers::bmc_endpoint_explorer::enable_infinite_boot(
            self,
            bmc_endpoint_request.clone(),
        )
        .await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();
        tracing::info!(
            "enable_infinite_boot request succeeded to {}",
            endpoint_address
        );

        Ok(Response::new(rpc::EnableInfiniteBootResponse {}))
    }

    async fn is_infinite_boot_enabled(
        &self,
        request: Request<rpc::IsInfiniteBootEnabledRequest>,
    ) -> Result<Response<::rpc::forge::IsInfiniteBootEnabledResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: IsInfiniteBootEnabledRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("is_infinite_boot_enabled").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        let response = crate::handlers::bmc_endpoint_explorer::is_infinite_boot_enabled(
            self,
            bmc_endpoint_request.clone(),
        )
        .await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();
        tracing::info!(
            "is_infinite_boot_enabled request succeeded to {}, result: {:?}",
            endpoint_address,
            response.get_ref()
        );

        Ok(Response::new(rpc::IsInfiniteBootEnabledResponse {
            is_enabled: response.into_inner(),
        }))
    }

    async fn forge_setup(
        &self,
        request: Request<rpc::ForgeSetupRequest>,
    ) -> Result<Response<::rpc::forge::ForgeSetupResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: ForgeSetupRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("forge_setup").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!("Starting Forge Setup for BMC: {}", endpoint_address);

        crate::handlers::bmc_endpoint_explorer::forge_setup(
            self,
            rpc::ForgeSetupRequest {
                bmc_endpoint_request: Some(bmc_endpoint_request.clone()),
                machine_id: req.machine_id,
                boot_interface_mac: req.boot_interface_mac,
            },
        )
        .await?;

        tracing::info!("Forge Setup request succeeded to {}", endpoint_address);

        Ok(Response::new(rpc::ForgeSetupResponse {}))
    }

    async fn set_dpu_first_boot_order(
        &self,
        request: Request<rpc::SetDpuFirstBootOrderRequest>,
    ) -> Result<Response<::rpc::forge::SetDpuFirstBootOrderResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: SetDpuFirstBootOrderRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("set_dpu_first_boot_order").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!(
            "Setting DPU first in boot order for BMC: {}",
            endpoint_address
        );

        crate::handlers::bmc_endpoint_explorer::set_dpu_first_boot_order(
            self,
            rpc::SetDpuFirstBootOrderRequest {
                bmc_endpoint_request: Some(bmc_endpoint_request.clone()),
                machine_id: req.machine_id,
                boot_interface_mac: req.boot_interface_mac,
            },
        )
        .await?;

        tracing::info!(
            "Set DPU first in boot order request succeeded to {}",
            endpoint_address
        );

        Ok(Response::new(rpc::SetDpuFirstBootOrderResponse {}))
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

    // Override RUST_LOG or site-explorer create_machines
    async fn set_dynamic_config(
        &self,
        request: Request<rpc::SetDynamicConfigRequest>,
    ) -> Result<Response<()>, Status> {
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
                let level = &self.dynamic_settings.log_filter;
                level.update(&req.value, Some(expire_at)).map_err(|err| {
                    Status::invalid_argument(format!(
                        "Invalid log filter string '{}'. {err}",
                        req.value
                    ))
                })?;
                tracing::info!(
                    "Log filter updated to '{}'; global log level: {}",
                    req.value,
                    tracing_subscriber::filter::LevelFilter::current()
                );
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
                    .store(is_enabled, Ordering::Relaxed);
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
            rpc::ConfigSetting::TracingEnabled => {
                let enable = req.value.parse().map_err(|_| {
                    Status::invalid_argument(format!(
                        "Expected bool for TracingEnabled, got {}",
                        &req.value
                    ))
                })?;
                self.dynamic_settings
                    .tracing_enabled
                    .store(enable, Ordering::Relaxed);
            }
        }
        Ok(Response::new(()))
    }

    async fn clear_host_uefi_password(
        &self,
        request: Request<rpc::ClearHostUefiPasswordRequest>,
    ) -> Result<Response<rpc::ClearHostUefiPasswordResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.txn_begin("clear_host_uefi_password").await?;

        let request = request.into_inner();
        let machine_id = convert_and_log_machine_id(request.host_id.as_ref())?;

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
                host_health_config: self.runtime_config.host_health,
            },
        )
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        let redfish_client = self
            .redfish_pool
            .create_client_from_machine(&snapshot.host_snapshot, &mut txn)
            .await
            .map_err(|e| {
                tracing::error!("unable to create redfish client: {}", e);
                Status::internal(format!(
                    "Could not create connection to Redfish API to {machine_id}, check logs"
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
        request: Request<rpc::SetHostUefiPasswordRequest>,
    ) -> Result<Response<rpc::SetHostUefiPasswordResponse>, Status> {
        log_request_data(&request);
        let request = request.into_inner();
        let machine_id = convert_and_log_machine_id(request.host_id.as_ref())?;

        if !machine_id.machine_type().is_host() {
            return Err(Status::invalid_argument(
                "Carbide only supports setting the UEFI password on discovered hosts",
            ));
        }

        let mut txn = self.txn_begin("set_host_uefi_password").await?;

        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: self.runtime_config.host_health,
            },
        )
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        let redfish_client = self
            .redfish_pool
            .create_client_from_machine(&snapshot.host_snapshot, &mut txn)
            .await
            .map_err(|e| {
                tracing::error!("unable to create redfish client: {}", e);
                Status::internal(format!(
                    "Could not create connection to Redfish API to {machine_id}, check logs"
                ))
            })?;

        let job_id = crate::redfish::set_host_uefi_password(
            redfish_client.as_ref(),
            self.redfish_pool.clone(),
        )
        .await?;

        machine::update_bios_password_set_time(&machine_id, &mut txn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update bios_password_set_time: {}", e);
                Status::internal(format!("Failed to update BIOS password timestamp: {e}"))
            })?;

        txn.commit().await?;

        Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
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

    async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: Request<::rpc::common::MachineIdList>,
    ) -> Result<Response<rpc::ConnectedDeviceList>, Status> {
        log_request_data(&request);

        let mut txn = self
            .txn_begin("find_connected_devices_by_dpu_machine_ids")
            .await?;

        let dpu_ids = request.into_inner().machine_ids;

        let connected_devices =
            db::network_devices::dpu_to_network_device_map::find_by_dpu_ids(&mut txn, &dpu_ids)
                .await?;

        Ok(Response::new(rpc::ConnectedDeviceList {
            connected_devices: connected_devices.into_iter().map_into().collect(),
        }))
    }

    async fn find_network_devices_by_device_ids(
        &self,
        request: Request<rpc::NetworkDeviceIdList>,
    ) -> Result<Response<rpc::NetworkTopologyData>, Status> {
        log_request_data(&request);

        let mut txn = self.txn_begin("find_network_devices_by_device_ids").await?;
        let request = request.into_inner(); // keep lifetime for this scope
        let network_device_ids: Vec<&str> = request
            .network_device_ids
            .iter()
            .map(|d| d.as_str())
            .collect();
        let network_devices = db::network_devices::find(
            &mut txn,
            ObjectFilter::List(&network_device_ids),
            &NetworkDeviceSearchConfig::new(false),
        )
        .await?;

        Ok(Response::new(rpc::NetworkTopologyData {
            network_devices: network_devices.into_iter().map_into().collect(),
        }))
    }

    async fn find_machine_ids_by_bmc_ips(
        &self,
        request: Request<rpc::BmcIpList>,
    ) -> Result<Response<rpc::MachineIdBmcIpPairs>, Status> {
        log_request_data(&request);

        let mut txn = self.txn_begin("find_machine_ids_by_bmc_ips").await?;

        let pairs =
            db::machine_topology::find_machine_bmc_pairs(&mut txn, request.into_inner().bmc_ips)
                .await?;
        let rpc_pairs = rpc::MachineIdBmcIpPairs {
            pairs: pairs
                .into_iter()
                .map(|(machine_id, bmc_ip)| rpc::MachineIdBmcIp {
                    machine_id: Some(machine_id),
                    bmc_ip,
                })
                .collect(),
        };

        Ok(Response::new(rpc_pairs))
    }

    async fn find_mac_address_by_bmc_ip(
        &self,
        request: Request<rpc::BmcIp>,
    ) -> Result<Response<rpc::MacAddressBmcIp>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let bmc_ip = req.bmc_ip;

        let mut txn = self.txn_begin("find_mac_address_by_bmc_ip").await?;

        let interface = db::machine_interface::find_by_ip(&mut txn, bmc_ip.parse().unwrap())
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine_interface",
                id: bmc_ip.clone(),
            })?;

        Ok(Response::new(rpc::MacAddressBmcIp {
            bmc_ip,
            mac_address: interface.mac_address.to_string(),
        }))
    }

    #[cfg(feature = "linux-build")]
    async fn attest_quote(
        &self,
        request: Request<rpc::AttestQuoteRequest>,
    ) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
        log_request_data(&request);

        let mut request = request.into_inner();

        // TODO: consider if this code can be turned into a templated function and reused
        // in bind_attest_key
        let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

        let mut txn = self.txn_begin("machine attestation verify quote").await?;

        let ak_pub_bytes =
            match db_attest::secret_ak_pub::get_by_secret(&mut txn, &request.credential).await? {
                Some(entry) => entry.ak_pub,
                None => {
                    return Err(Status::from(CarbideError::AttestQuoteError(
                        "Could not form SQL query to fetch AK Pub".into(),
                    )));
                }
            };

        let ak_pub = TssPublic::unmarshall(ak_pub_bytes.as_slice()).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshal AK Pub: {e}"))
        })?;

        let attest = Attest::unmarshall(&request.attestation).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshall Attest struct: {e}"))
        })?;

        let signature = Signature::unmarshall(&request.signature).map_err(|e| {
            CarbideError::AttestQuoteError(format!("Could not unmarshall Signature struct: {e}"))
        })?;

        // Make sure sure the signature can at least be verified
        // as valid or invalid. If it can't be verified in any
        // way at all, return an error.
        let signature_valid = attest::verify_signature(&ak_pub, &request.attestation, &signature)
            .inspect_err(|_| {
            tracing::warn!(
                "PCR signature verification failed (event log: {})",
                attest::event_log_to_string(&request.event_log)
            );
        })?;

        // Make sure we can verify the the PCR hash one way
        // or another. If it can't be, return an error.
        let pcr_hash_matches =
            attest::verify_pcr_hash(&attest, &request.pcr_values).inspect_err(|_| {
                tracing::warn!(
                    "PCR hash verification failed (event log: {})",
                    attest::event_log_to_string(&request.event_log)
                );
            })?;

        // And now pass on through the computed signature
        // validity and PCR hash match to see if execution can
        // continue (the event log goes with, since it will be
        // logged in the event of an invalid signature or PCR
        // hash mismatch).
        attest::verify_quote_state(signature_valid, pcr_hash_matches, &request.event_log)?;

        // If we've reached this point, we can now clean up
        // now ephemeral secret data from the database, and send
        // off the PCR values as a MeasurementReport.
        db_attest::secret_ak_pub::delete(&mut txn, &request.credential).await?;

        let pcr_values: ::measured_boot::pcr::PcrRegisterValueVec = request
            .pcr_values
            .drain(..)
            .map(hex::encode)
            .collect::<Vec<String>>()
            .into();

        // In this case, we're not doing anything with
        // the resulting report (at least not yet), so just
        // throw it away.
        let report = db::measured_boot::report::new_with_txn(
            &mut txn,
            machine_id,
            pcr_values.into_inner().as_slice(),
        )
        .await
        .map_err(|e| {
            Status::internal(format!(
                "Failed storing measurement report: (machine_id: {}, err: {})",
                &machine_id, e
            ))
        })?;

        txn.commit().await?;

        // if the attestation was successful and enabled, we can now vend the certs
        // - get attestation result
        // - if enabled and not successful, send response without certs
        // - else send response with certs
        let mut txn = self.txn_begin("machine attestation verify quote").await?;

        if self.runtime_config.attestation_enabled
            && !attest::has_passed_attestation(&mut txn, &machine_id, &report.report_id).await?
        {
            tracing::info!(
                "Attestation failed for machine with id {} - not vending any certs",
                machine_id
            );
            return Ok(Response::new(rpc::AttestQuoteResponse {
                success: false,
                machine_certificate: None,
            }));
        }

        let id_str = machine_id.to_string();
        let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            forge_secrets::certificates::Certificate::default()
        } else {
            self.certificate_provider
                .get_certificate(id_str.as_str(), None, None)
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
        };

        tracing::info!(
            "Attestation succeeded for machine with id {} - sending a cert back. Attestion_enabled is {}",
            machine_id,
            self.runtime_config.attestation_enabled
        );
        Ok(Response::new(rpc::AttestQuoteResponse {
            success: true,
            machine_certificate: Some(certificate.into()),
        }))
    }

    #[cfg(not(feature = "linux-build"))]
    async fn attest_quote(
        &self,
        request: Request<rpc::AttestQuoteRequest>,
    ) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
        log_request_data(&request);
        unimplemented!()
    }
    async fn create_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_create_system_measurement_profile(
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
            )
            .await?,
        ))
    }

    async fn show_measurement_reports(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_reports(self, request.into_inner())
                .await?,
        ))
    }

    async fn list_measurement_report(
        &self,
        request: Request<measured_boot_pb::ListMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_list_measurement_report(self, request.into_inner())
                .await?,
        ))
    }

    async fn match_measurement_report(
        &self,
        request: Request<measured_boot_pb::MatchMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::MatchMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_match_measurement_report(self, request.into_inner())
                .await?,
        ))
    }

    async fn create_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_create_measurement_bundle(
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
            )
            .await?,
        ))
    }

    async fn show_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundle(self, request.into_inner())
                .await?,
        ))
    }

    async fn show_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundles(self, request.into_inner())
                .await?,
        ))
    }

    async fn list_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundles(self, request.into_inner())
                .await?,
        ))
    }

    async fn list_measurement_bundle_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundleMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundleMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundle_machines(
                self,
                request.into_inner(),
            )
            .await?,
        ))
    }

    async fn find_closest_bundle_match(
        &self,
        request: Request<measured_boot_pb::FindClosestBundleMatchRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_find_closest_match(self, request.into_inner())
                .await?,
        ))
    }

    async fn delete_measurement_journal(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_delete_measurement_journal(
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
            )
            .await?,
        ))
    }

    async fn show_candidate_machine(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machine(self, request.into_inner())
                .await?,
        ))
    }

    async fn show_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machines(self, request.into_inner())
                .await?,
        ))
    }

    async fn list_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ListCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_list_candidate_machines(self, request.into_inner())
                .await?,
        ))
    }

    async fn import_site_measurements(
        &self,
        request: Request<measured_boot_pb::ImportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ImportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_import_site_measurements(self, request.into_inner())
                .await?,
        ))
    }

    async fn export_site_measurements(
        &self,
        request: Request<measured_boot_pb::ExportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ExportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_export_site_measurements(self, request.into_inner())
                .await?,
        ))
    }

    async fn add_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_add_measurement_trusted_machine(
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
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
                self,
                request.into_inner(),
            )
            .await?,
        ))
    }

    async fn list_attestation_summary(
        &self,
        request: Request<measured_boot_pb::ListAttestationSummaryRequest>,
    ) -> Result<Response<measured_boot_pb::ListAttestationSummaryResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_list_attestation_summary(self, request.into_inner())
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
        let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

        let (machine, mut txn) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig::default(),
                "reboot_completed",
            )
            .await?;
        db::machine::update_reboot_time(&machine, &mut txn).await?;

        txn.commit().await?;

        Ok(Response::new(rpc::MachineRebootCompletedResponse {}))
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
        log_request_data(&request);
        let req = request.into_inner();

        // Note: AdminPowerControlRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let action = req.action();

        let mut txn = self.txn_begin("admin_power_control").await?;

        let (bmc_endpoint_request, machine_id) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

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
            ::rpc::forge::admin_power_control_request::SystemPowerControl::AcPowercycle => {
                libredfish::SystemPowerControl::ACPowercycle
            }
        };

        let mut msg: Option<String> = None;
        if let Some(machine_id) = machine_id {
            let power_manager_enabled = self.runtime_config.power_manager_options.enabled;
            if power_manager_enabled {
                let snapshot = db::managed_host::load_snapshot(
                    &mut txn,
                    &machine_id,
                    LoadSnapshotOptions {
                        include_history: true,
                        include_instance_data: false,
                        host_health_config: self.runtime_config.host_health,
                    },
                )
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?;

                if let Some(power_state) = snapshot
                    .host_snapshot
                    .power_options
                    .map(|x| x.desired_power_state)
                    && power_state == model::power_manager::PowerState::On
                    && action == libredfish::SystemPowerControl::ForceOff
                {
                    msg = Some(
                        "!!WARNING!! Desired power state for the host is set as On while the requested action is Off. Carbide will attempt to bring the host online after some time.".to_string(),
                    )
                }
            }
        }

        txn.commit().await?;

        crate::handlers::bmc_endpoint_explorer::redfish_power_control(
            self,
            bmc_endpoint_request,
            action,
        )
        .await?;

        Ok(Response::new(rpc::AdminPowerControlResponse { msg }))
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
        log_request_data(&request);

        let entries = self
            .runtime_config
            .get_firmware_config()
            .map()
            .into_values()
            .map(|firmware| {
                let vendor = firmware.vendor;
                let model = firmware.model.clone();
                let component_versions = DesiredFirmwareVersions::from(firmware).versions;

                Ok::<_, serde_json::Error>(rpc::DesiredFirmwareVersionEntry {
                    vendor: vendor.to_string(),
                    model,
                    // Launder firmware.components through serde::value to convert FirmwareComponentType
                    // to String (serde is configured to lowercase it.)
                    component_versions: serde_json::from_value(serde_json::to_value(
                        component_versions,
                    )?)?,
                })
            })
            .try_collect()
            .map_err(CarbideError::from)?;
        Ok(Response::new(rpc::GetDesiredFirmwareVersionsResponse {
            entries,
        }))
    }

    async fn create_sku(
        &self,
        request: Request<rpc::SkuList>,
    ) -> Result<Response<rpc::SkuIdList>, Status> {
        Ok(crate::handlers::sku::create(self, request).await?)
    }

    async fn delete_sku(&self, request: Request<SkuIdList>) -> Result<Response<()>, Status> {
        Ok(crate::handlers::sku::delete(self, request).await?)
    }
    async fn generate_sku_from_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<rpc::Sku>, Status> {
        Ok(crate::handlers::sku::generate_from_machine(self, request).await?)
    }
    async fn verify_sku_for_machine(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<()>, Status> {
        Ok(crate::handlers::sku::verify_for_machine(self, request).await?)
    }
    async fn assign_sku_to_machine(
        &self,
        request: Request<::rpc::forge::SkuMachinePair>,
    ) -> Result<Response<()>, Status> {
        Ok(crate::handlers::sku::assign_to_machine(self, request).await?)
    }

    async fn remove_sku_association(
        &self,
        request: Request<MachineId>,
    ) -> Result<Response<()>, Status> {
        Ok(crate::handlers::sku::remove_sku_association(self, request).await?)
    }

    async fn get_all_sku_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::SkuIdList>, Status> {
        Ok(crate::handlers::sku::get_all_ids(self, request).await?)
    }

    async fn find_skus_by_ids(
        &self,
        request: Request<rpc::SkusByIdsRequest>,
    ) -> Result<Response<rpc::SkuList>, Status> {
        Ok(crate::handlers::sku::find_skus_by_ids(self, request).await?)
    }

    async fn update_sku_metadata(
        &self,
        request: Request<rpc::SkuUpdateMetadataRequest>,
    ) -> Result<Response<()>, Status> {
        Ok(crate::handlers::sku::update_sku_metadata(self, request).await?)
    }

    async fn replace_sku(&self, request: Request<rpc::Sku>) -> Result<Response<rpc::Sku>, Status> {
        Ok(crate::handlers::sku::replace_sku(self, request).await?)
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
        log_request_data(&request);
        let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

        let mut txn = self.txn_begin("reset_host_reprovisioning").await?;

        db::host_machine_update::reset_host_reprovisioning_request(&mut txn, &machine_id, false)
            .await?;
        txn.commit().await?;

        Ok(Response::new(()))
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        request: Request<rpc::CopyBfbToDpuRshimRequest>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let (bmc_endpoint_request, ssh_config) = match req.ssh_request {
            Some(ssh_req) => match ssh_req.endpoint_request {
                Some(bmc_request) => {
                    // Port 22 is the default SSH port--carbide-api assumes port :4443
                    let ip_address: String = if bmc_request.ip_address.contains(':') {
                        bmc_request.ip_address
                    } else {
                        format!("{}:22", bmc_request.ip_address)
                    };

                    (
                        BmcEndpointRequest {
                            ip_address,
                            mac_address: bmc_request.mac_address,
                        },
                        ssh_req.timeout_config,
                    )
                }
                None => {
                    return Err(CarbideError::MissingArgument("bmc_endpoint_request").into());
                }
            },
            None => {
                return Err(CarbideError::MissingArgument("ssh_request").into());
            }
        };

        crate::handlers::bmc_endpoint_explorer::copy_bfb_to_dpu_rshim(
            self,
            &bmc_endpoint_request,
            ssh_config,
        )
        .await?;

        Ok(Response::new(()))
    }

    // Return a Vector of all the DPA interface IDs
    async fn get_all_dpa_interface_ids(
        &self,
        request: Request<()>,
    ) -> Result<Response<rpc::DpaInterfaceIdList>, Status> {
        Ok(crate::handlers::dpa::get_all_ids(self, request).await?)
    }

    // Given a Vector of DPA Interface IDs, return the corresponding
    // DPA Interfaces in a Vector
    async fn find_dpa_interfaces_by_ids(
        &self,
        request: Request<rpc::DpaInterfacesByIdsRequest>,
    ) -> Result<Response<rpc::DpaInterfaceList>, Status> {
        Ok(crate::handlers::dpa::find_dpa_interfaces_by_ids(self, request).await?)
    }

    // create_dpa_interface is mainly for debugging purposes. In practice,
    // when the scout reports its inventory, we will create DPA interfaces
    // for DPA NICs reported in the inventory.
    async fn create_dpa_interface(
        &self,
        request: Request<rpc::DpaInterfaceCreationRequest>,
    ) -> Result<Response<rpc::DpaInterface>, Status> {
        if !self.runtime_config.is_dpa_enabled() {
            return Err(CarbideError::InvalidArgument(
                "CreateDpaInterface cannot be done as dpa_enabled is false".to_string(),
            )
            .into());
        }
        Ok(crate::handlers::dpa::create(self, request).await?)
    }

    // delete_dpa_interface is mainly for debugging purposes.
    async fn delete_dpa_interface(
        &self,
        request: Request<rpc::DpaInterfaceDeletionRequest>,
    ) -> Result<Response<rpc::DpaInterfaceDeletionResult>, Status> {
        if !self.runtime_config.is_dpa_enabled() {
            return Err(CarbideError::InvalidArgument(
                "DeleteDpaInterface cannot be done as dpa_enabled is false".to_string(),
            )
            .into());
        }
        Ok(crate::handlers::dpa::delete(self, request).await?)
    }

    // set_dpa_network_observaction_status is for debugging purposes.
    // In practice, the MQTT subscriber running in Carbide will update
    // the observation status
    async fn set_dpa_network_observation_status(
        &self,
        request: Request<rpc::DpaNetworkObservationSetRequest>,
    ) -> Result<Response<rpc::DpaInterface>, Status> {
        Ok(crate::handlers::dpa::set_dpa_network_observation_status(self, request).await?)
    }

    async fn create_bmc_user(
        &self,
        request: Request<rpc::CreateBmcUserRequest>,
    ) -> Result<Response<rpc::CreateBmcUserResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: CreateBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("create_bmc_user").await?;

        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        let role: RoleId = match req
            .create_role_id
            .unwrap_or("Administrator".to_string())
            .to_lowercase()
            .as_str()
        {
            "administrator" => RoleId::Administrator,
            "operator" => RoleId::Operator,
            "readonly" => RoleId::ReadOnly,
            "noaccess" => RoleId::NoAccess,
            _ => RoleId::Administrator,
        };

        tracing::info!(
            "Creating BMC User {} ({role}) on {endpoint_address}",
            req.create_username,
        );

        crate::handlers::bmc_endpoint_explorer::create_bmc_user(
            self,
            &bmc_endpoint_request,
            &req.create_username,
            &req.create_password,
            role,
        )
        .await?;

        tracing::info!(
            "Successfully created BMC User {} ({role}) on {endpoint_address}",
            req.create_username
        );

        Ok(Response::new(rpc::CreateBmcUserResponse {}))
    }

    async fn delete_bmc_user(
        &self,
        request: Request<rpc::DeleteBmcUserRequest>,
    ) -> Result<Response<rpc::DeleteBmcUserResponse>, Status> {
        log_request_data(&request);
        let req = request.into_inner();

        // Note: DeleteBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
        let machine_id = req
            .machine_id
            .as_ref()
            .map(|id| try_parse_machine_id(id))
            .transpose()?;

        let mut txn = self.txn_begin("delete_bmc_user").await?;
        let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
            &mut txn,
            req.bmc_endpoint_request,
            machine_id,
        )
        .await?;

        txn.commit().await?;

        let endpoint_address = bmc_endpoint_request.ip_address.clone();

        tracing::info!(
            "Deleting BMC User {} on {endpoint_address}",
            req.delete_username,
        );

        crate::handlers::bmc_endpoint_explorer::delete_bmc_user(
            self,
            &bmc_endpoint_request,
            &req.delete_username,
        )
        .await?;

        tracing::info!(
            "Successfully deleted BMC User {} on {endpoint_address}",
            req.delete_username
        );

        Ok(Response::new(rpc::DeleteBmcUserResponse {}))
    }

    async fn set_firmware_update_time_window(
        &self,
        request: Request<rpc::SetFirmwareUpdateTimeWindowRequest>,
    ) -> Result<Response<rpc::SetFirmwareUpdateTimeWindowResponse>, Status> {
        let request = request.into_inner();
        let start = request.start_timestamp.unwrap_or_default().seconds;
        let end = request.end_timestamp.unwrap_or_default().seconds;
        // Sanity checks
        if start != 0 || end != 0 {
            if start == 0 || end == 0 {
                return Err(CarbideError::InvalidArgument(
                    "Start and end must both be zero or nonzero".to_string(),
                )
                .into());
            }
            if start >= end {
                return Err(
                    CarbideError::InvalidArgument("Start must precede end".to_string()).into(),
                );
            }
            if end < chrono::Utc::now().timestamp() {
                return Err(
                    CarbideError::InvalidArgument("End occurs in the past".to_string()).into(),
                );
            }
        }

        let mut txn = self.txn_begin("set_firmware_update_time_window").await?;

        tracing::info!(
            "set_firmware_update_time_window: Setting update start/end ({:?} {:?}) for {:?}",
            chrono::Utc.timestamp_opt(start, 0),
            chrono::Utc.timestamp_opt(end, 0),
            request.machine_ids
        );

        db::machine::update_firmware_update_time_window_start_end(
            &request.machine_ids,
            chrono::Utc
                .timestamp_opt(request.start_timestamp.unwrap_or_default().seconds, 0)
                .earliest()
                .unwrap_or(chrono::Utc::now()),
            chrono::Utc
                .timestamp_opt(request.end_timestamp.unwrap_or_default().seconds, 0)
                .earliest()
                .unwrap_or(chrono::Utc::now()),
            &mut txn,
        )
        .await?;

        txn.commit().await?;

        Ok(Response::new(rpc::SetFirmwareUpdateTimeWindowResponse {}))
    }

    async fn list_host_firmware(
        &self,
        _request: Request<rpc::ListHostFirmwareRequest>,
    ) -> Result<Response<rpc::ListHostFirmwareResponse>, Status> {
        let mut ret = vec![];
        for (_, entry) in self.runtime_config.get_firmware_config().map() {
            for (component, component_info) in entry.components {
                for firmware in component_info.known_firmware {
                    if firmware.default {
                        ret.push(rpc::AvailableHostFirmware {
                            vendor: entry.vendor.to_string(),
                            model: entry.model.clone(),
                            r#type: component.to_string(),
                            inventory_name_regex: component_info
                                .current_version_reported_as
                                .clone()
                                .map(|x| x.as_str().to_string())
                                .unwrap_or("UNSPECIFIED".to_string()),
                            version: firmware.version.clone(),
                            needs_explicit_start: entry.explicit_start_needed,
                        });
                    }
                }
            }
        }
        Ok(Response::new(rpc::ListHostFirmwareResponse {
            available: ret,
        }))
    }

    async fn publish_mlx_device_report(
        &self,
        request: Request<mlx_device_pb::PublishMlxDeviceReportRequest>,
    ) -> Result<Response<mlx_device_pb::PublishMlxDeviceReportResponse>, Status> {
        // TODO(chet): Integrate this once it's time. For now, just log
        // that a report was received, that we can successfully convert
        // it from an RPC message back to an MlxDeviceReport, and drop it.
        log_request_data(&request);
        let req = request.into_inner();
        if let Some(report_pb) = req.report {
            let report: MlxDeviceReport = report_pb
                .try_into()
                .map_err(|e: String| Status::internal(e))?;
            tracing::info!(
                "received MlxDeviceReport hostname={} device_count={}",
                report.hostname,
                report.devices.len(),
            );
        } else {
            tracing::warn!("no embedded MlxDeviceReport published");
        }
        Ok(Response::new(
            mlx_device_pb::PublishMlxDeviceReportResponse {},
        ))
    }

    async fn trim_table(
        &self,
        request: Request<rpc::TrimTableRequest>,
    ) -> Result<Response<rpc::TrimTableResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.txn_begin("trim_table").await?;

        let total_deleted = db::trim_table::trim_table(
            &mut txn,
            request.get_ref().target(),
            request.get_ref().keep_entries,
        )
        .await?;

        txn.commit().await?;

        Ok(Response::new(rpc::TrimTableResponse {
            total_deleted: total_deleted.to_string(),
        }))
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

    // This is a work-around for FORGE-7085.  Due to an issue with interface reporting in the host BMC
    // its possible that the primary DPU is not the lowest slot DPU.  Functionally this is not a problem
    // but the host names interfaces by pci address so the behavior between machines of the same type
    // is different.
    //
    // this function is broken into the following parts
    // 1. collect interface and bmc information
    // 2. set the boot device
    // 3. update the primary interface and network config versions.
    // 4. reboot the host if requested.
    //
    // No transaction should be held during 2 or 4 since they are requests to the host bmc.
    //
    async fn set_primary_dpu(
        &self,
        request: Request<rpc::SetPrimaryDpuRequest>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let host_machine_id = request.host_machine_id.ok_or_else(|| {
            CarbideError::InvalidArgument("Host Machine ID is required".to_string())
        })?;
        let dpu_machine_id = request.dpu_machine_id.ok_or_else(|| {
            CarbideError::InvalidArgument("DPU Machine ID is required".to_string())
        })?;

        log_machine_id(&host_machine_id);

        let mut txn = self.txn_begin("set_primary_dpu").await?;

        let interface_map =
            db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;

        let interface_snapshots =
            interface_map
                .get(&host_machine_id)
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "Machine",
                    id: host_machine_id.to_string(),
                })?;

        // Find the interface id for the old primary dpu and the interface for the new primary dpu.  they have to be found
        // before the db update since the "only one primary" constraint will cause a failure
        // if the new interface is found first.
        let mut current_primary_interface_id = None;
        let mut new_primary_interface = None;

        for interface_snapshot in interface_snapshots {
            if interface_snapshot.primary_interface {
                let Some(attached_dpu_machine_id) = interface_snapshot.attached_dpu_machine_id
                else {
                    return Err(CarbideError::InvalidArgument(
                        "Primary interface is not associated with a DPU.  Operation not supported"
                            .to_string(),
                    )
                    .into());
                };

                if attached_dpu_machine_id == dpu_machine_id {
                    return Err(CarbideError::InvalidArgument(
                        "Requested DPU is already primary".to_string(),
                    )
                    .into());
                }
                current_primary_interface_id = Some(interface_snapshot.id);
                tracing::info!("Removing primary from {}", attached_dpu_machine_id);
            } else if interface_snapshot.attached_dpu_machine_id == Some(dpu_machine_id) {
                new_primary_interface = Some(interface_snapshot);
                tracing::info!("Setting primary on {}", dpu_machine_id);
            }
        }

        // we need to set the boot device or the host will no longer be able to boot.  we need BMC info.
        // the same BMC info is used if a reboot was requested.
        let machine =
            db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "Machine",
                    id: host_machine_id.to_string(),
                })?;

        let bmc_addr_str = machine
            .bmc_info
            .ip
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "BMC IP",
                id: host_machine_id.to_string(),
            })?;

        let bmc_addr = IpAddr::from_str(&bmc_addr_str).map_err(CarbideError::AddressParseError)?;
        let bmc_socket_addr = SocketAddr::new(bmc_addr, 443);

        let bmc_interface = db::machine_interface::find_by_ip(&mut txn, bmc_addr)
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "BMC Interface",
                id: bmc_addr.to_string(),
            })?;

        let primary_interface_mac_address = new_primary_interface
            .ok_or_else(|| {
                CarbideError::internal("Primary interface disappeared during update".to_string())
            })?
            .mac_address
            .to_string();

        txn.rollback().await?;

        let Some(current_primary_interface_id) = current_primary_interface_id else {
            return Err(CarbideError::internal(
                "Could not determing old primary interface id".to_string(),
            )
            .into());
        };
        let Some(new_primary_interface) = new_primary_interface else {
            return Err(CarbideError::internal(
                "Could not determing new primary interface id".to_string(),
            )
            .into());
        };

        // set the boot device
        self.endpoint_explorer
            .set_boot_order_dpu_first(
                bmc_socket_addr,
                &bmc_interface,
                &primary_interface_mac_address,
            )
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

        let mut txn = self.txn_begin("set_primary_dpu").await?;

        // update the primary interface
        db::machine_interface::set_primary_interface(
            &current_primary_interface_id,
            false,
            &mut txn,
        )
        .await?;
        db::machine_interface::set_primary_interface(&new_primary_interface.id, true, &mut txn)
            .await?;

        // increment the network config version so that the DPUs pick up their new config
        let (network_config, network_config_version) =
            db::machine::get_network_config(&mut txn, &host_machine_id)
                .await?
                .take();
        db::machine::try_update_network_config(
            &mut txn,
            &host_machine_id,
            network_config_version,
            &network_config,
        )
        .await?;

        // if there is an instance, update the instances network config version so the DPUs pick up the new config
        if let Some(instance) = db::instance::find_by_machine_id(&mut txn, &host_machine_id).await?
        {
            db::instance::update_network_config(
                &mut txn,
                instance.id,
                instance.network_config_version,
                &instance.config.network,
                true,
            )
            .await?;
        }

        txn.commit().await?;

        // optionally reboot the host.  if there is an instance, this is probably a required step,
        // but an operator will need to make that call.  The scout image handles this pretty well,
        // albeit with a leftover IP on the unused interface
        if request.reboot {
            self.endpoint_explorer
                .redfish_power_control(
                    bmc_socket_addr,
                    &bmc_interface,
                    libredfish::SystemPowerControl::ForceRestart,
                )
                .await
                .map_err(|e| CarbideError::internal(e.to_string()))?;
        }
        Ok(Response::new(()))
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
    txn: &mut PgConnection,
    bmc_endpoint_request: Option<rpc::BmcEndpointRequest>,
    machine_id: Option<MachineId>,
) -> Result<(rpc::BmcEndpointRequest, Option<MachineId>), Status> {
    match (bmc_endpoint_request, machine_id) {
        (Some(bmc_endpoint_request), _) => {
            let interface = db::machine_interface::find_by_ip(
                txn,
                bmc_endpoint_request.ip_address.parse().unwrap(),
            )
            .await?
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

            Ok((
                BmcEndpointRequest {
                    ip_address: bmc_endpoint_request.ip_address,
                    mac_address: Some(bmc_mac),
                },
                interface.machine_id,
            ))
        }
        // User provided machine_id
        (_, Some(machine_id)) => {
            log_machine_id(&machine_id);

            let mut topologies =
                db::machine_topology::find_latest_by_machine_ids(txn, &[machine_id]).await?;

            let topology =
                topologies
                    .remove(&machine_id)
                    .ok_or_else(|| CarbideError::NotFoundError {
                        kind: "machine",
                        id: machine_id.to_string(),
                    })?;

            let bmc_ip = topology.topology().bmc_info.ip.as_ref().ok_or_else(|| {
                CarbideError::internal(format!(
                    "Machine found for {machine_id} but BMC IP is missing"
                ))
            })?;

            let bmc_mac_address = topology.topology().bmc_info.mac.ok_or_else(|| {
                CarbideError::internal(format!("BMC endpoint for {bmc_ip} ({machine_id}) found but does not have associated MAC"))
            })?;

            Ok((
                BmcEndpointRequest {
                    ip_address: bmc_ip.to_owned(),
                    mac_address: Some(bmc_mac_address.to_string()),
                },
                Some(machine_id),
            ))
        }

        _ => Err(Status::invalid_argument(
            "Provide either machine_id or BmcEndpointRequest with at least ip_address",
        )),
    }
}

impl Api {
    pub async fn txn_begin(
        &self,
        name: &'static str,
    ) -> Result<db::Transaction<'_>, DatabaseError> {
        db::Transaction::begin(&self.database_connection, name).await
    }

    pub(crate) async fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
        txn_name: &'static str,
    ) -> CarbideResult<(Machine, db::Transaction<'_>)> {
        let mut txn = self.txn_begin(txn_name).await?;

        let machine = match db::machine::find_one(&mut txn, machine_id, search_config).await {
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

    pub fn log_filter_string(&self) -> String {
        self.dynamic_settings.log_filter.to_string()
    }

    async fn clear_bmc_credentials(&self, machine: &Machine) -> Result<(), CarbideError> {
        if let Some(mac_address) = machine.bmc_info.mac {
            tracing::info!(
                "Cleaning up BMC credentials in vault at {} for machine {}",
                mac_address,
                machine.id
            );
            crate::handlers::credential::delete_bmc_root_credentials_by_mac(self, mac_address)
                .await?;
        }

        Ok(())
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
