use crate::Uuid;
use crate::common::MachineIdList;
use crate::forge::dns_message::{DnsQuestion, DnsResponse};
use crate::forge::*;
use crate::forge_tls_client::{
    ApiConfig, ForgeClientConfig, ForgeClientT, ForgeTlsClientResult, RetryConfig,
};
use crate::protos::measured_boot::*;
use crate::site_explorer::*;
use crate::*;
use std::fs;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;
use tonic::{Request, Status};

#[derive(Clone, Debug)]
pub struct ForgeApiClient {
    inner: Arc<ForgeApiClientInner>,
}

#[derive(Debug)]
struct ForgeApiClientInner {
    url: String,
    client_config: ForgeClientConfig,
    retry_config: RetryConfig,
    connection: Mutex<Option<InnerConnection>>,
}

#[derive(Debug)]
struct InnerConnection {
    client: ForgeClientT,
    created: SystemTime,
}

impl ForgeApiClient {
    pub fn new(api_config: &ApiConfig<'_>) -> Self {
        Self {
            inner: Arc::new(ForgeApiClientInner {
                url: api_config.url.to_owned(),
                client_config: api_config.client_config.clone(),
                retry_config: api_config.retry_config,
                connection: Mutex::new(None),
            }),
        }
    }

    pub async fn connect_eagerly(&self) -> ForgeTlsClientResult<()> {
        self.connection().await.map(|_| ())
    }

    /// Causes this client to drop its internal ForgeClientT and construct a new one from the
    /// original configuration passed to it. This will cause client certificates to be reloaded.
    pub async fn reload_config(&self) -> ForgeTlsClientResult<()> {
        self.inner.connection.lock().await.take();
        self.connect_eagerly().await?;
        Ok(())
    }

    pub async fn connection(&self) -> ForgeTlsClientResult<ForgeClientT> {
        let mut guard = self.inner.connection.lock().await;

        // If the on-disk cert is newer than the connection, drop it and reload it
        if let Some(connection) = guard.deref() {
            if let Some(ref client_cert) = self.inner.client_config.client_cert {
                if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                    if mtime > connection.created {
                        let old_cert_date = DateTime::<Utc>::from(connection.created);
                        let new_cert_date = DateTime::<Utc>::from(mtime);
                        tracing::info!(
                            cert_path = &client_cert.cert_path,
                            %old_cert_date,
                            %new_cert_date,
                            "ForgeApiClient: Reconnecting to pick up newer client certificate"
                        );
                        guard.take();
                    }
                } else if let Ok(mtime) =
                    fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
                {
                    // Just in case the cert and key are created some amount of time apart and we
                    // last constructed a client with the new cert but the old key...
                    if mtime > connection.created {
                        let old_key_date = DateTime::<Utc>::from(connection.created);
                        let new_key_date = DateTime::<Utc>::from(mtime);
                        tracing::info!(
                            key_path = &client_cert.key_path,
                            %old_key_date,
                            %new_key_date,
                            "ForgeApiClient: Reconnecting to pick up newer client key"
                        );
                        guard.take();
                    }
                }
            }
        }

        match guard.deref() {
            Some(connection) => Ok(connection.client.clone()),
            None => {
                let client = forge_tls_client::ForgeTlsClient::retry_build(
                    &ApiConfig::new(&self.inner.url, &self.inner.client_config)
                        .with_retry_config(self.inner.retry_config),
                )
                .await?;
                guard.replace(InnerConnection {
                    client: client.clone(),
                    created: SystemTime::now(),
                });
                Ok(client)
            }
        }
    }

    pub fn url(&self) -> &String {
        &self.inner.url
    }

    // MARK -- gRPC methods
    pub async fn version(&self, request: VersionRequest) -> Result<BuildInfo, Status> {
        Ok(self
            .connection()
            .await?
            .version(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_domain(&self, request: Domain) -> Result<Domain, Status> {
        Ok(self
            .connection()
            .await?
            .create_domain(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_domain(&self, request: Domain) -> Result<Domain, Status> {
        Ok(self
            .connection()
            .await?
            .update_domain(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_domain(
        &self,
        request: DomainDeletion,
    ) -> Result<DomainDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_domain(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_domain(&self, request: DomainSearchQuery) -> Result<DomainList, Status> {
        Ok(self
            .connection()
            .await?
            .find_domain(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_vpc(&self, request: VpcCreationRequest) -> Result<Vpc, Status> {
        Ok(self
            .connection()
            .await?
            .create_vpc(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_vpc(&self, request: VpcUpdateRequest) -> Result<VpcUpdateResult, Status> {
        Ok(self
            .connection()
            .await?
            .update_vpc(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_vpc_virtualization(
        &self,
        request: VpcUpdateVirtualizationRequest,
    ) -> Result<VpcUpdateVirtualizationResult, Status> {
        Ok(self
            .connection()
            .await?
            .update_vpc_virtualization(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_vpc(
        &self,
        request: VpcDeletionRequest,
    ) -> Result<VpcDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_vpc(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_vpc_ids(&self, request: VpcSearchFilter) -> Result<VpcIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_vpc_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_vpcs_by_ids(&self, request: VpcsByIdsRequest) -> Result<VpcList, Status> {
        Ok(self
            .connection()
            .await?
            .find_vpcs_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_vpcs(&self, request: VpcSearchQuery) -> Result<VpcList, Status> {
        Ok(self
            .connection()
            .await?
            .find_vpcs(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_vpc_prefix(
        &self,
        request: VpcPrefixCreationRequest,
    ) -> Result<VpcPrefix, Status> {
        Ok(self
            .connection()
            .await?
            .create_vpc_prefix(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn search_vpc_prefixes(
        &self,
        request: VpcPrefixSearchQuery,
    ) -> Result<VpcPrefixIdList, Status> {
        Ok(self
            .connection()
            .await?
            .search_vpc_prefixes(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_vpc_prefixes(
        &self,
        request: VpcPrefixGetRequest,
    ) -> Result<VpcPrefixList, Status> {
        Ok(self
            .connection()
            .await?
            .get_vpc_prefixes(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_vpc_prefix(
        &self,
        request: VpcPrefixUpdateRequest,
    ) -> Result<VpcPrefix, Status> {
        Ok(self
            .connection()
            .await?
            .update_vpc_prefix(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_vpc_prefix(
        &self,
        request: VpcPrefixDeletionRequest,
    ) -> Result<VpcPrefixDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_vpc_prefix(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_segment_ids(
        &self,
        request: NetworkSegmentSearchFilter,
    ) -> Result<NetworkSegmentIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_segment_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_segments_by_ids(
        &self,
        request: NetworkSegmentsByIdsRequest,
    ) -> Result<NetworkSegmentList, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_segments_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_segments(
        &self,
        request: NetworkSegmentQuery,
    ) -> Result<NetworkSegmentList, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_segments(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_network_segment(
        &self,
        request: NetworkSegmentCreationRequest,
    ) -> Result<NetworkSegment, Status> {
        Ok(self
            .connection()
            .await?
            .create_network_segment(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_network_segment(
        &self,
        request: NetworkSegmentDeletionRequest,
    ) -> Result<NetworkSegmentDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_network_segment(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn network_segments_for_vpc(
        &self,
        request: VpcSearchQuery,
    ) -> Result<NetworkSegmentList, Status> {
        Ok(self
            .connection()
            .await?
            .network_segments_for_vpc(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_ib_partition_ids(
        &self,
        request: IbPartitionSearchFilter,
    ) -> Result<IbPartitionIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_ib_partition_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_ib_partitions_by_ids(
        &self,
        request: IbPartitionsByIdsRequest,
    ) -> Result<IbPartitionList, Status> {
        Ok(self
            .connection()
            .await?
            .find_ib_partitions_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_ib_partitions(
        &self,
        request: IbPartitionQuery,
    ) -> Result<IbPartitionList, Status> {
        Ok(self
            .connection()
            .await?
            .find_ib_partitions(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_ib_partition(
        &self,
        request: IbPartitionCreationRequest,
    ) -> Result<IbPartition, Status> {
        Ok(self
            .connection()
            .await?
            .create_ib_partition(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_ib_partition(
        &self,
        request: IbPartitionDeletionRequest,
    ) -> Result<IbPartitionDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_ib_partition(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn ib_partitions_for_tenant(
        &self,
        request: TenantSearchQuery,
    ) -> Result<IbPartitionList, Status> {
        Ok(self
            .connection()
            .await?
            .ib_partitions_for_tenant(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn allocate_instance(
        &self,
        request: InstanceAllocationRequest,
    ) -> Result<Instance, Status> {
        Ok(self
            .connection()
            .await?
            .allocate_instance(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn release_instance(
        &self,
        request: InstanceReleaseRequest,
    ) -> Result<InstanceReleaseResult, Status> {
        Ok(self
            .connection()
            .await?
            .release_instance(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_instance_operating_system(
        &self,
        request: InstanceOperatingSystemUpdateRequest,
    ) -> Result<Instance, Status> {
        Ok(self
            .connection()
            .await?
            .update_instance_operating_system(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_instance_config(
        &self,
        request: InstanceConfigUpdateRequest,
    ) -> Result<Instance, Status> {
        Ok(self
            .connection()
            .await?
            .update_instance_config(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instance_ids(
        &self,
        request: InstanceSearchFilter,
    ) -> Result<InstanceIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_instance_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instances_by_ids(
        &self,
        request: InstancesByIdsRequest,
    ) -> Result<InstanceList, Status> {
        Ok(self
            .connection()
            .await?
            .find_instances_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instances(
        &self,
        request: InstanceSearchQuery,
    ) -> Result<InstanceList, Status> {
        Ok(self
            .connection()
            .await?
            .find_instances(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instance_by_machine_id(
        &self,
        request: MachineId,
    ) -> Result<InstanceList, Status> {
        Ok(self
            .connection()
            .await?
            .find_instance_by_machine_id(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn record_observed_instance_network_status(
        &self,
        request: InstanceNetworkStatusObservation,
    ) -> Result<ObservedInstanceNetworkStatusRecordResult, Status> {
        Ok(self
            .connection()
            .await?
            .record_observed_instance_network_status(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_managed_host_network_config(
        &self,
        request: ManagedHostNetworkConfigRequest,
    ) -> Result<ManagedHostNetworkConfigResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_managed_host_network_config(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn record_dpu_network_status(&self, request: DpuNetworkStatus) -> Result<(), Status> {
        self.connection()
            .await?
            .record_dpu_network_status(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn record_hardware_health_report(
        &self,
        request: HardwareHealthReport,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .record_hardware_health_report(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_hardware_health_report(
        &self,
        request: MachineId,
    ) -> Result<OptionalHealthReport, Status> {
        Ok(self
            .connection()
            .await?
            .get_hardware_health_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn record_log_parser_health_report(
        &self,
        request: HardwareHealthReport,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .record_log_parser_health_report(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn list_health_report_overrides(
        &self,
        request: MachineId,
    ) -> Result<ListHealthReportOverrideResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_health_report_overrides(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn insert_health_report_override(
        &self,
        request: InsertHealthReportOverrideRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .insert_health_report_override(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn remove_health_report_override(
        &self,
        request: RemoveHealthReportOverrideRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .remove_health_report_override(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn dpu_agent_upgrade_check(
        &self,
        request: DpuAgentUpgradeCheckRequest,
    ) -> Result<DpuAgentUpgradeCheckResponse, Status> {
        Ok(self
            .connection()
            .await?
            .dpu_agent_upgrade_check(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn dpu_agent_upgrade_policy_action(
        &self,
        request: DpuAgentUpgradePolicyRequest,
    ) -> Result<DpuAgentUpgradePolicyResponse, Status> {
        Ok(self
            .connection()
            .await?
            .dpu_agent_upgrade_policy_action(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn lookup_record(&self, request: DnsQuestion) -> Result<DnsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .lookup_record(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn invoke_instance_power(
        &self,
        request: InstancePowerRequest,
    ) -> Result<InstancePowerResult, Status> {
        Ok(self
            .connection()
            .await?
            .invoke_instance_power(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn forge_agent_control(
        &self,
        request: ForgeAgentControlRequest,
    ) -> Result<ForgeAgentControlResponse, Status> {
        Ok(self
            .connection()
            .await?
            .forge_agent_control(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn discover_machine(
        &self,
        request: MachineDiscoveryInfo,
    ) -> Result<MachineDiscoveryResult, Status> {
        Ok(self
            .connection()
            .await?
            .discover_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn renew_machine_certificate(
        &self,
        request: MachineCertificateRenewRequest,
    ) -> Result<MachineCertificateResult, Status> {
        Ok(self
            .connection()
            .await?
            .renew_machine_certificate(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn discovery_completed(
        &self,
        request: MachineDiscoveryCompletedRequest,
    ) -> Result<MachineDiscoveryCompletedResponse, Status> {
        Ok(self
            .connection()
            .await?
            .discovery_completed(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn cleanup_machine_completed(
        &self,
        request: MachineCleanupInfo,
    ) -> Result<MachineCleanupResult, Status> {
        Ok(self
            .connection()
            .await?
            .cleanup_machine_completed(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn report_forge_scout_error(
        &self,
        request: ForgeScoutErrorReport,
    ) -> Result<ForgeScoutErrorReportResult, Status> {
        Ok(self
            .connection()
            .await?
            .report_forge_scout_error(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn discover_dhcp(&self, request: DhcpDiscovery) -> Result<DhcpRecord, Status> {
        Ok(self
            .connection()
            .await?
            .discover_dhcp(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_machine(&self, request: MachineId) -> Result<Machine, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_machines(&self, request: MachineSearchQuery) -> Result<MachineList, Status> {
        Ok(self
            .connection()
            .await?
            .find_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_interfaces(
        &self,
        request: InterfaceSearchQuery,
    ) -> Result<InterfaceList, Status> {
        Ok(self
            .connection()
            .await?
            .find_interfaces(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_interface(&self, request: InterfaceDeleteQuery) -> Result<(), Status> {
        self.connection()
            .await?
            .delete_interface(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn find_ip_address(
        &self,
        request: FindIpAddressRequest,
    ) -> Result<FindIpAddressResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_ip_address(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_machine_ids(
        &self,
        request: MachineSearchConfig,
    ) -> Result<MachineIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_machine_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_machines_by_ids(
        &self,
        request: MachinesByIdsRequest,
    ) -> Result<MachineList, Status> {
        Ok(self
            .connection()
            .await?
            .find_machines_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_machine_health_histories(
        &self,
        request: MachineHealthHistoriesRequest,
    ) -> Result<MachineHealthHistories, Status> {
        Ok(self
            .connection()
            .await?
            .find_machine_health_histories(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenant_organization_ids(
        &self,
        request: TenantSearchFilter,
    ) -> Result<TenantOrganizationIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenant_organization_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenants_by_organization_ids(
        &self,
        request: TenantByOrganizationIdsRequest,
    ) -> Result<TenantList, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenants_by_organization_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: MachineIdList,
    ) -> Result<ConnectedDeviceList, Status> {
        Ok(self
            .connection()
            .await?
            .find_connected_devices_by_dpu_machine_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_machine_ids_by_bmc_ips(
        &self,
        request: BmcIpList,
    ) -> Result<MachineIdBmcIpPairs, Status> {
        Ok(self
            .connection()
            .await?
            .find_machine_ids_by_bmc_ips(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_mac_address_by_bmc_ip(
        &self,
        request: BmcIp,
    ) -> Result<MacAddressBmcIp, Status> {
        Ok(self
            .connection()
            .await?
            .find_mac_address_by_bmc_ip(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn identify_uuid(
        &self,
        request: IdentifyUuidRequest,
    ) -> Result<IdentifyUuidResponse, Status> {
        Ok(self
            .connection()
            .await?
            .identify_uuid(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn identify_mac(
        &self,
        request: IdentifyMacRequest,
    ) -> Result<IdentifyMacResponse, Status> {
        Ok(self
            .connection()
            .await?
            .identify_mac(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn identify_serial(
        &self,
        request: IdentifySerialRequest,
    ) -> Result<IdentifySerialResponse, Status> {
        Ok(self
            .connection()
            .await?
            .identify_serial(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_bmc_meta_data(
        &self,
        request: BmcMetaDataGetRequest,
    ) -> Result<BmcMetaDataGetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_bmc_meta_data(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_machine_credentials(
        &self,
        request: MachineCredentialsUpdateRequest,
    ) -> Result<MachineCredentialsUpdateResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_machine_credentials(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_pxe_instructions(
        &self,
        request: PxeInstructionRequest,
    ) -> Result<PxeInstructions, Status> {
        Ok(self
            .connection()
            .await?
            .get_pxe_instructions(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_cloud_init_instructions(
        &self,
        request: CloudInitInstructionsRequest,
    ) -> Result<CloudInitInstructions, Status> {
        Ok(self
            .connection()
            .await?
            .get_cloud_init_instructions(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn echo(&self, request: EchoRequest) -> Result<EchoResponse, Status> {
        Ok(self
            .connection()
            .await?
            .echo(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_tenant(
        &self,
        request: CreateTenantRequest,
    ) -> Result<CreateTenantResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_tenant(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenant(
        &self,
        request: FindTenantRequest,
    ) -> Result<FindTenantResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenant(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_tenant(
        &self,
        request: UpdateTenantRequest,
    ) -> Result<UpdateTenantResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_tenant(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_tenant_keyset(
        &self,
        request: CreateTenantKeysetRequest,
    ) -> Result<CreateTenantKeysetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_tenant_keyset(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenant_keyset_ids(
        &self,
        request: TenantKeysetSearchFilter,
    ) -> Result<TenantKeysetIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenant_keyset_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenant_keysets_by_ids(
        &self,
        request: TenantKeysetsByIdsRequest,
    ) -> Result<TenantKeySetList, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenant_keysets_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_tenant_keyset(
        &self,
        request: FindTenantKeysetRequest,
    ) -> Result<TenantKeySetList, Status> {
        Ok(self
            .connection()
            .await?
            .find_tenant_keyset(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_tenant_keyset(
        &self,
        request: UpdateTenantKeysetRequest,
    ) -> Result<UpdateTenantKeysetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_tenant_keyset(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_tenant_keyset(
        &self,
        request: DeleteTenantKeysetRequest,
    ) -> Result<DeleteTenantKeysetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_tenant_keyset(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn validate_tenant_public_key(
        &self,
        request: ValidateTenantPublicKeyRequest,
    ) -> Result<ValidateTenantPublicKeyResponse, Status> {
        Ok(self
            .connection()
            .await?
            .validate_tenant_public_key(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_dpu_ssh_credential(
        &self,
        request: CredentialRequest,
    ) -> Result<CredentialResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_dpu_ssh_credential(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_all_managed_host_network_status(
        &self,
        request: ManagedHostNetworkStatusRequest,
    ) -> Result<ManagedHostNetworkStatusResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_all_managed_host_network_status(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_site_exploration_report(
        &self,
        request: GetSiteExplorationRequest,
    ) -> Result<SiteExplorationReport, Status> {
        Ok(self
            .connection()
            .await?
            .get_site_exploration_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn clear_site_exploration_error(
        &self,
        request: ClearSiteExplorationErrorRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .clear_site_exploration_error(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn is_bmc_in_managed_host(
        &self,
        request: BmcEndpointRequest,
    ) -> Result<IsBmcInManagedHostResponse, Status> {
        Ok(self
            .connection()
            .await?
            .is_bmc_in_managed_host(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn bmc_credential_status(
        &self,
        request: BmcEndpointRequest,
    ) -> Result<BmcCredentialStatusResponse, Status> {
        Ok(self
            .connection()
            .await?
            .bmc_credential_status(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn explore(
        &self,
        request: BmcEndpointRequest,
    ) -> Result<EndpointExplorationReport, Status> {
        Ok(self
            .connection()
            .await?
            .explore(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn re_explore_endpoint(
        &self,
        request: ReExploreEndpointRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .re_explore_endpoint(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn find_explored_endpoint_ids(
        &self,
        request: ExploredEndpointSearchFilter,
    ) -> Result<ExploredEndpointIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_explored_endpoint_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_explored_endpoints_by_ids(
        &self,
        request: ExploredEndpointsByIdsRequest,
    ) -> Result<ExploredEndpointList, Status> {
        Ok(self
            .connection()
            .await?
            .find_explored_endpoints_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_explored_managed_host_ids(
        &self,
        request: ExploredManagedHostSearchFilter,
    ) -> Result<ExploredManagedHostIdList, Status> {
        Ok(self
            .connection()
            .await?
            .find_explored_managed_host_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_explored_managed_hosts_by_ids(
        &self,
        request: ExploredManagedHostsByIdsRequest,
    ) -> Result<ExploredManagedHostList, Status> {
        Ok(self
            .connection()
            .await?
            .find_explored_managed_hosts_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_machine_hardware_info(
        &self,
        request: UpdateMachineHardwareInfoRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .update_machine_hardware_info(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn admin_force_delete_machine(
        &self,
        request: AdminForceDeleteMachineRequest,
    ) -> Result<AdminForceDeleteMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .admin_force_delete_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn admin_list_resource_pools(
        &self,
        request: ListResourcePoolsRequest,
    ) -> Result<ResourcePools, Status> {
        Ok(self
            .connection()
            .await?
            .admin_list_resource_pools(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn admin_grow_resource_pool(
        &self,
        request: GrowResourcePoolRequest,
    ) -> Result<GrowResourcePoolResponse, Status> {
        Ok(self
            .connection()
            .await?
            .admin_grow_resource_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_machine_metadata(
        &self,
        request: MachineMetadataUpdateRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .update_machine_metadata(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn set_maintenance(&self, request: MaintenanceRequest) -> Result<(), Status> {
        self.connection()
            .await?
            .set_maintenance(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn set_dynamic_config(&self, request: SetDynamicConfigRequest) -> Result<(), Status> {
        self.connection()
            .await?
            .set_dynamic_config(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn trigger_dpu_reprovisioning(
        &self,
        request: DpuReprovisioningRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .trigger_dpu_reprovisioning(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: DpuReprovisioningListRequest,
    ) -> Result<DpuReprovisioningListResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_dpu_waiting_for_reprovisioning(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn trigger_host_reprovisioning(
        &self,
        request: HostReprovisioningRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .trigger_host_reprovisioning(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn list_hosts_waiting_for_reprovisioning(
        &self,
        request: HostReprovisioningListRequest,
    ) -> Result<HostReprovisioningListResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_hosts_waiting_for_reprovisioning(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_dpu_info_list(
        &self,
        request: GetDpuInfoListRequest,
    ) -> Result<GetDpuInfoListResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_dpu_info_list(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_machine_boot_override(
        &self,
        request: Uuid,
    ) -> Result<MachineBootOverride, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_boot_override(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn set_machine_boot_override(
        &self,
        request: MachineBootOverride,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .set_machine_boot_override(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn clear_machine_boot_override(&self, request: Uuid) -> Result<(), Status> {
        self.connection()
            .await?
            .clear_machine_boot_override(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_network_topology(
        &self,
        request: NetworkTopologyRequest,
    ) -> Result<NetworkTopologyData, Status> {
        Ok(self
            .connection()
            .await?
            .get_network_topology(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_devices_by_device_ids(
        &self,
        request: NetworkDeviceIdList,
    ) -> Result<NetworkTopologyData, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_devices_by_device_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_credential(
        &self,
        request: CredentialCreationRequest,
    ) -> Result<CredentialCreationResult, Status> {
        Ok(self
            .connection()
            .await?
            .create_credential(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_credential(
        &self,
        request: CredentialDeletionRequest,
    ) -> Result<CredentialDeletionResult, Status> {
        Ok(self
            .connection()
            .await?
            .delete_credential(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_route_servers(&self) -> Result<RouteServers, Status> {
        Ok(self
            .connection()
            .await?
            .get_route_servers(Request::new(()))
            .await?
            .into_inner())
    }

    pub async fn add_route_servers(&self, request: RouteServers) -> Result<(), Status> {
        self.connection()
            .await?
            .add_route_servers(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn remove_route_servers(&self, request: RouteServers) -> Result<(), Status> {
        self.connection()
            .await?
            .remove_route_servers(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn replace_route_servers(&self, request: RouteServers) -> Result<(), Status> {
        self.connection()
            .await?
            .replace_route_servers(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn update_agent_reported_inventory(
        &self,
        request: DpuAgentInventoryReport,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .update_agent_reported_inventory(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn update_instance_phone_home_last_contact(
        &self,
        request: InstancePhoneHomeLastContactRequest,
    ) -> Result<InstancePhoneHomeLastContactResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_instance_phone_home_last_contact(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn set_host_uefi_password(
        &self,
        request: SetHostUefiPasswordRequest,
    ) -> Result<SetHostUefiPasswordResponse, Status> {
        Ok(self
            .connection()
            .await?
            .set_host_uefi_password(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn clear_host_uefi_password(
        &self,
        request: ClearHostUefiPasswordRequest,
    ) -> Result<ClearHostUefiPasswordResponse, Status> {
        Ok(self
            .connection()
            .await?
            .clear_host_uefi_password(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn add_expected_machine(&self, request: ExpectedMachine) -> Result<(), Status> {
        self.connection()
            .await?
            .add_expected_machine(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn delete_expected_machine(
        &self,
        request: ExpectedMachineRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .delete_expected_machine(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn update_expected_machine(&self, request: ExpectedMachine) -> Result<(), Status> {
        self.connection()
            .await?
            .update_expected_machine(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_expected_machine(
        &self,
        request: ExpectedMachineRequest,
    ) -> Result<ExpectedMachine, Status> {
        Ok(self
            .connection()
            .await?
            .get_expected_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_all_expected_machines(&self) -> Result<ExpectedMachineList, Status> {
        Ok(self
            .connection()
            .await?
            .get_all_expected_machines(Request::new(()))
            .await?
            .into_inner())
    }

    pub async fn replace_all_expected_machines(
        &self,
        request: ExpectedMachineList,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .replace_all_expected_machines(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn delete_all_expected_machines(&self) -> Result<(), Status> {
        self.connection()
            .await?
            .delete_all_expected_machines(())
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_all_expected_machines_linked(
        &self,
    ) -> Result<LinkedExpectedMachineList, Status> {
        Ok(self
            .connection()
            .await?
            .get_all_expected_machines_linked(())
            .await?
            .into_inner())
    }

    pub async fn attest_quote(
        &self,
        request: AttestQuoteRequest,
    ) -> Result<AttestQuoteResponse, Status> {
        Ok(self
            .connection()
            .await?
            .attest_quote(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_instance_type(
        &self,
        request: CreateInstanceTypeRequest,
    ) -> Result<CreateInstanceTypeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_instance_type(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instance_type_ids(
        &self,
        request: FindInstanceTypeIdsRequest,
    ) -> Result<FindInstanceTypeIdsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_instance_type_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_instance_types_by_ids(
        &self,
        request: FindInstanceTypesByIdsRequest,
    ) -> Result<FindInstanceTypesByIdsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_instance_types_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_instance_type(
        &self,
        request: UpdateInstanceTypeRequest,
    ) -> Result<UpdateInstanceTypeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_instance_type(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_instance_type(
        &self,
        request: DeleteInstanceTypeRequest,
    ) -> Result<DeleteInstanceTypeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_instance_type(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn associate_machines_with_instance_type(
        &self,
        request: AssociateMachinesWithInstanceTypeRequest,
    ) -> Result<AssociateMachinesWithInstanceTypeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .associate_machines_with_instance_type(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn remove_machine_instance_type_association(
        &self,
        request: RemoveMachineInstanceTypeAssociationRequest,
    ) -> Result<RemoveMachineInstanceTypeAssociationResponse, Status> {
        Ok(self
            .connection()
            .await?
            .remove_machine_instance_type_association(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_measurement_bundle(
        &self,
        request: CreateMeasurementBundleRequest,
    ) -> Result<CreateMeasurementBundleResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_measurement_bundle(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_measurement_bundle(
        &self,
        request: DeleteMeasurementBundleRequest,
    ) -> Result<DeleteMeasurementBundleResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_measurement_bundle(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn rename_measurement_bundle(
        &self,
        request: RenameMeasurementBundleRequest,
    ) -> Result<RenameMeasurementBundleResponse, Status> {
        Ok(self
            .connection()
            .await?
            .rename_measurement_bundle(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_measurement_bundle(
        &self,
        request: UpdateMeasurementBundleRequest,
    ) -> Result<UpdateMeasurementBundleResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_measurement_bundle(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_bundle(
        &self,
        request: ShowMeasurementBundleRequest,
    ) -> Result<ShowMeasurementBundleResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_bundle(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_bundles(
        &self,
        request: ShowMeasurementBundlesRequest,
    ) -> Result<ShowMeasurementBundlesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_bundles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_bundles(
        &self,
        request: ListMeasurementBundlesRequest,
    ) -> Result<ListMeasurementBundlesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_bundles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_bundle_machines(
        &self,
        request: ListMeasurementBundleMachinesRequest,
    ) -> Result<ListMeasurementBundleMachinesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_bundle_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_measurement_journal(
        &self,
        request: DeleteMeasurementJournalRequest,
    ) -> Result<DeleteMeasurementJournalResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_measurement_journal(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_journal(
        &self,
        request: ShowMeasurementJournalRequest,
    ) -> Result<ShowMeasurementJournalResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_journal(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_journals(
        &self,
        request: ShowMeasurementJournalsRequest,
    ) -> Result<ShowMeasurementJournalsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_journals(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_journal(
        &self,
        request: ListMeasurementJournalRequest,
    ) -> Result<ListMeasurementJournalResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_journal(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn attest_candidate_machine(
        &self,
        request: AttestCandidateMachineRequest,
    ) -> Result<AttestCandidateMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .attest_candidate_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_candidate_machine(
        &self,
        request: ShowCandidateMachineRequest,
    ) -> Result<ShowCandidateMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_candidate_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_candidate_machines(
        &self,
        request: ShowCandidateMachinesRequest,
    ) -> Result<ShowCandidateMachinesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_candidate_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_candidate_machines(
        &self,
        request: ListCandidateMachinesRequest,
    ) -> Result<ListCandidateMachinesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_candidate_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_measurement_system_profile(
        &self,
        request: CreateMeasurementSystemProfileRequest,
    ) -> Result<CreateMeasurementSystemProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_measurement_system_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_measurement_system_profile(
        &self,
        request: DeleteMeasurementSystemProfileRequest,
    ) -> Result<DeleteMeasurementSystemProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_measurement_system_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn rename_measurement_system_profile(
        &self,
        request: RenameMeasurementSystemProfileRequest,
    ) -> Result<RenameMeasurementSystemProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .rename_measurement_system_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_system_profile(
        &self,
        request: ShowMeasurementSystemProfileRequest,
    ) -> Result<ShowMeasurementSystemProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_system_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_system_profiles(
        &self,
        request: ShowMeasurementSystemProfilesRequest,
    ) -> Result<ShowMeasurementSystemProfilesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_system_profiles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_system_profiles(
        &self,
        request: ListMeasurementSystemProfilesRequest,
    ) -> Result<ListMeasurementSystemProfilesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_system_profiles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_system_profile_bundles(
        &self,
        request: ListMeasurementSystemProfileBundlesRequest,
    ) -> Result<ListMeasurementSystemProfileBundlesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_system_profile_bundles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_system_profile_machines(
        &self,
        request: ListMeasurementSystemProfileMachinesRequest,
    ) -> Result<ListMeasurementSystemProfileMachinesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_system_profile_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_measurement_report(
        &self,
        request: CreateMeasurementReportRequest,
    ) -> Result<CreateMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_measurement_report(
        &self,
        request: DeleteMeasurementReportRequest,
    ) -> Result<DeleteMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn promote_measurement_report(
        &self,
        request: PromoteMeasurementReportRequest,
    ) -> Result<PromoteMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .promote_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn revoke_measurement_report(
        &self,
        request: RevokeMeasurementReportRequest,
    ) -> Result<RevokeMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .revoke_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_report_for_id(
        &self,
        request: ShowMeasurementReportForIdRequest,
    ) -> Result<ShowMeasurementReportForIdResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_report_for_id(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_reports_for_machine(
        &self,
        request: ShowMeasurementReportsForMachineRequest,
    ) -> Result<ShowMeasurementReportsForMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_reports_for_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn show_measurement_reports(
        &self,
        request: ShowMeasurementReportsRequest,
    ) -> Result<ShowMeasurementReportsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .show_measurement_reports(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_report(
        &self,
        request: ListMeasurementReportRequest,
    ) -> Result<ListMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn match_measurement_report(
        &self,
        request: MatchMeasurementReportRequest,
    ) -> Result<MatchMeasurementReportResponse, Status> {
        Ok(self
            .connection()
            .await?
            .match_measurement_report(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn import_site_measurements(
        &self,
        request: ImportSiteMeasurementsRequest,
    ) -> Result<ImportSiteMeasurementsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .import_site_measurements(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn export_site_measurements(
        &self,
        request: ExportSiteMeasurementsRequest,
    ) -> Result<ExportSiteMeasurementsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .export_site_measurements(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn add_measurement_trusted_machine(
        &self,
        request: AddMeasurementTrustedMachineRequest,
    ) -> Result<AddMeasurementTrustedMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .add_measurement_trusted_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn remove_measurement_trusted_machine(
        &self,
        request: RemoveMeasurementTrustedMachineRequest,
    ) -> Result<RemoveMeasurementTrustedMachineResponse, Status> {
        Ok(self
            .connection()
            .await?
            .remove_measurement_trusted_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn add_measurement_trusted_profile(
        &self,
        request: AddMeasurementTrustedProfileRequest,
    ) -> Result<AddMeasurementTrustedProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .add_measurement_trusted_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn remove_measurement_trusted_profile(
        &self,
        request: RemoveMeasurementTrustedProfileRequest,
    ) -> Result<RemoveMeasurementTrustedProfileResponse, Status> {
        Ok(self
            .connection()
            .await?
            .remove_measurement_trusted_profile(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_trusted_machines(
        &self,
        request: ListMeasurementTrustedMachinesRequest,
    ) -> Result<ListMeasurementTrustedMachinesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_trusted_machines(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_measurement_trusted_profiles(
        &self,
        request: ListMeasurementTrustedProfilesRequest,
    ) -> Result<ListMeasurementTrustedProfilesResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_measurement_trusted_profiles(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_network_security_group(
        &self,
        request: CreateNetworkSecurityGroupRequest,
    ) -> Result<CreateNetworkSecurityGroupResponse, Status> {
        Ok(self
            .connection()
            .await?
            .create_network_security_group(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_security_group_ids(
        &self,
        request: FindNetworkSecurityGroupIdsRequest,
    ) -> Result<FindNetworkSecurityGroupIdsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_security_group_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn find_network_security_groups_by_ids(
        &self,
        request: FindNetworkSecurityGroupsByIdsRequest,
    ) -> Result<FindNetworkSecurityGroupsByIdsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .find_network_security_groups_by_ids(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_network_security_group(
        &self,
        request: UpdateNetworkSecurityGroupRequest,
    ) -> Result<UpdateNetworkSecurityGroupResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_network_security_group(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_network_security_group(
        &self,
        request: DeleteNetworkSecurityGroupRequest,
    ) -> Result<DeleteNetworkSecurityGroupResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_network_security_group(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_network_security_group_propagation_status(
        &self,
        request: GetNetworkSecurityGroupPropagationStatusRequest,
    ) -> Result<GetNetworkSecurityGroupPropagationStatusResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_network_security_group_propagation_status(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_network_security_group_attachments(
        &self,
        request: GetNetworkSecurityGroupAttachmentsRequest,
    ) -> Result<GetNetworkSecurityGroupAttachmentsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_network_security_group_attachments(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn import_storage_cluster(
        &self,
        request: StorageClusterAttributes,
    ) -> Result<StorageCluster, Status> {
        Ok(self
            .connection()
            .await?
            .import_storage_cluster(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_storage_cluster(
        &self,
        request: DeleteStorageClusterRequest,
    ) -> Result<DeleteStorageClusterResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_storage_cluster(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_storage_cluster(
        &self,
        request: ListStorageClusterRequest,
    ) -> Result<ListStorageClusterResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_storage_cluster(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_storage_cluster(&self, request: Uuid) -> Result<StorageCluster, Status> {
        Ok(self
            .connection()
            .await?
            .get_storage_cluster(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_storage_cluster(
        &self,
        request: UpdateStorageClusterRequest,
    ) -> Result<StorageCluster, Status> {
        Ok(self
            .connection()
            .await?
            .update_storage_cluster(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_storage_pool(
        &self,
        request: StoragePoolAttributes,
    ) -> Result<StoragePool, Status> {
        Ok(self
            .connection()
            .await?
            .create_storage_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_storage_pool(
        &self,
        request: DeleteStoragePoolRequest,
    ) -> Result<DeleteStoragePoolResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_storage_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_storage_pool(
        &self,
        request: ListStoragePoolRequest,
    ) -> Result<ListStoragePoolResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_storage_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_storage_pool(&self, request: Uuid) -> Result<StoragePool, Status> {
        Ok(self
            .connection()
            .await?
            .get_storage_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_storage_pool(
        &self,
        request: StoragePoolAttributes,
    ) -> Result<StoragePool, Status> {
        Ok(self
            .connection()
            .await?
            .update_storage_pool(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_storage_volume(
        &self,
        request: StorageVolumeAttributes,
    ) -> Result<StorageVolume, Status> {
        Ok(self
            .connection()
            .await?
            .create_storage_volume(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_storage_volume(
        &self,
        request: DeleteStorageVolumeRequest,
    ) -> Result<DeleteStorageVolumeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_storage_volume(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_storage_volume(
        &self,
        request: StorageVolumeFilter,
    ) -> Result<ListStorageVolumeResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_storage_volume(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_storage_volume(&self, request: Uuid) -> Result<StorageVolume, Status> {
        Ok(self
            .connection()
            .await?
            .get_storage_volume(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_storage_volume(
        &self,
        request: StorageVolumeAttributes,
    ) -> Result<StorageVolume, Status> {
        Ok(self
            .connection()
            .await?
            .update_storage_volume(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_os_image(&self, request: OsImageAttributes) -> Result<OsImage, Status> {
        Ok(self
            .connection()
            .await?
            .create_os_image(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn delete_os_image(
        &self,
        request: DeleteOsImageRequest,
    ) -> Result<DeleteOsImageResponse, Status> {
        Ok(self
            .connection()
            .await?
            .delete_os_image(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn list_os_image(
        &self,
        request: ListOsImageRequest,
    ) -> Result<ListOsImageResponse, Status> {
        Ok(self
            .connection()
            .await?
            .list_os_image(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_os_image(&self, request: Uuid) -> Result<OsImage, Status> {
        Ok(self
            .connection()
            .await?
            .get_os_image(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_os_image(&self, request: OsImageAttributes) -> Result<OsImage, Status> {
        Ok(self
            .connection()
            .await?
            .update_os_image(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn reboot_completed(
        &self,
        request: MachineRebootCompletedRequest,
    ) -> Result<MachineRebootCompletedResponse, Status> {
        Ok(self
            .connection()
            .await?
            .reboot_completed(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn persist_validation_result(
        &self,
        request: MachineValidationResultPostRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .persist_validation_result(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_machine_validation_results(
        &self,
        request: MachineValidationGetRequest,
    ) -> Result<MachineValidationResultList, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_validation_results(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn machine_validation_completed(
        &self,
        request: MachineValidationCompletedRequest,
    ) -> Result<MachineValidationCompletedResponse, Status> {
        Ok(self
            .connection()
            .await?
            .machine_validation_completed(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn machine_set_auto_update(
        &self,
        request: MachineSetAutoUpdateRequest,
    ) -> Result<MachineSetAutoUpdateResponse, Status> {
        Ok(self
            .connection()
            .await?
            .machine_set_auto_update(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_machine_validation_external_config(
        &self,
        request: GetMachineValidationExternalConfigRequest,
    ) -> Result<GetMachineValidationExternalConfigResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_validation_external_config(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_machine_validation_external_configs(
        &self,
        request: GetMachineValidationExternalConfigsRequest,
    ) -> Result<GetMachineValidationExternalConfigsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_validation_external_configs(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn add_update_machine_validation_external_config(
        &self,
        request: AddUpdateMachineValidationExternalConfigRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .add_update_machine_validation_external_config(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_machine_validation_runs(
        &self,
        request: MachineValidationRunListGetRequest,
    ) -> Result<MachineValidationRunList, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_validation_runs(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn remove_machine_validation_external_config(
        &self,
        request: RemoveMachineValidationExternalConfigRequest,
    ) -> Result<(), Status> {
        self.connection()
            .await?
            .remove_machine_validation_external_config(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_machine_validation_tests(
        &self,
        request: MachineValidationTestsGetRequest,
    ) -> Result<MachineValidationTestsGetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_machine_validation_tests(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn add_machine_validation_test(
        &self,
        request: MachineValidationTestAddRequest,
    ) -> Result<MachineValidationTestAddUpdateResponse, Status> {
        Ok(self
            .connection()
            .await?
            .add_machine_validation_test(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_machine_validation_test(
        &self,
        request: MachineValidationTestUpdateRequest,
    ) -> Result<MachineValidationTestAddUpdateResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_machine_validation_test(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn machine_validation_test_verfied(
        &self,
        request: MachineValidationTestVerfiedRequest,
    ) -> Result<MachineValidationTestVerfiedResponse, Status> {
        Ok(self
            .connection()
            .await?
            .machine_validation_test_verfied(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn machine_validation_test_next_version(
        &self,
        request: MachineValidationTestNextVersionRequest,
    ) -> Result<MachineValidationTestNextVersionResponse, Status> {
        Ok(self
            .connection()
            .await?
            .machine_validation_test_next_version(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn machine_validation_test_enable_disable_test(
        &self,
        request: MachineValidationTestEnableDisableTestRequest,
    ) -> Result<MachineValidationTestEnableDisableTestResponse, Status> {
        Ok(self
            .connection()
            .await?
            .machine_validation_test_enable_disable_test(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn update_machine_validation_run(
        &self,
        request: MachineValidationRunRequest,
    ) -> Result<MachineValidationRunResponse, Status> {
        Ok(self
            .connection()
            .await?
            .update_machine_validation_run(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn admin_bmc_reset(
        &self,
        request: AdminBmcResetRequest,
    ) -> Result<AdminBmcResetResponse, Status> {
        Ok(self
            .connection()
            .await?
            .admin_bmc_reset(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn admin_power_control(
        &self,
        request: AdminPowerControlRequest,
    ) -> Result<AdminPowerControlResponse, Status> {
        Ok(self
            .connection()
            .await?
            .admin_power_control(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn forge_setup(
        &self,
        request: ForgeSetupRequest,
    ) -> Result<ForgeSetupResponse, Status> {
        Ok(self
            .connection()
            .await?
            .forge_setup(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn on_demand_machine_validation(
        &self,
        request: MachineValidationOnDemandRequest,
    ) -> Result<MachineValidationOnDemandResponse, Status> {
        Ok(self
            .connection()
            .await?
            .on_demand_machine_validation(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn tpm_add_ca_cert(&self, request: TpmCaCert) -> Result<TpmCaAddedCaStatus, Status> {
        Ok(self
            .connection()
            .await?
            .tpm_add_ca_cert(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn tpm_show_ca_certs(&self) -> Result<TpmCaCertDetailCollection, Status> {
        Ok(self
            .connection()
            .await?
            .tpm_show_ca_certs(())
            .await?
            .into_inner())
    }

    pub async fn tpm_show_unmatched_ek_certs(&self) -> Result<TpmEkCertStatusCollection, Status> {
        Ok(self
            .connection()
            .await?
            .tpm_show_unmatched_ek_certs(())
            .await?
            .into_inner())
    }

    pub async fn tpm_delete_ca_cert(&self, request: TpmCaCertId) -> Result<(), Status> {
        self.connection()
            .await?
            .tpm_delete_ca_cert(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn redfish_browse(
        &self,
        request: RedfishBrowseRequest,
    ) -> Result<RedfishBrowseResponse, Status> {
        Ok(self
            .connection()
            .await?
            .redfish_browse(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn get_desired_firmware_versions(
        &self,
        request: GetDesiredFirmwareVersionsRequest,
    ) -> Result<GetDesiredFirmwareVersionsResponse, Status> {
        Ok(self
            .connection()
            .await?
            .get_desired_firmware_versions(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn create_sku(&self, request: SkuList) -> Result<SkuIdList, Status> {
        Ok(self
            .connection()
            .await?
            .create_sku(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn generate_sku_from_machine(&self, request: MachineId) -> Result<Sku, Status> {
        Ok(self
            .connection()
            .await?
            .generate_sku_from_machine(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn verify_sku_for_machine(&self, request: MachineId) -> Result<(), Status> {
        self.connection()
            .await?
            .verify_sku_for_machine(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn assign_sku_to_machine(&self, request: SkuMachinePair) -> Result<(), Status> {
        self.connection()
            .await?
            .assign_sku_to_machine(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn remove_sku_association(&self, request: MachineId) -> Result<(), Status> {
        self.connection()
            .await?
            .remove_sku_association(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn delete_sku(&self, request: SkuIdList) -> Result<(), Status> {
        self.connection()
            .await?
            .delete_sku(Request::new(request))
            .await?
            .into_inner();
        Ok(())
    }

    pub async fn get_all_sku_ids(&self) -> Result<SkuIdList, Status> {
        Ok(self
            .connection()
            .await?
            .get_all_sku_ids(Request::new(()))
            .await?
            .into_inner())
    }

    pub async fn find_skus_by_ids(&self, request: SkusByIdsRequest) -> Result<SkuList, Status> {
        Ok(self
            .connection()
            .await?
            .find_skus_by_ids(Request::new(request))
            .await?
            .into_inner())
    }
}
