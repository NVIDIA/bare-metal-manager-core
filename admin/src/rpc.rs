/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::Machine;
use ::rpc::forge::instance_interface_config::NetworkDetails;
use ::rpc::forge::{
    self as rpc, BmcCredentialStatusResponse, BmcEndpointRequest,
    CreateNetworkSecurityGroupRequest, DeleteNetworkSecurityGroupRequest,
    FindInstanceTypesByIdsRequest, FindNetworkSecurityGroupsByIdsRequest,
    GetNetworkSecurityGroupAttachmentsRequest, GetNetworkSecurityGroupPropagationStatusRequest,
    IdentifySerialRequest, IsBmcInManagedHostResponse, MachineBootOverride, MachineHardwareInfo,
    MachineHardwareInfoUpdateType, NetworkPrefix, NetworkSecurityGroupAttributes,
    NetworkSegmentCreationRequest, NetworkSegmentType, PowerState, SshRequest,
    UpdateMachineHardwareInfoRequest, UpdateNetworkSecurityGroupRequest, VpcCreationRequest,
    VpcPeeringDeletionResult, VpcSearchQuery, VpcVirtualizationType,
};
use ::rpc::{NetworkSegment, Uuid};

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use crate::cfg::cli_options::{
    self, AllocateInstance, ForceDeleteMachineQuery, MachineAutoupdate, TimeoutConfig,
};
use crate::rpc::cli_options::UpdateInstanceOS;
use ::rpc::forge_api_client::ForgeApiClient;
use mac_address::MacAddress;
use utils::admin_cli::{CarbideCliError, CarbideCliResult};

/// [`ApiClient`] is a thin wrapper around [`ForgeApiClient`], which mainly adds some convenience
/// methods.
#[derive(Clone)]
pub struct ApiClient(pub ForgeApiClient);

// Note: You do *not* need to add every gRPC method to this wrapper. Callers can use `.0` to get
// access to the underlying ForgeApiClient, if they want to simply call the gRPC methods themselves.
// Add methods here if there's some value to it, like constructing rpc request objects from simpler
// primitives, or other data conversions.
//
// (this module used to have more logic around establishing a connection to carbide, but this is all
// now done in ForgeApiClient itself, leaving these methods only concerned with data conversions and
// other conveniences. 90% of these methods no longer justify their existence... we probably don't
// need to add more.)
impl ApiClient {
    pub async fn get_machine(&self, id: String) -> CarbideCliResult<rpc::Machine> {
        let mut machines = self
            .0
            .find_machines_by_ids(::rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![id.clone().into()],
                include_history: true,
            })
            .await?;

        if machines.machines.is_empty() {
            return Err(CarbideCliError::MachineNotFound(id.into()));
        }

        let mut machine_details = machines.machines.remove(0);

        // Note: The field going forward is `associated_dpu_machine_ids`, but if we're talking to
        // an older version of the API which doesn't support it, fall back on building our own Vec
        // out of the `associated_dpu_machine_id` field.
        if machine_details.associated_dpu_machine_ids.is_empty() {
            if let Some(ref dpu_id) = machine_details.associated_dpu_machine_id {
                machine_details.associated_dpu_machine_ids = vec![dpu_id.clone()];
            }
        }

        Ok(machine_details)
    }

    pub async fn get_network_device_topology(
        &self,
        id: Option<String>,
    ) -> CarbideCliResult<rpc::NetworkTopologyData> {
        let request = rpc::NetworkTopologyRequest { id };
        self.0
            .get_network_topology(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_machines(
        &self,
        request: rpc::MachineSearchConfig,
        page_size: usize,
    ) -> CarbideCliResult<rpc::MachineList> {
        let all_machine_ids = self.0.find_machine_ids(request.clone()).await?;
        let mut all_machines = rpc::MachineList {
            machines: Vec::with_capacity(all_machine_ids.machine_ids.len()),
        };

        for machine_ids in all_machine_ids.machine_ids.chunks(page_size) {
            let machines = self.get_machines_by_ids(machine_ids).await?;
            all_machines.machines.extend(machines.machines);
        }

        Ok(all_machines)
    }

    pub async fn reboot_instance(
        &self,
        machine_id: ::rpc::common::MachineId,
        boot_with_custom_ipxe: bool,
        apply_updates_on_reboot: bool,
    ) -> CarbideCliResult<()> {
        let request = rpc::InstancePowerRequest {
            machine_id: Some(machine_id),
            operation: rpc::instance_power_request::Operation::PowerReset as i32,
            boot_with_custom_ipxe,
            apply_updates_on_reboot,
        };

        self.0.invoke_instance_power(request).await?;

        Ok(())
    }

    pub async fn release_instances(
        &self,
        instance_ids: Vec<::rpc::common::Uuid>,
    ) -> CarbideCliResult<()> {
        for instance_id in instance_ids {
            let request = rpc::InstanceReleaseRequest {
                id: Some(instance_id),
                issue: None,
                is_repair_tenant: None,
            };
            self.0.release_instance(request).await?;
        }
        Ok(())
    }

    pub async fn identify_uuid(&self, u: uuid::Uuid) -> CarbideCliResult<rpc::UuidType> {
        let request = rpc::IdentifyUuidRequest {
            uuid: Some(u.into()),
        };

        let uuid_details = match self.0.identify_uuid(request).await {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::UuidNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_uuid error calling grpc identify_uuid");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };
        let object_type = match rpc::UuidType::try_from(uuid_details.object_type) {
            Ok(ot) => ot,
            Err(e) => {
                tracing::error!(
                    "Invalid UuidType from carbide api: {}",
                    uuid_details.object_type
                );
                return Err(CarbideCliError::GenericError(e.to_string()));
            }
        };

        Ok(object_type)
    }

    pub async fn identify_mac(
        &self,
        mac_address: MacAddress,
    ) -> CarbideCliResult<(rpc::MacOwner, String)> {
        let request = rpc::IdentifyMacRequest {
            mac_address: mac_address.to_string(),
        };

        let mac_details = match self.0.identify_mac(request).await {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::MacAddressNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_mac error calling grpc identify_mac");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };
        let object_type = match rpc::MacOwner::try_from(mac_details.object_type) {
            Ok(ot) => ot,
            Err(e) => {
                tracing::error!(
                    "Invalid MachineOwner from carbide api: {}",
                    mac_details.object_type
                );
                return Err(CarbideCliError::GenericError(e.to_string()));
            }
        };

        Ok((object_type, mac_details.primary_key))
    }

    pub async fn identify_serial(
        &self,
        serial_number: String,
        exact: bool,
    ) -> CarbideCliResult<::rpc::common::MachineId> {
        let serial_details = match self
            .0
            .identify_serial(IdentifySerialRequest {
                serial_number,
                exact,
            })
            .await
        {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::SerialNumberNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_serial error calling grpc identify_serial");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };

        serial_details
            .machine_id
            .ok_or(CarbideCliError::GenericError(
                "Serial number found without associated machine ID".to_string(),
            ))
    }

    pub async fn get_all_instances(
        &self,
        tenant_org_id: Option<String>,
        vpc_id: Option<String>,
        label_key: Option<String>,
        label_value: Option<String>,
        instance_type_id: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::InstanceList> {
        let all_ids = self
            .get_instance_ids(
                tenant_org_id.clone(),
                vpc_id.clone(),
                label_key.clone(),
                label_value.clone(),
                instance_type_id,
            )
            .await?;
        let mut all_list = rpc::InstanceList {
            instances: Vec::with_capacity(all_ids.instance_ids.len()),
        };

        for ids in all_ids.instance_ids.chunks(page_size) {
            let list = self.0.find_instances_by_ids(ids.to_vec()).await?;
            all_list.instances.extend(list.instances);
        }

        Ok(all_list)
    }

    pub async fn get_one_instance(
        &self,
        instance_id: ::rpc::common::Uuid,
    ) -> CarbideCliResult<rpc::InstanceList> {
        let instances = self
            .0
            .find_instances_by_ids(vec![instance_id.clone()])
            .await?;

        Ok(instances)
    }

    async fn get_instance_ids(
        &self,
        tenant_org_id: Option<String>,
        vpc_id: Option<String>,
        label_key: Option<String>,
        label_value: Option<String>,
        instance_type_id: Option<String>,
    ) -> CarbideCliResult<rpc::InstanceIdList> {
        let request = rpc::InstanceSearchFilter {
            tenant_org_id,
            vpc_id,
            instance_type_id,
            label: if label_key.is_none() && label_value.is_none() {
                None
            } else {
                Some(rpc::Label {
                    key: label_key.unwrap_or_default(),
                    value: label_value,
                })
            },
        };
        self.0
            .find_instance_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_segments(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let all_ids = self
            .get_segment_ids(tenant_org_id.clone(), name.clone())
            .await?;
        let mut all_list = rpc::NetworkSegmentList {
            network_segments: Vec::with_capacity(all_ids.network_segments_ids.len()),
        };

        for ids in all_ids.network_segments_ids.chunks(page_size) {
            let list = self.get_segments_by_ids(ids).await?;
            all_list.network_segments.extend(list.network_segments);
        }

        Ok(all_list)
    }

    pub async fn get_one_segment(
        &self,
        segment_id: ::rpc::common::Uuid,
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let segments = self.get_segments_by_ids(&[segment_id.clone()]).await?;

        Ok(segments)
    }

    async fn get_segment_ids(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
    ) -> CarbideCliResult<rpc::NetworkSegmentIdList> {
        let request = rpc::NetworkSegmentSearchFilter {
            tenant_org_id,
            name,
        };
        self.0
            .find_network_segment_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_segments_by_ids(
        &self,
        segment_ids: &[::rpc::common::Uuid],
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let request = rpc::NetworkSegmentsByIdsRequest {
            network_segments_ids: Vec::from(segment_ids),
            include_history: segment_ids.len() == 1, // only request it when getting data for single resource
            include_num_free_ips: true,
        };
        self.0
            .find_network_segments_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_domains(
        &self,
        id: Option<::rpc::common::Uuid>,
    ) -> CarbideCliResult<rpc::DomainList> {
        let request = rpc::DomainSearchQuery { id, name: None };
        self.0
            .find_domain(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn machine_insert_health_report_override(
        &self,
        id: String,
        report: ::rpc::health::HealthReport,
        replace: bool,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::InsertHealthReportOverrideRequest {
            machine_id: Some(::rpc::MachineId { id }),
            r#override: Some(rpc::HealthReportOverride {
                report: Some(report),
                mode: if replace {
                    rpc::OverrideMode::Replace
                } else {
                    rpc::OverrideMode::Merge
                } as i32,
            }),
        };
        self.0
            .insert_health_report_override(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn machine_remove_health_report_override(
        &self,
        id: String,
        source: String,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::RemoveHealthReportOverrideRequest {
            machine_id: Some(::rpc::MachineId { id }),
            source,
        };
        self.0
            .remove_health_report_override(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn machine_admin_force_delete(
        &self,
        query: ForceDeleteMachineQuery,
    ) -> CarbideCliResult<::rpc::forge::AdminForceDeleteMachineResponse> {
        let request = ::rpc::forge::AdminForceDeleteMachineRequest {
            host_query: query.machine,
            delete_interfaces: query.delete_interfaces,
            delete_bmc_interfaces: query.delete_bmc_interfaces,
            delete_bmc_credentials: query.delete_bmc_credentials,
        };
        self.0
            .admin_force_delete_machine(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn trigger_dpu_reprovisioning(
        &self,
        id: String,
        mode: ::rpc::forge::dpu_reprovisioning_request::Mode,
        update_firmware: bool,
    ) -> CarbideCliResult<()> {
        let request = rpc::DpuReprovisioningRequest {
            dpu_id: Some(::rpc::common::MachineId { id: id.clone() }),
            machine_id: Some(::rpc::common::MachineId { id }),
            mode: mode as i32,
            initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
            update_firmware,
        };
        self.0
            .trigger_dpu_reprovisioning(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn trigger_host_reprovisioning(
        &self,
        id: String,
        mode: ::rpc::forge::host_reprovisioning_request::Mode,
    ) -> CarbideCliResult<()> {
        let request = rpc::HostReprovisioningRequest {
            machine_id: Some(::rpc::common::MachineId { id }),
            mode: mode as i32,
            initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
        };
        self.0.trigger_host_reprovisioning(request).await?;

        Ok(())
    }

    pub async fn set_boot_override(
        &self,
        machine_interface_id: ::rpc::common::Uuid,
        custom_pxe_path: Option<&Path>,
        custom_user_data_path: Option<&Path>,
    ) -> CarbideCliResult<()> {
        let custom_pxe = match custom_pxe_path {
            Some(custom_pxe_path) => Some(std::fs::read_to_string(custom_pxe_path)?),
            None => None,
        };

        let custom_user_data = match custom_user_data_path {
            Some(custom_user_data_path) => Some(std::fs::read_to_string(custom_user_data_path)?),
            None => None,
        };

        let request = MachineBootOverride {
            machine_interface_id: Some(machine_interface_id),
            custom_pxe,
            custom_user_data,
        };

        self.0
            .set_machine_boot_override(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn bmc_reset(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: Option<String>,
        use_ipmitool: bool,
    ) -> CarbideCliResult<rpc::AdminBmcResetResponse> {
        let request = rpc::AdminBmcResetRequest {
            bmc_endpoint_request,
            machine_id,
            use_ipmitool,
        };
        self.0
            .admin_bmc_reset(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn admin_power_control(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: Option<String>,
        action: ::rpc::forge::admin_power_control_request::SystemPowerControl,
    ) -> CarbideCliResult<rpc::AdminPowerControlResponse> {
        let request = rpc::AdminPowerControlRequest {
            bmc_endpoint_request,
            machine_id,
            action: action.into(),
        };
        self.0
            .admin_power_control(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_route_servers(&self) -> CarbideCliResult<Vec<IpAddr>> {
        let route_servers = self.0.get_route_servers().await?;
        route_servers
            .route_servers
            .iter()
            .map(|rs| {
                IpAddr::from_str(rs).map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect()
    }

    pub async fn get_all_machines_interfaces(
        &self,
        id: Option<::rpc::common::Uuid>,
    ) -> CarbideCliResult<rpc::InterfaceList> {
        let request = rpc::InterfaceSearchQuery { id, ip: None };
        self.0
            .find_interfaces(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_site_exploration_report(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<::rpc::site_explorer::SiteExplorationReport> {
        // grab endpoints
        let endpoint_ids = match self.0.find_explored_endpoint_ids().await {
            Ok(endpoint_ids) => endpoint_ids,
            Err(status) => {
                return if status.code() == tonic::Code::Unimplemented {
                    Ok(self.0.get_site_exploration_report().await?)
                } else {
                    Err(status.into())
                };
            }
        };
        let mut all_endpoints = ::rpc::site_explorer::ExploredEndpointList {
            endpoints: Vec::with_capacity(endpoint_ids.endpoint_ids.len()),
        };
        for ids in endpoint_ids.endpoint_ids.chunks(page_size) {
            let list = self.get_explored_endpoints_by_ids(ids).await?;
            all_endpoints.endpoints.extend(list.endpoints);
        }

        // grab managed hosts
        let all_hosts = self.get_all_explored_managed_hosts(page_size).await?;

        Ok(::rpc::site_explorer::SiteExplorationReport {
            endpoints: all_endpoints.endpoints,
            managed_hosts: all_hosts,
        })
    }

    pub async fn get_explored_endpoints_by_ids(
        &self,
        endpoint_ids: &[String],
    ) -> CarbideCliResult<::rpc::site_explorer::ExploredEndpointList> {
        let request = ::rpc::site_explorer::ExploredEndpointsByIdsRequest {
            endpoint_ids: Vec::from(endpoint_ids),
        };
        self.0
            .find_explored_endpoints_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_explored_managed_hosts(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<Vec<::rpc::site_explorer::ExploredManagedHost>> {
        let host_ids = match self.0.find_explored_managed_host_ids().await {
            Ok(host_ids) => host_ids,
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                let hosts = self.0.get_site_exploration_report().await?.managed_hosts;
                return Ok(hosts);
            }
            Err(e) => return Err(e.into()),
        };
        let mut all_hosts = ::rpc::site_explorer::ExploredManagedHostList {
            managed_hosts: Vec::with_capacity(host_ids.host_ids.len()),
        };
        for ids in host_ids.host_ids.chunks(page_size) {
            let list = self.0.find_explored_managed_hosts_by_ids(ids).await?;
            all_hosts.managed_hosts.extend(list.managed_hosts);
        }
        Ok(all_hosts.managed_hosts)
    }

    pub async fn explore(
        &self,
        address: &str,
        mac_address: Option<MacAddress>,
    ) -> CarbideCliResult<::rpc::site_explorer::EndpointExplorationReport> {
        let request = rpc::BmcEndpointRequest {
            ip_address: address.to_string(),
            mac_address: mac_address.map(|mac| mac.to_string()),
        };
        self.0
            .explore(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn re_explore_endpoint(&self, address: &str) -> CarbideCliResult<()> {
        let request = rpc::ReExploreEndpointRequest {
            ip_address: address.to_string(),
            if_version_match: None,
        };
        self.0
            .re_explore_endpoint(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn is_bmc_in_managed_host(
        &self,
        address: &str,
        mac_address: Option<MacAddress>,
    ) -> CarbideCliResult<IsBmcInManagedHostResponse> {
        let request = rpc::BmcEndpointRequest {
            ip_address: address.to_string(),
            mac_address: mac_address.map(|mac| mac.to_string()),
        };
        self.0
            .is_bmc_in_managed_host(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn bmc_credential_status(
        &self,
        address: &str,
        mac_address: Option<MacAddress>,
    ) -> CarbideCliResult<BmcCredentialStatusResponse> {
        let request = rpc::BmcEndpointRequest {
            ip_address: address.to_string(),
            mac_address: mac_address.map(|mac| mac.to_string()),
        };
        self.0
            .bmc_credential_status(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn copy_bfb_to_dpu_rshim(
        &self,
        address: String,
        mac_address: Option<MacAddress>,
        timeout_config: Option<TimeoutConfig>,
    ) -> CarbideCliResult<()> {
        let request = rpc::CopyBfbToDpuRshimRequest {
            ssh_request: Some(SshRequest {
                endpoint_request: Some(BmcEndpointRequest {
                    ip_address: address.to_string(),
                    mac_address: mac_address.map(|mac| mac.to_string()),
                }),
                timeout_config: timeout_config.map(|config| config.to_rpc_timeout_config()),
            }),
        };

        self.0
            .copy_bfb_to_dpu_rshim(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_machines_by_ids(
        &self,
        machine_ids: &[::rpc::common::MachineId],
    ) -> CarbideCliResult<rpc::MachineList> {
        let request = ::rpc::forge::MachinesByIdsRequest {
            machine_ids: Vec::from(machine_ids),
            ..Default::default()
        };
        self.0
            .find_machines_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn set_dynamic_config(
        &self,
        feature: rpc::ConfigSetting,
        value: String,
        expiry: Option<String>,
    ) -> CarbideCliResult<()> {
        let request = rpc::SetDynamicConfigRequest {
            setting: feature.into(),
            value,
            expiry,
        };
        self.0
            .set_dynamic_config(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_expected_machine(
        &self,
        bmc_mac_address: MacAddress,
        bmc_username: String,
        bmc_password: String,
        chassis_serial_number: String,
        fallback_dpu_serial_numbers: Option<Vec<String>>,
        metadata: ::rpc::forge::Metadata,
        sku_id: Option<String>,
    ) -> Result<(), CarbideCliError> {
        let request = rpc::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username,
            bmc_password,
            chassis_serial_number,
            fallback_dpu_serial_numbers: fallback_dpu_serial_numbers.unwrap_or_default(),
            metadata: Some(metadata),
            sku_id,
        };

        self.0
            .add_expected_machine(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_expected_machine(
        &self,
        bmc_mac_address: MacAddress,
        bmc_username: Option<String>,
        bmc_password: Option<String>,
        chassis_serial_number: Option<String>,
        fallback_dpu_serial_numbers: Option<Vec<String>>,
        metadata: ::rpc::forge::Metadata,
        sku_id: Option<String>,
    ) -> Result<(), CarbideCliError> {
        let expected_machine = self
            .0
            .get_expected_machine(bmc_mac_address.to_string())
            .await?;
        let request = rpc::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: bmc_username.unwrap_or(expected_machine.bmc_username),
            bmc_password: bmc_password.unwrap_or(expected_machine.bmc_password),
            chassis_serial_number: chassis_serial_number
                .unwrap_or(expected_machine.chassis_serial_number),
            fallback_dpu_serial_numbers: fallback_dpu_serial_numbers
                .unwrap_or(expected_machine.fallback_dpu_serial_numbers),
            metadata: Some(metadata),
            sku_id,
        };

        self.0
            .update_expected_machine(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn replace_all_expected_machines(
        &self,
        expected_machine_list: Vec<cli_options::ExpectedMachineJson>,
    ) -> Result<(), CarbideCliError> {
        let request = rpc::ExpectedMachineList {
            expected_machines: expected_machine_list
                .into_iter()
                .map(|machine| rpc::ExpectedMachine {
                    bmc_mac_address: machine.bmc_mac_address.to_string(),
                    bmc_username: machine.bmc_username,
                    bmc_password: machine.bmc_password,
                    chassis_serial_number: machine.chassis_serial_number,
                    fallback_dpu_serial_numbers: machine
                        .fallback_dpu_serial_numbers
                        .unwrap_or_default(),
                    metadata: machine.metadata,
                    sku_id: machine.sku_id,
                })
                .collect(),
        };

        self.0
            .replace_all_expected_machines(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_vpcs(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
        label_key: Option<String>,
        label_value: Option<String>,
    ) -> CarbideCliResult<rpc::VpcList> {
        let all_ids = self
            .get_vpc_ids(tenant_org_id.clone(), name.clone(), label_key, label_value)
            .await?;
        let mut all_list = rpc::VpcList {
            vpcs: Vec::with_capacity(all_ids.vpc_ids.len()),
        };

        for ids in all_ids.vpc_ids.chunks(page_size) {
            let list = self.0.find_vpcs_by_ids(ids).await?;
            all_list.vpcs.extend(list.vpcs);
        }

        Ok(all_list)
    }

    pub async fn get_one_vpc(&self, vpc_id: ::rpc::common::Uuid) -> CarbideCliResult<rpc::VpcList> {
        let vpcs = self.0.find_vpcs_by_ids(&[vpc_id.clone()]).await?;

        Ok(vpcs)
    }

    pub async fn get_vpc_by_name(&self, name: &str) -> CarbideCliResult<rpc::VpcList> {
        let vpcs = self
            .0
            .find_vpcs(VpcSearchQuery {
                id: None,
                name: Some(name.to_string()),
            })
            .await?;

        Ok(vpcs)
    }

    pub async fn create_vpc(&self, name: &str, vpc_id: ::rpc::Uuid) -> CarbideCliResult<rpc::Vpc> {
        let vpc = match self
            .0
            .create_vpc(VpcCreationRequest {
                name: name.to_string(),
                tenant_organization_id: "devenv_test_org".to_string(),
                tenant_keyset_id: None,
                network_virtualization_type: Some(
                    VpcVirtualizationType::EthernetVirtualizerWithNvue as i32,
                ),
                id: Some(vpc_id),
                metadata: Some(rpc::Metadata {
                    name: name.to_string(),
                    description: "test vpc".to_string(),
                    labels: vec![],
                }),
                network_security_group_id: None,
            })
            .await
        {
            Ok(vpc) => vpc,
            Err(e) => return Err(e.into()),
        };

        Ok(vpc)
    }

    pub async fn create_network_segment(
        &self,
        id: Uuid,
        vpc_id: Option<Uuid>,
        name: String,
        prefix: String,
        gateway: Option<String>,
    ) -> CarbideCliResult<NetworkSegment> {
        let request = NetworkSegmentCreationRequest {
            vpc_id,
            name,
            subdomain_id: None,
            mtu: Some(9000),
            prefixes: vec![NetworkPrefix {
                id: None,
                prefix,
                gateway,
                reserve_first: 0,
                state: None,
                events: vec![],
                free_ip_count: 1,
                svi_ip: None,
            }],
            segment_type: NetworkSegmentType::Tenant as i32,
            id: Some(id),
        };
        self.0
            .create_network_segment(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_vpc_ids(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        label_key: Option<String>,
        label_value: Option<String>,
    ) -> CarbideCliResult<rpc::VpcIdList> {
        let request = rpc::VpcSearchFilter {
            tenant_org_id,
            name,
            label: if label_key.is_none() && label_value.is_none() {
                None
            } else {
                Some(rpc::Label {
                    key: label_key.unwrap_or_default(),
                    value: label_value,
                })
            },
        };
        self.0
            .find_vpc_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    /// set_vpc_network_virtualization_type sends out a `VpcUpdateVirtualizationRequest`
    /// to the API, with the purpose of being able to modify the underlying
    /// VpcVirtualizationType (or NetworkVirtualizationType) of the VPC. This will
    /// return an error if there are configured instances in the VPC (you can only
    /// do this with an empty VPC).
    pub async fn set_vpc_network_virtualization_type(
        &self,
        vpc: rpc::Vpc,
        virtualizer: VpcVirtualizationType,
    ) -> CarbideCliResult<()> {
        let request = rpc::VpcUpdateVirtualizationRequest {
            id: vpc.id,
            if_version_match: None,
            network_virtualization_type: Some(virtualizer as i32),
        };
        self.0.update_vpc_virtualization(request).await?;

        Ok(())
    }

    pub async fn create_vpc_peering(
        &self,
        vpc_id: Option<::rpc::common::Uuid>,
        peer_vpc_id: Option<::rpc::common::Uuid>,
    ) -> CarbideCliResult<rpc::VpcPeering> {
        let request = rpc::VpcPeeringCreationRequest {
            vpc_id,
            peer_vpc_id,
        };
        self.0
            .create_vpc_peering(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn find_vpc_peering_ids(
        &self,
        vpc_id: Option<::rpc::common::Uuid>,
    ) -> CarbideCliResult<rpc::VpcPeeringIdList> {
        let request = rpc::VpcPeeringSearchFilter { vpc_id };
        self.0
            .find_vpc_peering_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn find_vpc_peerings_by_ids(
        &self,
        vpc_peering_ids: Vec<::rpc::common::Uuid>,
    ) -> CarbideCliResult<rpc::VpcPeeringList> {
        let request = rpc::VpcPeeringsByIdsRequest { vpc_peering_ids };
        self.0
            .find_vpc_peerings_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn delete_vpc_peering(
        &self,
        id: Option<::rpc::common::Uuid>,
    ) -> CarbideCliResult<VpcPeeringDeletionResult> {
        let request = rpc::VpcPeeringDeletionRequest { id };
        self.0
            .delete_vpc_peering(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_ib_partitions(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let all_ids = self
            .get_ib_partition_ids(tenant_org_id.clone(), name.clone())
            .await?;
        let mut all_list = rpc::IbPartitionList {
            ib_partitions: Vec::with_capacity(all_ids.ib_partition_ids.len()),
        };

        for ids in all_ids.ib_partition_ids.chunks(page_size) {
            let list = self.get_ib_partitions_by_ids(ids).await?;
            all_list.ib_partitions.extend(list.ib_partitions);
        }

        Ok(all_list)
    }

    pub async fn get_one_ib_partition(
        &self,
        ib_partition_id: ::rpc::common::Uuid,
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let partitions = self
            .get_ib_partitions_by_ids(&[ib_partition_id.clone()])
            .await?;

        Ok(partitions)
    }

    async fn get_ib_partition_ids(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
    ) -> CarbideCliResult<rpc::IbPartitionIdList> {
        let request = rpc::IbPartitionSearchFilter {
            tenant_org_id,
            name,
        };
        self.0
            .find_ib_partition_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_ib_partitions_by_ids(
        &self,
        ids: &[::rpc::common::Uuid],
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let request = rpc::IbPartitionsByIdsRequest {
            ib_partition_ids: Vec::from(ids),
            include_history: ids.len() == 1,
        };
        self.0
            .find_ib_partitions_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_keysets(
        &self,
        tenant_org_id: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::TenantKeySetList> {
        let all_ids = self.get_keyset_ids(tenant_org_id.clone()).await?;
        let mut all_list = rpc::TenantKeySetList {
            keyset: Vec::with_capacity(all_ids.keyset_ids.len()),
        };

        for ids in all_ids.keyset_ids.chunks(page_size) {
            let list = self.get_keysets_by_ids(ids).await?;
            all_list.keyset.extend(list.keyset);
        }

        Ok(all_list)
    }

    pub async fn get_one_keyset(
        &self,
        keyset_id: rpc::TenantKeysetIdentifier,
    ) -> CarbideCliResult<rpc::TenantKeySetList> {
        let keysets = self.get_keysets_by_ids(&[keyset_id.clone()]).await?;

        Ok(keysets)
    }

    async fn get_keyset_ids(
        &self,
        tenant_org_id: Option<String>,
    ) -> CarbideCliResult<rpc::TenantKeysetIdList> {
        let request = rpc::TenantKeysetSearchFilter { tenant_org_id };
        self.0
            .find_tenant_keyset_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_keysets_by_ids(
        &self,
        identifiers: &[rpc::TenantKeysetIdentifier],
    ) -> CarbideCliResult<rpc::TenantKeySetList> {
        let request = rpc::TenantKeysetsByIdsRequest {
            keyset_ids: Vec::from(identifiers),
            include_key_data: true,
        };
        self.0
            .find_tenant_keysets_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn machine_set_auto_update(
        &self,
        req: MachineAutoupdate,
    ) -> CarbideCliResult<::rpc::forge::MachineSetAutoUpdateResponse> {
        let action = if req.enable {
            ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Enable
        } else if req.disable {
            ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Disable
        } else {
            ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Clear
        };
        let request = ::rpc::forge::MachineSetAutoUpdateRequest {
            machine_id: Some(::rpc::MachineId {
                id: req.machine.to_string(),
            }),
            action: action.into(),
        };
        self.0
            .machine_set_auto_update(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_subnet_ids_for_names(&self, subnets: &Vec<String>) -> CarbideCliResult<Vec<Uuid>> {
        // find all the segment ids for the specified subnets.
        let mut network_segment_ids = Vec::default();
        for network_segment_name in subnets {
            let segment_request = rpc::NetworkSegmentSearchFilter {
                name: Some(network_segment_name.clone()),
                tenant_org_id: None,
            };

            match self.0.find_network_segment_ids(segment_request).await {
                Ok(response) => {
                    network_segment_ids.extend_from_slice(&response.network_segments_ids);
                }

                Err(e) => {
                    return Err(CarbideCliError::GenericError(format!(
                        "network segment: {network_segment_name} retrieval error {e}"
                    )));
                }
            }
        }

        Ok(network_segment_ids)
    }

    pub async fn allocate_instance(
        &self,
        machine: Machine,
        allocate_instance: &AllocateInstance,
        instance_name: &str,
        modified_by: Option<String>,
    ) -> CarbideCliResult<rpc::Instance> {
        let mut vf_function_id = 0;
        let (interface_configs, tenant_org) = if !allocate_instance.subnet.is_empty() {
            if !allocate_instance.vf_vpc_prefix_id.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "Cannot use vf_vpc_prefix_id with subnet".to_string(),
                ));
            }
            let pf_network_segment_ids = self
                .get_subnet_ids_for_names(&allocate_instance.subnet)
                .await?;
            if pf_network_segment_ids.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "no network segments found.".to_string(),
                ));
            }
            let vf_network_segment_ids = self
                .get_subnet_ids_for_names(&allocate_instance.vf_subnet)
                .await?;
            let vfs_per_pf = if vf_network_segment_ids.len() < pf_network_segment_ids.len() {
                1
            } else {
                vf_network_segment_ids.len() / pf_network_segment_ids.len()
            };
            tracing::debug!("VFs per PF: {vfs_per_pf}");

            let mut next_device_instance = HashMap::new();

            let Some(interfaces) = machine.discovery_info.map(|di| di.network_interfaces) else {
                return Err(CarbideCliError::GenericError(format!(
                    "no inteface information for machine: {}",
                    machine.id.unwrap_or_default()
                )));
            };

            let mut interface_iter = interfaces.iter().filter(|iface| {
                iface
                    .pci_properties
                    .as_ref()
                    .map(|pci| &pci.vendor)
                    .is_some_and(|v| v.to_ascii_lowercase().contains("mellanox"))
            });
            let mut interface_config = Vec::default();
            let mut vf_chunk_iter = vf_network_segment_ids.chunks(vfs_per_pf);

            for network_segment_id in pf_network_segment_ids {
                let device = interface_iter
                    .next()
                    .ok_or(CarbideCliError::GenericError(
                        "Insufficient interfaces for selected machine".to_string(),
                    ))?
                    .pci_properties
                    .as_ref()
                    .map(|pci| pci.device.clone())
                    .clone();

                if device.is_none() {
                    continue;
                }

                let device_instance = *next_device_instance
                    .entry(device.clone())
                    .and_modify(|i| *i += 1)
                    .or_insert(0) as u32;

                interface_config.push(rpc::InstanceInterfaceConfig {
                    function_type: rpc::InterfaceFunctionType::Physical as i32,
                    network_segment_id: Some(network_segment_id.clone()), // to support legacy.
                    network_details: Some(NetworkDetails::SegmentId(network_segment_id)),
                    device: device.clone(),
                    device_instance,
                    virtual_function_id: None,
                });

                if let Some(vf_network_segment_chunks) = vf_chunk_iter.next() {
                    for vf_network_segment_id in vf_network_segment_chunks {
                        interface_config.push(rpc::InstanceInterfaceConfig {
                            function_type: rpc::InterfaceFunctionType::Virtual as i32,
                            network_segment_id: Some(vf_network_segment_id.clone()), // to support legacy.
                            network_details: Some(NetworkDetails::SegmentId(
                                vf_network_segment_id.clone(),
                            )),
                            device: device.clone(),
                            device_instance,
                            virtual_function_id: Some(vf_function_id),
                        });
                        vf_function_id += 1;
                    }
                }
            }

            (
                interface_config,
                allocate_instance
                    .tenant_org
                    .clone()
                    .unwrap_or("Forge-simulation-tenant".to_string()),
            )
        } else if !allocate_instance.vpc_prefix_id.is_empty() {
            let Some(discovery_info) = &machine.discovery_info else {
                return Err(CarbideCliError::GenericError(
                    "Machine discovery info is required for VPC prefix allocation.".to_string(),
                ));
            };
            // Create a vector of interface configs for each VPC prefix.  only Mellanox devices are supported.
            let mut interface_index_map = HashMap::new();
            let mut interface_configs = Vec::new();
            let pf_vpc_prefix_ids = &allocate_instance.vpc_prefix_id;
            let vf_vpc_prefix_ids = &allocate_instance.vf_vpc_prefix_id;

            let vfs_per_pf = if vf_vpc_prefix_ids.len() < pf_vpc_prefix_ids.len() {
                1
            } else {
                // pf_vpc_prefix_ids is checked for empty above (len() cannot be 0)
                vf_vpc_prefix_ids.len() / pf_vpc_prefix_ids.len()
            };
            tracing::debug!("VFs per PF: {vfs_per_pf}");
            let mut vf_chunk_iter = vf_vpc_prefix_ids.chunks(vfs_per_pf);
            for (map_index, i) in discovery_info
                .network_interfaces
                .iter()
                .filter(|i| {
                    i.pci_properties
                        .as_ref()
                        .is_some_and(|pci| pci.vendor.to_ascii_lowercase().contains("mellanox"))
                })
                .enumerate()
            {
                if let Some(pci_properties) = &i.pci_properties {
                    let Some(vpc_prefix_id) = allocate_instance.vpc_prefix_id.get(map_index) else {
                        tracing::debug!("No more vpc prefix ids; done");
                        break;
                    };

                    let device_instance = *interface_index_map
                        .entry(pci_properties.device.clone())
                        .and_modify(|c| *c += 1)
                        .or_insert(0u32);

                    let new_interface = rpc::InstanceInterfaceConfig {
                        function_type: rpc::InterfaceFunctionType::Physical as i32,
                        network_segment_id: None,
                        network_details: Some(NetworkDetails::VpcPrefixId(::rpc::Uuid {
                            value: vpc_prefix_id.clone(),
                        })),
                        device: Some(pci_properties.device.clone()),
                        device_instance,
                        virtual_function_id: None,
                    };
                    tracing::debug!("Adding interface: {:?}", new_interface);

                    interface_configs.push(new_interface);

                    if let Some(vf_prefix_chunks) = vf_chunk_iter.next() {
                        for vf_vpc_prefix_id in vf_prefix_chunks {
                            let new_interface = rpc::InstanceInterfaceConfig {
                                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                                network_segment_id: None,
                                network_details: Some(NetworkDetails::VpcPrefixId(::rpc::Uuid {
                                    value: vf_vpc_prefix_id.clone(),
                                })),
                                device: Some(pci_properties.device.clone()),
                                device_instance,
                                virtual_function_id: Some(vf_function_id),
                            };
                            vf_function_id += 1;
                            tracing::debug!("Adding interface: {:?}", new_interface);
                            interface_configs.push(new_interface);
                        }
                    }
                } else {
                    tracing::debug!("No pci device info for interface: {i:?}");
                }
            }

            (
                interface_configs,
                allocate_instance.tenant_org.clone().ok_or_else(|| {
                    CarbideCliError::GenericError(
                        "Tenant org is mandatory in case of vpc_prefix.".to_string(),
                    )
                })?,
            )
        } else {
            return Err(CarbideCliError::GenericError(
                "Either network segment id or vpc_prefix id is needed.".to_string(),
            ));
        };

        if interface_configs.len()
            != (allocate_instance.subnet.len()
                + allocate_instance.vf_subnet.len()
                + allocate_instance.vpc_prefix_id.len()
                + allocate_instance.vf_vpc_prefix_id.len())
        {
            return Err(CarbideCliError::GenericError(
                "Could not create the correct number of interface configs to satisfy request."
                    .to_string(),
            ));
        }
        let tenant_config = rpc::TenantConfig {
            user_data: None,
            custom_ipxe: "Non-existing-ipxe".to_string(),
            phone_home_enabled: false,
            always_boot_with_custom_ipxe: false,
            tenant_organization_id: tenant_org,
            tenant_keyset_ids: vec![],
            hostname: None,
        };

        let instance_config = rpc::InstanceConfig {
            tenant: Some(tenant_config),
            os: allocate_instance.os.clone(),
            network: Some(rpc::InstanceNetworkConfig {
                interfaces: interface_configs,
            }),
            network_security_group_id: allocate_instance.network_security_group_id.clone(),
            infiniband: None,
            storage: None,
        };

        let mut labels = vec![
            rpc::Label {
                key: String::from("cloud-unsafe-op"),
                value: None,
            },
            rpc::Label {
                key: String::from("admin-cli-last-modified-by"),
                value: modified_by,
            },
        ];

        match (&allocate_instance.label_key, &allocate_instance.label_value) {
            (None, Some(_)) => {
                tracing::error!("label key cannot be empty while value is not empty.");
            }
            (Some(key), value) => labels.push(rpc::Label {
                key: key.to_string(),
                value: value.clone(),
            }),
            (None, None) => {}
        }

        let instance_request = rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(::rpc::common::MachineId {
                id: machine.id.unwrap_or_default().id,
            }),

            instance_type_id: allocate_instance.instance_type_id.clone(),
            config: Some(instance_config),
            metadata: Some(rpc::Metadata {
                name: instance_name.to_string(),
                description: "instance created from admin-cli".to_string(),
                labels,
            }),
            allow_unhealthy_machine: false,
        };

        tracing::trace!("{}", serde_json::to_string(&instance_request).unwrap());
        self.0
            .allocate_instance(instance_request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn update_instance_os(
        &self,
        update_instance: UpdateInstanceOS,
        modified_by: Option<String>,
    ) -> CarbideCliResult<rpc::Instance> {
        let instance_uuid = ::rpc::Uuid {
            value: update_instance.instance,
        };

        let find_response = self
            .0
            .find_instances_by_ids(vec![instance_uuid.clone()])
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;

        let instance = find_response
            .instances
            .first()
            .ok_or_else(|| CarbideCliError::InstanceNotFound(instance_uuid.clone()))?;

        let config = instance.config.clone().map(|mut c| {
            c.os = Some(update_instance.os);
            c
        });

        tracing::info!("{:?}", config);

        let metadata = instance.metadata.clone().map(|mut m| {
            let mut labels: Vec<rpc::Label> = m
                .labels
                .into_iter()
                .filter(|l| l.key != "cloud-unsafe-op" && l.key != "admin-cli-last-modified-by")
                .collect();
            labels.push(rpc::Label {
                key: String::from("cloud-unsafe-op"),
                value: None,
            });
            labels.push(rpc::Label {
                key: String::from("admin-cli-last-modified-by"),
                value: modified_by,
            });
            m.labels = labels;

            m
        });

        let update_instance_request = rpc::InstanceConfigUpdateRequest {
            instance_id: Some(instance_uuid),
            if_version_match: Some(instance.config_version.clone()),
            config,
            metadata,
        };
        self.0
            .update_instance_config(update_instance_request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn add_update_machine_validation_external_config(
        &self,
        name: String,
        description: String,
        config: Vec<u8>,
    ) -> CarbideCliResult<()> {
        let request = rpc::AddUpdateMachineValidationExternalConfigRequest {
            name,
            description: Some(description),
            config,
        };
        self.0
            .add_update_machine_validation_external_config(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_machine_validation_results(
        &self,
        arg_machine_id: Option<String>,
        history: bool,
        arg_validation_id: Option<String>,
    ) -> CarbideCliResult<rpc::MachineValidationResultList> {
        let mut machine_id: Option<::rpc::common::MachineId> = None;
        if let Some(id) = arg_machine_id {
            machine_id = Some(::rpc::common::MachineId { id })
        }
        let mut validation_id: Option<::rpc::common::Uuid> = None;
        if let Some(value) = arg_validation_id {
            validation_id = Some(::rpc::common::Uuid { value })
        }
        let request = rpc::MachineValidationGetRequest {
            machine_id,
            include_history: history,
            validation_id,
        };
        self.0
            .get_machine_validation_results(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn delete_storage_cluster(
        &self,
        id: ::rpc::common::Uuid,
        name: String,
    ) -> CarbideCliResult<()> {
        let request = rpc::DeleteStorageClusterRequest { name, id: Some(id) };
        self.0.delete_storage_cluster(request).await?;
        Ok(())
    }

    pub async fn update_storage_cluster(
        &self,
        id: ::rpc::common::Uuid,
        host: Vec<String>,
        port: Option<u32>,
        username: Option<String>,
        password: Option<String>,
    ) -> CarbideCliResult<rpc::StorageCluster> {
        if host.is_empty() && port.is_none() && username.is_none() && password.is_none() {
            return Err(CarbideCliError::GenericError(
                "Invalid arguments".to_string(),
            ));
        }
        let cluster = self.0.get_storage_cluster(id.clone()).await?;
        if cluster.attributes.is_none() {
            return Err(CarbideCliError::Empty);
        }
        let mut new_attrs = cluster.attributes.clone().unwrap();
        if !host.is_empty() {
            new_attrs.host = host;
        }
        if let Some(x) = port {
            new_attrs.port = x;
        }
        if username.is_some() {
            new_attrs.username = username;
        }
        if password.is_some() {
            new_attrs.password = password;
        }
        let request = rpc::UpdateStorageClusterRequest {
            cluster_id: Some(id),
            attributes: Some(new_attrs),
        };

        self.0
            .update_storage_cluster(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_machine_validation_runs(
        &self,
        arg_machine_id: Option<String>,
        include_history: bool,
    ) -> CarbideCliResult<rpc::MachineValidationRunList> {
        let mut machine_id: Option<::rpc::common::MachineId> = None;
        if let Some(id) = arg_machine_id {
            machine_id = Some(::rpc::common::MachineId { id })
        }
        let request = rpc::MachineValidationRunListGetRequest {
            machine_id,
            include_history,
        };
        self.0
            .get_machine_validation_runs(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn on_demand_machine_validation(
        &self,
        machine_id: String,
        tags: Option<Vec<String>>,
        allowed_tests: Option<Vec<String>>,
        run_unverfied_tests: bool,
        contexts: Option<Vec<String>>,
    ) -> CarbideCliResult<rpc::MachineValidationOnDemandResponse> {
        let request = rpc::MachineValidationOnDemandRequest {
            machine_id: Some(::rpc::common::MachineId { id: machine_id }),
            tags: tags.unwrap_or_default(),
            allowed_tests: allowed_tests.unwrap_or_default(),
            action: rpc::machine_validation_on_demand_request::Action::Start.into(),
            run_unverfied_tests,
            contexts: contexts.unwrap_or_default(),
        };
        self.0
            .on_demand_machine_validation(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn list_storage_pool(
        &self,
        cluster_id: Option<::rpc::common::Uuid>,
        tenant_organization_id: Option<String>,
    ) -> CarbideCliResult<Vec<rpc::StoragePool>> {
        let request = rpc::ListStoragePoolRequest {
            cluster_id,
            tenant_organization_id,
        };
        let response = self.0.list_storage_pool(request).await?;
        Ok(response.pools)
    }

    pub async fn delete_storage_pool(
        &self,
        cluster_id: ::rpc::common::Uuid,
        pool_id: ::rpc::common::Uuid,
    ) -> CarbideCliResult<()> {
        let request = rpc::DeleteStoragePoolRequest {
            cluster_id: Some(cluster_id),
            pool_id: Some(pool_id),
        };
        self.0.delete_storage_pool(request).await?;
        Ok(())
    }

    pub async fn update_storage_pool(
        &self,
        id: ::rpc::common::Uuid,
        capacity: Option<u64>,
        name: Option<String>,
        description: Option<String>,
    ) -> CarbideCliResult<rpc::StoragePool> {
        if capacity.is_none() && name.is_none() && description.is_none() {
            return Err(CarbideCliError::GenericError(
                "Invalid arguments".to_string(),
            ));
        }
        let pool = self.0.get_storage_pool(id).await?;
        if pool.attributes.is_none() {
            return Err(CarbideCliError::Empty);
        }
        let mut new_attrs = pool.attributes.clone().unwrap();
        if let Some(x) = capacity {
            new_attrs.capacity = x;
        }
        if name.is_some() {
            new_attrs.name = name;
        }
        if description.is_some() {
            new_attrs.description = description;
        }
        self.0
            .update_storage_pool(new_attrs)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn delete_storage_volume(
        &self,
        cluster_id: ::rpc::common::Uuid,
        pool_id: ::rpc::common::Uuid,
        volume_id: ::rpc::common::Uuid,
    ) -> CarbideCliResult<()> {
        let request = rpc::DeleteStorageVolumeRequest {
            volume_id: Some(volume_id),
            pool_id: Some(pool_id),
            cluster_id: Some(cluster_id),
        };
        self.0.delete_storage_volume(request).await?;
        Ok(())
    }

    pub async fn update_storage_volume(
        &self,
        id: ::rpc::common::Uuid,
        capacity: Option<u64>,
        name: Option<String>,
        description: Option<String>,
    ) -> CarbideCliResult<rpc::StorageVolume> {
        if capacity.is_none() && name.is_none() && description.is_none() {
            return Err(CarbideCliError::GenericError(
                "Invalid arguments".to_string(),
            ));
        }
        let volume = self.0.get_storage_volume(id).await?;
        if volume.attributes.is_none() {
            return Err(CarbideCliError::Empty);
        }
        let mut new_attrs = volume.attributes.clone().unwrap();
        if let Some(x) = capacity {
            new_attrs.capacity = x;
        }
        if name.is_some() {
            new_attrs.name = name;
        }
        if description.is_some() {
            new_attrs.description = description;
        }
        self.0
            .update_storage_volume(new_attrs)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn list_os_image(
        &self,
        tenant_organization_id: Option<String>,
    ) -> CarbideCliResult<Vec<rpc::OsImage>> {
        let request = rpc::ListOsImageRequest {
            tenant_organization_id,
        };
        let response = self.0.list_os_image(request).await?;
        Ok(response.images)
    }

    pub async fn delete_os_image(
        &self,
        id: ::rpc::common::Uuid,
        tenant_organization_id: String,
    ) -> CarbideCliResult<()> {
        let request = rpc::DeleteOsImageRequest {
            id: Some(id),
            tenant_organization_id,
        };
        self.0.delete_os_image(request).await?;
        Ok(())
    }

    pub async fn update_os_image(
        &self,
        id: ::rpc::common::Uuid,
        auth_type: Option<String>,
        auth_token: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> CarbideCliResult<rpc::OsImage> {
        let os_image = self.0.get_os_image(id).await?;
        if os_image.attributes.is_none() {
            return Err(CarbideCliError::Empty);
        }
        let mut new_attrs = os_image.attributes.clone().unwrap();
        if auth_type.is_some() {
            new_attrs.auth_type = auth_type;
        }
        if auth_token.is_some() {
            new_attrs.auth_token = auth_token;
        }
        if name.is_some() {
            new_attrs.name = name;
        }
        if description.is_some() {
            new_attrs.description = description;
        }
        self.0
            .update_os_image(new_attrs)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn update_instance_config(
        &self,
        instance_id: String,
        version: String,
        config: rpc::InstanceConfig,
        metadata: Option<rpc::Metadata>,
    ) -> CarbideCliResult<rpc::Instance> {
        let request = rpc::InstanceConfigUpdateRequest {
            instance_id: Some(::rpc::Uuid { value: instance_id }),
            if_version_match: Some(version),
            config: Some(config),
            metadata,
        };
        self.0
            .update_instance_config(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn update_vpc_config(
        &self,
        vpc_id: String,
        version: String,
        name: String,
        metadata: Option<rpc::Metadata>,
        network_security_group_id: Option<String>,
    ) -> CarbideCliResult<rpc::Vpc> {
        let request = rpc::VpcUpdateRequest {
            name,
            id: Some(::rpc::Uuid { value: vpc_id }),
            if_version_match: Some(version),
            metadata,
            network_security_group_id,
        };
        self.0
            .update_vpc(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .vpc
            .ok_or(CarbideCliError::Empty)
    }

    pub async fn get_machine_validation_tests(
        &self,
        test_id: Option<String>,
        platforms: Vec<String>,
        contexts: Vec<String>,
        show_un_verified: bool,
    ) -> CarbideCliResult<rpc::MachineValidationTestsGetResponse> {
        let verified = if show_un_verified { None } else { Some(true) };
        let request = rpc::MachineValidationTestsGetRequest {
            supported_platforms: platforms,
            contexts,
            test_id,
            verified,
            ..rpc::MachineValidationTestsGetRequest::default()
        };
        self.0
            .get_machine_validation_tests(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn machine_validation_test_verfied(
        &self,
        test_id: String,
        version: String,
    ) -> CarbideCliResult<()> {
        let request = rpc::MachineValidationTestVerfiedRequest { test_id, version };
        self.0.machine_validation_test_verfied(request).await?;
        Ok(())
    }

    pub async fn machine_validation_test_enable_disable(
        &self,
        test_id: String,
        version: String,
        is_enabled: bool,
    ) -> CarbideCliResult<()> {
        let request = rpc::MachineValidationTestEnableDisableTestRequest {
            test_id,
            version,
            is_enabled,
        };
        self.0
            .machine_validation_test_enable_disable_test(request)
            .await?;
        Ok(())
    }

    pub async fn machine_validation_test_update(
        &self,
        test_id: String,
        version: String,
        payload: rpc::machine_validation_test_update_request::Payload,
    ) -> CarbideCliResult<()> {
        let request = rpc::MachineValidationTestUpdateRequest {
            test_id,
            version,
            payload: Some(payload),
        };
        self.0.update_machine_validation_test(request).await?;
        Ok(())
    }

    pub async fn update_machine_metadata(
        &self,
        machine_id: ::rpc::common::MachineId,
        metadata: ::rpc::forge::Metadata,
        current_version: String,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::MachineMetadataUpdateRequest {
            machine_id: Some(machine_id),
            if_version_match: Some(current_version),
            metadata: Some(metadata),
        };
        self.0
            .update_machine_metadata(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn assign_sku_to_machine(
        &self,
        sku_id: String,
        machine_id: ::rpc::common::MachineId,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::SkuMachinePair {
            sku_id,
            machine_id: Some(machine_id),
        };
        self.0
            .assign_sku_to_machine(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn create_network_security_group(
        &self,
        id: Option<String>,
        tenant_organization_id: String,
        metadata: rpc::Metadata,
        rules: Vec<rpc::NetworkSecurityGroupRuleAttributes>,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroup> {
        let request = CreateNetworkSecurityGroupRequest {
            id,
            tenant_organization_id,
            metadata: Some(metadata),
            network_security_group_attributes: Some(NetworkSecurityGroupAttributes { rules }),
        };

        let response = self.0.create_network_security_group(request).await?;

        response
            .network_security_group
            .ok_or(CarbideCliError::Empty)
    }

    pub async fn get_single_network_security_group(
        &self,
        id: String,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroup> {
        self.0
            .find_network_security_groups_by_ids(FindNetworkSecurityGroupsByIdsRequest {
                tenant_organization_id: None,
                network_security_group_ids: vec![id],
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .network_security_groups
            .pop()
            .ok_or(CarbideCliError::Empty)
    }

    pub async fn get_network_security_group_attachments(
        &self,
        id: String,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroupAttachments> {
        self.0
            .get_network_security_group_attachments(GetNetworkSecurityGroupAttachmentsRequest {
                network_security_group_ids: vec![id],
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .attachments
            .pop()
            .ok_or(CarbideCliError::Empty)
    }

    pub async fn get_network_security_group_propagation_status(
        &self,
        id: String,
        vpc_ids: Option<Vec<String>>,
        instance_ids: Option<Vec<String>>,
    ) -> CarbideCliResult<(
        Vec<rpc::NetworkSecurityGroupPropagationObjectStatus>,
        Vec<rpc::NetworkSecurityGroupPropagationObjectStatus>,
    )> {
        let nsg = self
            .0
            .get_network_security_group_propagation_status(
                GetNetworkSecurityGroupPropagationStatusRequest {
                    network_security_group_ids: Some(rpc::NetworkSecurityGroupIdList {
                        ids: vec![id],
                    }),
                    vpc_ids: vpc_ids.unwrap_or_default(),
                    instance_ids: instance_ids.unwrap_or_default(),
                },
            )
            .await?;

        Ok((nsg.vpcs, nsg.instances))
    }

    pub async fn get_all_network_security_groups(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<Vec<rpc::NetworkSecurityGroup>> {
        let all_nsg_ids = self
            .0
            .find_network_security_group_ids(rpc::FindNetworkSecurityGroupIdsRequest {
                name: None,
                tenant_organization_id: None,
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .network_security_group_ids;

        let mut all_nsgs = Vec::with_capacity(all_nsg_ids.len());

        for nsg_ids in all_nsg_ids.chunks(page_size) {
            let nsgs = self
                .0
                .find_network_security_groups_by_ids(FindNetworkSecurityGroupsByIdsRequest {
                    tenant_organization_id: None,
                    network_security_group_ids: nsg_ids.to_vec(),
                })
                .await
                .map_err(CarbideCliError::ApiInvocationError)?
                .network_security_groups;
            all_nsgs.extend(nsgs);
        }

        Ok(all_nsgs)
    }

    pub async fn update_network_security_group(
        &self,
        id: String,
        tenant_organization_id: String,
        metadata: rpc::Metadata,
        if_version_match: Option<String>,
        rules: Vec<rpc::NetworkSecurityGroupRuleAttributes>,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroup> {
        let request = UpdateNetworkSecurityGroupRequest {
            id,
            tenant_organization_id,
            metadata: Some(metadata),
            if_version_match,
            network_security_group_attributes: Some(NetworkSecurityGroupAttributes { rules }),
        };

        let response = self.0.update_network_security_group(request).await?;

        response
            .network_security_group
            .ok_or(CarbideCliError::Empty)
    }

    pub async fn delete_network_security_group(
        &self,
        id: String,
        tenant_organization_id: String,
    ) -> CarbideCliResult<()> {
        self.0
            .delete_network_security_group(DeleteNetworkSecurityGroupRequest {
                id,
                tenant_organization_id,
            })
            .await?;

        Ok(())
    }

    // TODO: add other hardware info
    pub async fn update_machine_hardware_info(
        &self,
        id: String,
        hardware_info_update_type: MachineHardwareInfoUpdateType,
        gpus: Vec<::rpc::machine_discovery::Gpu>,
    ) -> CarbideCliResult<()> {
        let hardware_info = MachineHardwareInfo { gpus };
        self.0
            .update_machine_hardware_info(UpdateMachineHardwareInfoRequest {
                machine_id: Some(::rpc::common::MachineId { id }),
                info: Some(hardware_info),
                update_type: hardware_info_update_type as i32,
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_instance_types(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<Vec<rpc::InstanceType>> {
        let all_ids = self
            .0
            .find_instance_type_ids()
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .instance_type_ids;

        let mut all_itypes = Vec::with_capacity(all_ids.len());

        for ids in all_ids.chunks(page_size) {
            let itypes = self
                .0
                .find_instance_types_by_ids(FindInstanceTypesByIdsRequest {
                    instance_type_ids: ids.to_vec(),
                })
                .await
                .map_err(CarbideCliError::ApiInvocationError)?
                .instance_types;
            all_itypes.extend(itypes);
        }

        Ok(all_itypes)
    }

    pub async fn create_instance_type_association(
        &self,
        instance_type_id: String,
        machine_ids: Vec<String>,
    ) -> CarbideCliResult<()> {
        self.0
            .associate_machines_with_instance_type(rpc::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id,
                machine_ids,
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn remove_instance_type_association(
        &self,
        machine_id: String,
    ) -> CarbideCliResult<()> {
        self.0
            .remove_machine_instance_type_association(
                rpc::RemoveMachineInstanceTypeAssociationRequest { machine_id },
            )
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn get_power_options(
        &self,
        machine_id: Vec<String>,
    ) -> CarbideCliResult<Vec<rpc::PowerOptions>> {
        let all_options = self
            .0
            .get_power_options(rpc::PowerOptionRequest {
                machine_id: machine_id
                    .into_iter()
                    .map(|x| ::rpc::common::MachineId { id: x })
                    .collect::<Vec<::rpc::common::MachineId>>(),
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .response;

        Ok(all_options)
    }

    pub async fn update_power_options(
        &self,
        machine_id: String,
        power_state: PowerState,
    ) -> CarbideCliResult<Vec<rpc::PowerOptions>> {
        let power_options = self
            .0
            .update_power_option(rpc::PowerOptionUpdateRequest {
                machine_id: Some(::rpc::common::MachineId { id: machine_id }),
                power_state: power_state as i32,
            })
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .response;

        Ok(power_options)
    }

    pub async fn create_bmc_user(
        &self,
        ip_address: Option<String>,
        mac_address: Option<MacAddress>,
        machine_id: Option<String>,
        create_username: String,
        create_password: String,
        create_role_id: Option<String>,
    ) -> CarbideCliResult<rpc::CreateBmcUserResponse> {
        let bmc_endpoint_request = if ip_address.is_some() || mac_address.is_some() {
            Some(rpc::BmcEndpointRequest {
                ip_address: ip_address.unwrap_or_default(),
                mac_address: mac_address.map(|mac| mac.to_string()),
            })
        } else {
            None
        };

        let request = rpc::CreateBmcUserRequest {
            bmc_endpoint_request,
            machine_id,
            create_username,
            create_password,
            create_role_id,
        };
        self.0
            .create_bmc_user(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn delete_bmc_user(
        &self,
        ip_address: Option<String>,
        mac_address: Option<MacAddress>,
        machine_id: Option<String>,
        delete_username: String,
    ) -> CarbideCliResult<rpc::DeleteBmcUserResponse> {
        let bmc_endpoint_request = if ip_address.is_some() || mac_address.is_some() {
            Some(rpc::BmcEndpointRequest {
                ip_address: ip_address.unwrap_or_default(),
                mac_address: mac_address.map(|mac| mac.to_string()),
            })
        } else {
            None
        };

        let request = rpc::DeleteBmcUserRequest {
            bmc_endpoint_request,
            machine_id,
            delete_username,
        };
        self.0
            .delete_bmc_user(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }
}
