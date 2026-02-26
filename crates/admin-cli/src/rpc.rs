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

use std::collections::HashMap;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::instance_interface_config::NetworkDetails;
use ::rpc::forge::{
    self as rpc, BmcEndpointRequest, CreateNetworkSecurityGroupRequest,
    FindInstanceTypesByIdsRequest, FindNetworkSecurityGroupsByIdsRequest, GetDpfStateRequest,
    GetNetworkSecurityGroupAttachmentsRequest, GetNetworkSecurityGroupPropagationStatusRequest,
    IdentifySerialRequest, MachineHardwareInfo, MachineHardwareInfoUpdateType,
    ModifyDpfStateRequest, NetworkPrefix, NetworkSecurityGroupAttributes,
    NetworkSegmentCreationRequest, NetworkSegmentType, Remediation, RemediationIdList,
    RemediationList, UpdateMachineHardwareInfoRequest, UpdateNetworkSecurityGroupRequest,
    VpcCreationRequest, VpcSearchFilter, VpcVirtualizationType, VpcsByIdsRequest,
};
use ::rpc::forge_api_client::ForgeApiClient;
use ::rpc::{Machine, NetworkSegment};
use carbide_uuid::dpa_interface::DpaInterfaceId;
use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::nvlink::{NvLinkLogicalPartitionId, NvLinkPartitionId};
use carbide_uuid::rack::RackId;
use carbide_uuid::vpc::VpcId;
use mac_address::MacAddress;

use crate::IntoOnlyOne;
use crate::expected_machines::common::ExpectedMachineJson;
use crate::instance::AllocateInstance;
use crate::machine::MachineAutoupdate;

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
    pub async fn get_machine(&self, id: MachineId) -> CarbideCliResult<rpc::Machine> {
        let mut machines = self
            .0
            .find_machines_by_ids(::rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![id],
                include_history: true,
            })
            .await?;

        if machines.machines.is_empty() {
            return Err(CarbideCliError::MachineNotFound(id));
        }

        let mut machine_details = machines.machines.remove(0);

        // Note: The field going forward is `associated_dpu_machine_ids`, but if we're talking to
        // an older version of the API which doesn't support it, fall back on building our own Vec
        // out of the `associated_dpu_machine_id` field.
        if machine_details.associated_dpu_machine_ids.is_empty()
            && let Some(ref dpu_id) = machine_details.associated_dpu_machine_id
        {
            machine_details.associated_dpu_machine_ids = vec![*dpu_id];
        }

        Ok(machine_details)
    }

    pub async fn get_all_machines(
        &self,
        request: rpc::MachineSearchConfig,
        page_size: usize,
    ) -> CarbideCliResult<rpc::MachineList> {
        let all_machine_ids = self.0.find_machine_ids(request).await?;
        let mut all_machines = rpc::MachineList {
            machines: Vec::with_capacity(all_machine_ids.machine_ids.len()),
        };

        for machine_ids in all_machine_ids.machine_ids.chunks(page_size) {
            let machines = self.get_machines_by_ids(machine_ids).await?;
            all_machines.machines.extend(machines.machines);
        }

        Ok(all_machines)
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
    ) -> CarbideCliResult<MachineId> {
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
                tenant_org_id,
                vpc_id,
                label_key,
                label_value,
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
        instance_id: InstanceId,
    ) -> CarbideCliResult<rpc::InstanceList> {
        let instances = self.0.find_instances_by_ids(vec![instance_id]).await?;

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
        Ok(self.0.find_instance_ids(request).await?)
    }

    pub async fn get_all_segments(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let all_ids = self.get_segment_ids(tenant_org_id, name).await?;
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
        segment_id: NetworkSegmentId,
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let segments = self.get_segments_by_ids(&[segment_id]).await?;

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
        Ok(self.0.find_network_segment_ids(request).await?)
    }

    pub async fn get_segments_by_ids(
        &self,
        network_segments_ids: &[NetworkSegmentId],
    ) -> CarbideCliResult<rpc::NetworkSegmentList> {
        let request = rpc::NetworkSegmentsByIdsRequest {
            network_segments_ids: network_segments_ids.to_vec(),
            include_history: network_segments_ids.len() == 1, // only request it when getting data for single resource
            include_num_free_ips: true,
        };
        Ok(self.0.find_network_segments_by_ids(request).await?)
    }

    pub async fn get_domains(
        &self,
        id: Option<::carbide_uuid::domain::DomainId>,
    ) -> CarbideCliResult<::rpc::protos::dns::DomainList> {
        let request = ::rpc::protos::dns::DomainSearchQuery { id, name: None };
        Ok(self.0.find_domain(request).await?)
    }

    pub async fn machine_insert_health_report_override(
        &self,
        id: MachineId,
        report: ::rpc::health::HealthReport,
        replace: bool,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::InsertHealthReportOverrideRequest {
            machine_id: Some(id),
            r#override: Some(rpc::HealthReportOverride {
                report: Some(report),
                mode: if replace {
                    rpc::OverrideMode::Replace
                } else {
                    rpc::OverrideMode::Merge
                } as i32,
            }),
        };
        Ok(self.0.insert_health_report_override(request).await?)
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
        Ok(self.0.admin_bmc_reset(request).await?)
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
        Ok(self.0.admin_power_control(request).await?)
    }

    pub async fn get_all_machines_interfaces(
        &self,
        id: Option<MachineInterfaceId>,
    ) -> CarbideCliResult<rpc::InterfaceList> {
        let request = rpc::InterfaceSearchQuery { id, ip: None };
        Ok(self.0.find_interfaces(request).await?)
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
            endpoint_ids: endpoint_ids.to_vec(),
        };
        Ok(self.0.find_explored_endpoints_by_ids(request).await?)
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

    pub async fn get_machines_by_ids(
        &self,
        machine_ids: &[MachineId],
    ) -> CarbideCliResult<rpc::MachineList> {
        let request = ::rpc::forge::MachinesByIdsRequest {
            machine_ids: Vec::from(machine_ids),
            ..Default::default()
        };
        Ok(self.0.find_machines_by_ids(request).await?)
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
        Ok(self.0.set_dynamic_config(request).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn patch_expected_machine(
        &self,
        bmc_mac_address: MacAddress,
        bmc_username: Option<String>,
        bmc_password: Option<String>,
        chassis_serial_number: Option<String>,
        fallback_dpu_serial_numbers: Option<Vec<String>>,
        meta_name: Option<String>,
        meta_description: Option<String>,
        labels: Option<Vec<String>>,
        sku_id: Option<String>,
        rack_id: Option<RackId>,
        default_pause_ingestion_and_poweron: Option<bool>,
        dpf_enabled: bool,
    ) -> Result<(), CarbideCliError> {
        let expected_machine = self
            .0
            .get_expected_machine(::rpc::forge::ExpectedMachineRequest {
                bmc_mac_address: bmc_mac_address.to_string(),
                id: None,
            })
            .await?;

        // Merge metadata fields individually
        let merged_metadata =
            if meta_name.is_some() || meta_description.is_some() || labels.is_some() {
                let existing = expected_machine.metadata.unwrap_or_default();

                // Convert labels to the proto format
                let merged_labels = if let Some(label_list) = labels {
                    let mut proto_labels = Vec::new();
                    for label in label_list {
                        let proto_label = match label.split_once(':') {
                            Some((k, v)) => ::rpc::forge::Label {
                                key: k.trim().to_string(),
                                value: Some(v.trim().to_string()),
                            },
                            None => ::rpc::forge::Label {
                                key: label.trim().to_string(),
                                value: None,
                            },
                        };
                        proto_labels.push(proto_label);
                    }
                    proto_labels
                } else {
                    existing.labels
                };

                Some(::rpc::forge::Metadata {
                    name: meta_name.unwrap_or(existing.name),
                    description: meta_description.unwrap_or(existing.description),
                    labels: merged_labels,
                })
            } else {
                expected_machine.metadata
            };

        let request = rpc::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: bmc_username.unwrap_or(expected_machine.bmc_username),
            bmc_password: bmc_password.unwrap_or(expected_machine.bmc_password),
            chassis_serial_number: chassis_serial_number
                .unwrap_or(expected_machine.chassis_serial_number),
            fallback_dpu_serial_numbers: fallback_dpu_serial_numbers
                .unwrap_or(expected_machine.fallback_dpu_serial_numbers),
            metadata: merged_metadata,
            sku_id,
            id: expected_machine.id,
            // TODO(chet): Add support for patching host_nics at some point.
            host_nics: expected_machine.host_nics,
            rack_id: rack_id.or(expected_machine.rack_id),
            default_pause_ingestion_and_poweron,
            dpf_enabled,
        };

        Ok(self.0.update_expected_machine(request).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_expected_power_shelf(
        &self,
        bmc_mac_address: MacAddress,
        bmc_username: Option<String>,
        bmc_password: Option<String>,
        shelf_serial_number: Option<String>,
        rack_id: Option<RackId>,
        ip_address: Option<String>,
        metadata: ::rpc::forge::Metadata,
    ) -> Result<(), CarbideCliError> {
        let expected_power_shelf = self
            .0
            .get_expected_power_shelf(bmc_mac_address.to_string())
            .await?;
        let request = rpc::ExpectedPowerShelf {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: bmc_username.unwrap_or(expected_power_shelf.bmc_username),
            bmc_password: bmc_password.unwrap_or(expected_power_shelf.bmc_password),
            shelf_serial_number: shelf_serial_number
                .unwrap_or(expected_power_shelf.shelf_serial_number),
            metadata: Some(metadata),
            ip_address: ip_address.unwrap_or(expected_power_shelf.ip_address),
            rack_id,
        };

        self.0
            .update_expected_power_shelf(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_expected_switch(
        &self,
        bmc_mac_address: MacAddress,
        bmc_username: Option<String>,
        bmc_password: Option<String>,
        switch_serial_number: Option<String>,
        rack_id: Option<RackId>,
        nvos_username: Option<String>,
        nvos_password: Option<String>,
        metadata: ::rpc::forge::Metadata,
    ) -> Result<(), CarbideCliError> {
        let expected_switch = self
            .0
            .get_expected_switch(bmc_mac_address.to_string())
            .await?;
        let request = rpc::ExpectedSwitch {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: bmc_username.unwrap_or(expected_switch.bmc_username),
            bmc_password: bmc_password.unwrap_or(expected_switch.bmc_password),
            switch_serial_number: switch_serial_number
                .unwrap_or(expected_switch.switch_serial_number),
            metadata: Some(metadata),
            rack_id,
            nvos_username: nvos_username.or(expected_switch.nvos_username),
            nvos_password: nvos_password.or(expected_switch.nvos_password),
        };

        self.0
            .update_expected_switch(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn replace_all_expected_machines(
        &self,
        expected_machine_list: Vec<ExpectedMachineJson>,
    ) -> Result<(), CarbideCliError> {
        let request = rpc::ExpectedMachineList {
            expected_machines: expected_machine_list
                .into_iter()
                .map(|machine| rpc::ExpectedMachine {
                    id: machine.id.map(|s| ::rpc::common::Uuid { value: s }),
                    bmc_mac_address: machine.bmc_mac_address.to_string(),
                    bmc_username: machine.bmc_username,
                    bmc_password: machine.bmc_password,
                    chassis_serial_number: machine.chassis_serial_number,
                    fallback_dpu_serial_numbers: machine
                        .fallback_dpu_serial_numbers
                        .unwrap_or_default(),
                    metadata: machine.metadata,
                    sku_id: machine.sku_id,
                    host_nics: machine.host_nics,
                    rack_id: machine.rack_id,
                    default_pause_ingestion_and_poweron: machine
                        .default_pause_ingestion_and_poweron,
                    dpf_enabled: machine.dpf_enabled,
                })
                .collect(),
        };

        Ok(self.0.replace_all_expected_machines(request).await?)
    }

    pub async fn replace_all_expected_power_shelves(
        &self,
        expected_power_shelf_list: Vec<crate::expected_power_shelf::common::ExpectedPowerShelfJson>,
    ) -> Result<(), CarbideCliError> {
        let request = rpc::ExpectedPowerShelfList {
            expected_power_shelves: expected_power_shelf_list
                .into_iter()
                .map(|power_shelf| rpc::ExpectedPowerShelf {
                    bmc_mac_address: power_shelf.bmc_mac_address.to_string(),
                    bmc_username: power_shelf.bmc_username,
                    bmc_password: power_shelf.bmc_password,
                    shelf_serial_number: power_shelf.shelf_serial_number,
                    ip_address: power_shelf.ip_address.unwrap_or_default(),
                    metadata: power_shelf.metadata,
                    rack_id: power_shelf.rack_id,
                })
                .collect(),
        };
        self.0
            .replace_all_expected_power_shelves(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn replace_all_expected_switches(
        &self,
        expected_switch_list: Vec<crate::expected_switch::common::ExpectedSwitchJson>,
    ) -> Result<(), CarbideCliError> {
        let request = rpc::ExpectedSwitchList {
            expected_switches: expected_switch_list
                .into_iter()
                .map(|switch| rpc::ExpectedSwitch {
                    bmc_mac_address: switch.bmc_mac_address.to_string(),
                    bmc_username: switch.bmc_username,
                    bmc_password: switch.bmc_password,
                    switch_serial_number: switch.switch_serial_number,
                    nvos_username: switch.nvos_username,
                    nvos_password: switch.nvos_password,
                    metadata: switch.metadata,
                    rack_id: switch.rack_id,
                })
                .collect(),
        };
        self.0
            .replace_all_expected_switches(request)
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
            .get_vpc_ids(tenant_org_id, name, label_key, label_value)
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

    // Get all the DPA interfaces and return the vector of DPA interfaces
    pub async fn get_all_dpas(&self, page_size: usize) -> CarbideCliResult<rpc::DpaInterfaceList> {
        let all_ids = self.get_dpa_ids().await?;
        let mut all_list = rpc::DpaInterfaceList {
            interfaces: Vec::with_capacity(all_ids.ids.len()),
        };

        let include_history = all_ids.ids.len() == 1;

        for ids in all_ids.ids.chunks(page_size) {
            let request = rpc::DpaInterfacesByIdsRequest {
                ids: ids.to_vec(),
                include_history,
            };

            let list = self.0.find_dpa_interfaces_by_ids(request).await?;
            all_list.interfaces.extend(list.interfaces);
        }

        Ok(all_list)
    }

    // Given an DPA interface ID, fetch it from Carbide and return it
    pub async fn get_one_dpa(
        &self,
        dpa_id: DpaInterfaceId,
    ) -> CarbideCliResult<rpc::DpaInterfaceList> {
        let request = rpc::DpaInterfacesByIdsRequest {
            ids: vec![dpa_id],
            include_history: true,
        };

        Ok(self.0.find_dpa_interfaces_by_ids(request).await?)
    }

    pub async fn get_vpc_by_name(&self, name: &str) -> CarbideCliResult<rpc::VpcList> {
        let vpc_ids = self
            .0
            .find_vpc_ids(VpcSearchFilter {
                label: None,
                tenant_org_id: None,
                name: Some(name.to_string()),
            })
            .await?
            .vpc_ids;

        Ok(if vpc_ids.is_empty() {
            rpc::VpcList { vpcs: vec![] }
        } else {
            self.0
                .find_vpcs_by_ids(VpcsByIdsRequest { vpc_ids })
                .await?
        })
    }

    pub async fn create_vpc(&self, name: &str, vpc_id: VpcId) -> CarbideCliResult<rpc::Vpc> {
        let vpc = match self
            .0
            .create_vpc(VpcCreationRequest {
                name: name.to_string(),
                vni: None,
                routing_profile_type: None,
                tenant_organization_id: "devenv_test_org".to_string(),
                tenant_keyset_id: None,
                network_virtualization_type: Some(
                    VpcVirtualizationType::EthernetVirtualizerWithNvue.into(),
                ),
                id: Some(vpc_id),
                metadata: Some(rpc::Metadata {
                    name: name.to_string(),
                    description: "test vpc".to_string(),
                    labels: vec![],
                }),
                network_security_group_id: None,
                default_nvlink_logical_partition_id: None,
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
        id: NetworkSegmentId,
        vpc_id: Option<VpcId>,
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
                free_ip_count: 1,
                svi_ip: None,
            }],
            segment_type: NetworkSegmentType::Tenant as i32,
            id: Some(id),
        };
        Ok(self.0.create_network_segment(request).await?)
    }

    // Fetch from Carbide and return a vector of Dpa interface IDs
    async fn get_dpa_ids(&self) -> CarbideCliResult<rpc::DpaInterfaceIdList> {
        Ok(self.0.get_all_dpa_interface_ids().await?)
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
        Ok(self.0.find_vpc_ids(request).await?)
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
            network_virtualization_type: Some(virtualizer.into()),
        };
        self.0.update_vpc_virtualization(request).await?;

        Ok(())
    }

    pub async fn get_all_ib_partitions(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let all_ids = self.get_ib_partition_ids(tenant_org_id, name).await?;
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
        ib_partition_id: IBPartitionId,
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let partitions = self.get_ib_partitions_by_ids(&[ib_partition_id]).await?;

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
        Ok(self.0.find_ib_partition_ids(request).await?)
    }

    async fn get_ib_partitions_by_ids(
        &self,
        ids: &[IBPartitionId],
    ) -> CarbideCliResult<rpc::IbPartitionList> {
        let request = rpc::IbPartitionsByIdsRequest {
            ib_partition_ids: Vec::from(ids),
            include_history: ids.len() == 1,
        };
        Ok(self.0.find_ib_partitions_by_ids(request).await?)
    }

    pub async fn get_all_keysets(
        &self,
        tenant_org_id: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::TenantKeySetList> {
        let all_ids = self.get_keyset_ids(tenant_org_id).await?;
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
        let keysets = self
            .get_keysets_by_ids(std::slice::from_ref(&keyset_id))
            .await?;

        Ok(keysets)
    }

    async fn get_keyset_ids(
        &self,
        tenant_org_id: Option<String>,
    ) -> CarbideCliResult<rpc::TenantKeysetIdList> {
        let request = rpc::TenantKeysetSearchFilter { tenant_org_id };
        Ok(self.0.find_tenant_keyset_ids(request).await?)
    }

    async fn get_keysets_by_ids(
        &self,
        identifiers: &[rpc::TenantKeysetIdentifier],
    ) -> CarbideCliResult<rpc::TenantKeySetList> {
        let request = rpc::TenantKeysetsByIdsRequest {
            keyset_ids: Vec::from(identifiers),
            include_key_data: true,
        };
        Ok(self.0.find_tenant_keysets_by_ids(request).await?)
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
            machine_id: Some(req.machine),
            action: action.into(),
        };
        Ok(self.0.machine_set_auto_update(request).await?)
    }

    async fn get_subnet_ids_for_names(
        &self,
        subnets: &Vec<String>,
    ) -> CarbideCliResult<Vec<NetworkSegmentId>> {
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

    /// Build an InstanceAllocationRequest from CLI args and machine info.
    pub async fn build_instance_request(
        &self,
        machine: Machine,
        allocate_instance: &AllocateInstance,
        instance_name: &str,
        modified_by: Option<String>,
    ) -> CarbideCliResult<rpc::InstanceAllocationRequest> {
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
                    "no interface information for machine: {}",
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
                    .map(|pci| pci.device.as_str());

                let Some(device) = device else {
                    continue;
                };

                let device_instance = *next_device_instance
                    .entry(device)
                    .and_modify(|i| *i += 1)
                    .or_insert(0) as u32;

                interface_config.push(rpc::InstanceInterfaceConfig {
                    function_type: rpc::InterfaceFunctionType::Physical as i32,
                    network_segment_id: Some(network_segment_id), // to support legacy.
                    network_details: Some(NetworkDetails::SegmentId(network_segment_id)),
                    device: Some(device.to_string()),
                    device_instance,
                    virtual_function_id: None,
                });

                if let Some(vf_network_segment_chunks) = vf_chunk_iter.next() {
                    for vf_network_segment_id in vf_network_segment_chunks {
                        interface_config.push(rpc::InstanceInterfaceConfig {
                            function_type: rpc::InterfaceFunctionType::Virtual as i32,
                            network_segment_id: Some(*vf_network_segment_id), // to support legacy.
                            network_details: Some(NetworkDetails::SegmentId(
                                *vf_network_segment_id,
                            )),
                            device: Some(device.to_string()),
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
                    .as_deref()
                    .unwrap_or("Forge-simulation-tenant"),
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
                        .entry(pci_properties.device.as_str())
                        .and_modify(|c| *c += 1)
                        .or_insert(0u32);

                    let new_interface = rpc::InstanceInterfaceConfig {
                        function_type: rpc::InterfaceFunctionType::Physical as i32,
                        network_segment_id: None,
                        network_details: Some(NetworkDetails::VpcPrefixId(*vpc_prefix_id)),
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
                                network_details: Some(NetworkDetails::VpcPrefixId(
                                    *vf_vpc_prefix_id,
                                )),
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
                allocate_instance.tenant_org.as_deref().ok_or_else(|| {
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
            tenant_organization_id: tenant_org.to_string(),
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
            dpu_extension_services: None,
            nvlink: None,
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
            machine_id: machine.id,

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
        Ok(instance_request)
    }

    pub async fn allocate_instance(
        &self,
        machine: Machine,
        allocate_instance: &AllocateInstance,
        instance_name: &str,
        modified_by: Option<String>,
    ) -> CarbideCliResult<rpc::Instance> {
        let request = self
            .build_instance_request(machine, allocate_instance, instance_name, modified_by)
            .await?;
        Ok(self.0.allocate_instance(request).await?)
    }

    /// Batch allocate instances (all-or-nothing).
    pub async fn allocate_instances(
        &self,
        requests: Vec<rpc::InstanceAllocationRequest>,
    ) -> CarbideCliResult<Vec<rpc::Instance>> {
        let response = self
            .0
            .allocate_instances(rpc::BatchInstanceAllocationRequest {
                instance_requests: requests,
            })
            .await?;
        Ok(response.instances)
    }

    /// Applies patches to a running instances configuration
    /// The function fetches the current configuration, and then calls the two
    /// `modify` closures to apply updates to the configuration.
    /// It then calls the `UpdateInstanceConfig` API to submit the updates
    /// to carbide.
    pub async fn update_instance_config_with(
        &self,
        instance_id: InstanceId,
        modify_config: impl FnOnce(&mut rpc::InstanceConfig),
        modify_metadata: impl FnOnce(&mut rpc::Metadata),
        modified_by: Option<String>,
    ) -> CarbideCliResult<rpc::Instance> {
        let find_response = self.0.find_instances_by_ids(vec![instance_id]).await?;

        let instance = find_response
            .instances
            .into_iter()
            .next()
            .ok_or_else(|| CarbideCliError::InstanceNotFound(instance_id))?;

        let config = instance.config.map(|mut c| {
            modify_config(&mut c);
            c
        });

        tracing::info!("{}", serde_json::to_string(&config).unwrap_or_default());

        let metadata = instance.metadata.map(|mut m| {
            modify_metadata(&mut m);

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
            instance_id: Some(instance_id),
            if_version_match: Some(instance.config_version),
            config,
            metadata,
        };
        Ok(self
            .0
            .update_instance_config(update_instance_request)
            .await?)
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
        Ok(self
            .0
            .add_update_machine_validation_external_config(request)
            .await?)
    }

    pub async fn get_machine_validation_results(
        &self,
        machine_id: Option<MachineId>,
        history: bool,
        arg_validation_id: Option<String>,
    ) -> CarbideCliResult<rpc::MachineValidationResultList> {
        let mut validation_id: Option<::rpc::common::Uuid> = None;
        if let Some(value) = arg_validation_id {
            validation_id = Some(::rpc::common::Uuid { value })
        }
        let request = rpc::MachineValidationGetRequest {
            machine_id,
            include_history: history,
            validation_id,
        };
        Ok(self.0.get_machine_validation_results(request).await?)
    }

    pub async fn get_machine_validation_runs(
        &self,
        machine_id: Option<MachineId>,
        include_history: bool,
    ) -> CarbideCliResult<rpc::MachineValidationRunList> {
        let request = rpc::MachineValidationRunListGetRequest {
            machine_id,
            include_history,
        };
        Ok(self.0.get_machine_validation_runs(request).await?)
    }

    pub async fn on_demand_machine_validation(
        &self,
        machine_id: MachineId,
        tags: Option<Vec<String>>,
        allowed_tests: Option<Vec<String>>,
        run_unverfied_tests: bool,
        contexts: Option<Vec<String>>,
    ) -> CarbideCliResult<rpc::MachineValidationOnDemandResponse> {
        let request = rpc::MachineValidationOnDemandRequest {
            machine_id: Some(machine_id),
            tags: tags.unwrap_or_default(),
            allowed_tests: allowed_tests.unwrap_or_default(),
            action: rpc::machine_validation_on_demand_request::Action::Start.into(),
            run_unverfied_tests,
            contexts: contexts.unwrap_or_default(),
        };
        Ok(self.0.on_demand_machine_validation(request).await?)
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

    pub async fn update_os_image(
        &self,
        id: ::rpc::common::Uuid,
        auth_type: Option<String>,
        auth_token: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> CarbideCliResult<rpc::OsImage> {
        let os_image = self.0.get_os_image(id).await?;
        let Some(mut new_attrs) = os_image.attributes else {
            return Err(CarbideCliError::Empty);
        };
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
        Ok(self.0.update_os_image(new_attrs).await?)
    }

    pub async fn update_instance_config(
        &self,
        instance_id: InstanceId,
        version: String,
        config: rpc::InstanceConfig,
        metadata: Option<rpc::Metadata>,
    ) -> CarbideCliResult<rpc::Instance> {
        let request = rpc::InstanceConfigUpdateRequest {
            instance_id: Some(instance_id),
            if_version_match: Some(version),
            config: Some(config),
            metadata,
        };
        Ok(self.0.update_instance_config(request).await?)
    }

    pub async fn update_vpc_config(
        &self,
        vpc_id: VpcId,
        version: String,
        name: String,
        metadata: Option<rpc::Metadata>,
        network_security_group_id: Option<String>,
    ) -> CarbideCliResult<rpc::Vpc> {
        let request = rpc::VpcUpdateRequest {
            name,
            id: Some(vpc_id),
            if_version_match: Some(version),
            metadata,
            network_security_group_id,
            default_nvlink_logical_partition_id: None,
        };
        self.0
            .update_vpc(request)
            .await?
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
        Ok(self.0.get_machine_validation_tests(request).await?)
    }

    pub async fn update_machine_metadata(
        &self,
        machine_id: MachineId,
        metadata: ::rpc::forge::Metadata,
        current_version: String,
    ) -> CarbideCliResult<()> {
        let request = ::rpc::forge::MachineMetadataUpdateRequest {
            machine_id: Some(machine_id),
            if_version_match: Some(current_version),
            metadata: Some(metadata),
        };
        Ok(self.0.update_machine_metadata(request).await?)
    }

    pub async fn create_network_security_group(
        &self,
        id: Option<String>,
        tenant_organization_id: String,
        metadata: rpc::Metadata,
        stateful_egress: bool,
        rules: Vec<rpc::NetworkSecurityGroupRuleAttributes>,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroup> {
        let request = CreateNetworkSecurityGroupRequest {
            id,
            tenant_organization_id,
            metadata: Some(metadata),
            network_security_group_attributes: Some(NetworkSecurityGroupAttributes {
                stateful_egress,
                rules,
            }),
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
            .await?
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
            .await?
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
            .await?
            .network_security_group_ids;

        let mut all_nsgs = Vec::with_capacity(all_nsg_ids.len());

        for nsg_ids in all_nsg_ids.chunks(page_size) {
            let nsgs = self
                .0
                .find_network_security_groups_by_ids(FindNetworkSecurityGroupsByIdsRequest {
                    tenant_organization_id: None,
                    network_security_group_ids: nsg_ids.to_vec(),
                })
                .await?
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
        stateful_egress: bool,
        rules: Vec<rpc::NetworkSecurityGroupRuleAttributes>,
    ) -> CarbideCliResult<rpc::NetworkSecurityGroup> {
        let request = UpdateNetworkSecurityGroupRequest {
            id,
            tenant_organization_id,
            metadata: Some(metadata),
            if_version_match,
            network_security_group_attributes: Some(NetworkSecurityGroupAttributes {
                stateful_egress,
                rules,
            }),
        };

        let response = self.0.update_network_security_group(request).await?;

        response
            .network_security_group
            .ok_or(CarbideCliError::Empty)
    }

    // TODO: add other hardware info
    pub async fn update_machine_hardware_info(
        &self,
        id: MachineId,
        hardware_info_update_type: MachineHardwareInfoUpdateType,
        gpus: Vec<::rpc::machine_discovery::Gpu>,
    ) -> CarbideCliResult<()> {
        let hardware_info = MachineHardwareInfo { gpus };
        Ok(self
            .0
            .update_machine_hardware_info(UpdateMachineHardwareInfoRequest {
                machine_id: Some(id),
                info: Some(hardware_info),
                update_type: hardware_info_update_type as i32,
            })
            .await?)
    }

    pub async fn update_machine_nvlink_info(
        &self,
        machine_id: MachineId,
        nvlink_info: rpc::MachineNvLinkInfo,
    ) -> CarbideCliResult<()> {
        Ok(self
            .0
            .update_machine_nv_link_info(rpc::UpdateMachineNvLinkInfoRequest {
                machine_id: Some(machine_id),
                nvlink_info: Some(nvlink_info),
            })
            .await?)
    }

    pub async fn get_all_instance_types(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<Vec<rpc::InstanceType>> {
        let all_ids = self.0.find_instance_type_ids().await?.instance_type_ids;

        let mut all_itypes = Vec::with_capacity(all_ids.len());

        for ids in all_ids.chunks(page_size) {
            let itypes = self
                .0
                .find_instance_types_by_ids(FindInstanceTypesByIdsRequest {
                    instance_type_ids: ids.to_vec(),
                })
                .await?
                .instance_types;
            all_itypes.extend(itypes);
        }

        Ok(all_itypes)
    }

    pub async fn get_power_options(
        &self,
        machine_id: Vec<MachineId>,
    ) -> CarbideCliResult<Vec<rpc::PowerOptions>> {
        let all_options = self
            .0
            .get_power_options(rpc::PowerOptionRequest { machine_id })
            .await?
            .response;

        Ok(all_options)
    }

    pub async fn get_all_nv_link_partitions(
        &self,
        tenant_org_id: Option<String>,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::NvLinkPartitionList> {
        let all_ids = self.get_nv_link_partition_ids(tenant_org_id, name).await?;
        let mut all_list = rpc::NvLinkPartitionList {
            partitions: Vec::with_capacity(all_ids.partition_ids.len()),
        };

        for ids in all_ids.partition_ids.chunks(page_size) {
            let list = self.get_nv_link_partitions_by_ids(ids).await?;
            all_list.partitions.extend(list.partitions);
        }

        Ok(all_list)
    }

    pub async fn get_one_nv_link_partition(
        &self,
        nvl_partition_id: NvLinkPartitionId,
    ) -> CarbideCliResult<rpc::NvLinkPartition> {
        let partitions = self
            .get_nv_link_partitions_by_ids(std::slice::from_ref(&nvl_partition_id))
            .await?;

        partitions.partitions.into_only_one_or_else(|_| {
            CarbideCliError::GenericError("Unknown NvLink Partition ID".to_string())
        })
    }

    async fn get_nv_link_partition_ids(
        &self,
        tenant_organization_id: Option<String>,
        name: Option<String>,
    ) -> CarbideCliResult<rpc::NvLinkPartitionIdList> {
        let request = rpc::NvLinkPartitionSearchFilter {
            tenant_organization_id,
            name,
        };
        self.0
            .find_nv_link_partition_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_nv_link_partitions_by_ids(
        &self,
        ids: &[NvLinkPartitionId],
    ) -> CarbideCliResult<rpc::NvLinkPartitionList> {
        let request = rpc::NvLinkPartitionsByIdsRequest {
            partition_ids: Vec::from(ids),
            include_history: ids.len() == 1,
        };
        self.0
            .find_nv_link_partitions_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    pub async fn get_all_logical_partitions(
        &self,
        name: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::NvLinkLogicalPartitionList> {
        let all_ids = self.get_logical_partition_ids(name).await?;
        let mut all_list = rpc::NvLinkLogicalPartitionList {
            partitions: Vec::with_capacity(all_ids.partition_ids.len()),
        };

        for ids in all_ids.partition_ids.chunks(page_size) {
            let list = self.get_logical_partitions_by_ids(ids).await?;
            all_list.partitions.extend(list.partitions);
        }

        Ok(all_list)
    }

    pub async fn get_one_logical_partition(
        &self,
        partition_id: NvLinkLogicalPartitionId,
    ) -> CarbideCliResult<rpc::NvLinkLogicalPartition> {
        let partitions = self
            .get_logical_partitions_by_ids(std::slice::from_ref(&partition_id))
            .await?;

        partitions.partitions.into_only_one_or_else(|len| {
            CarbideCliError::GenericError(format!(
                "Expected a single logical partition found for ID: {partition_id}, found {len}",
            ))
        })
    }

    async fn get_logical_partition_ids(
        &self,
        name: Option<String>,
    ) -> CarbideCliResult<rpc::NvLinkLogicalPartitionIdList> {
        let request = rpc::NvLinkLogicalPartitionSearchFilter { name };
        self.0
            .find_nv_link_logical_partition_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
    }

    async fn get_logical_partitions_by_ids(
        &self,
        ids: &[NvLinkLogicalPartitionId],
    ) -> CarbideCliResult<rpc::NvLinkLogicalPartitionList> {
        let request = rpc::NvLinkLogicalPartitionsByIdsRequest {
            partition_ids: Vec::from(ids),
            include_history: ids.len() == 1,
        };
        self.0
            .find_nv_link_logical_partitions_by_ids(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)
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
        Ok(self.0.create_bmc_user(request).await?)
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
        Ok(self.0.delete_bmc_user(request).await?)
    }

    pub async fn enable_infinite_boot(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: Option<String>,
    ) -> CarbideCliResult<rpc::EnableInfiniteBootResponse> {
        let request = rpc::EnableInfiniteBootRequest {
            bmc_endpoint_request,
            machine_id,
        };
        Ok(self.0.enable_infinite_boot(request).await?)
    }

    pub async fn is_infinite_boot_enabled(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: Option<String>,
    ) -> CarbideCliResult<rpc::IsInfiniteBootEnabledResponse> {
        let request = rpc::IsInfiniteBootEnabledRequest {
            bmc_endpoint_request,
            machine_id,
        };
        Ok(self.0.is_infinite_boot_enabled(request).await?)
    }

    pub async fn lockdown(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: MachineId,
        action: rpc::LockdownAction,
    ) -> CarbideCliResult<rpc::LockdownResponse> {
        let request = rpc::LockdownRequest {
            bmc_endpoint_request,
            machine_id: Some(machine_id),
            action: Some(action as i32),
        };
        Ok(self.0.lockdown(request).await?)
    }

    pub async fn lockdown_status(
        &self,
        bmc_endpoint_request: Option<BmcEndpointRequest>,
        machine_id: MachineId,
    ) -> CarbideCliResult<::rpc::site_explorer::LockdownStatus> {
        let request = rpc::LockdownStatusRequest {
            bmc_endpoint_request,
            machine_id: Some(machine_id),
        };
        Ok(self.0.lockdown_status(request).await?)
    }

    pub async fn get_remediation(
        &self,
        remediation_id: RemediationId,
    ) -> CarbideCliResult<Remediation> {
        let remediation_list = RemediationIdList {
            remediation_ids: vec![remediation_id],
        };

        let response = self.0.find_remediations_by_ids(remediation_list).await?;

        response
            .remediations
            .into_iter()
            .next()
            .ok_or(CarbideCliError::RemediationNotFound(remediation_id))
    }

    pub async fn get_all_remediations(
        &self,
        page_size: usize,
    ) -> CarbideCliResult<RemediationList> {
        let all_remediation_ids = self.0.find_remediation_ids().await?;

        use futures::{StreamExt, TryStreamExt, stream};
        let remediations = stream::iter(all_remediation_ids.remediation_ids.chunks(page_size))
            .then(|remediation_ids| async move {
                self.0
                    .find_remediations_by_ids(remediation_ids)
                    .await
                    .map_err(CarbideCliError::ApiInvocationError)
            })
            .try_fold(vec![], |mut accum, remediations| async move {
                accum.extend(remediations.remediations);
                Ok(accum)
            })
            .await?;
        Ok(RemediationList { remediations })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_extension_service(
        &self,
        service_id: Option<String>,
        service_name: String,
        tenant_organization_id: String,
        service_type: i32,
        description: Option<String>,
        data: String,
        credential: Option<rpc::DpuExtensionServiceCredential>,
        observability: Vec<rpc::DpuExtensionServiceObservabilityConfig>,
    ) -> CarbideCliResult<rpc::DpuExtensionService> {
        let request = rpc::CreateDpuExtensionServiceRequest {
            service_id,
            service_name,
            service_type,
            tenant_organization_id,
            data,
            description,
            credential,
            observability: Some(rpc::DpuExtensionServiceObservability {
                configs: observability,
            }),
        };

        Ok(self.0.create_dpu_extension_service(request).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_extension_service(
        &self,
        service_id: String,
        service_name: Option<String>,
        description: Option<String>,
        data: String,
        credential: Option<rpc::DpuExtensionServiceCredential>,
        observability: Vec<rpc::DpuExtensionServiceObservabilityConfig>,
        if_version_ctr_match: Option<i32>,
    ) -> CarbideCliResult<rpc::DpuExtensionService> {
        let request = rpc::UpdateDpuExtensionServiceRequest {
            service_id,
            service_name,
            description,
            data,
            credential,
            if_version_ctr_match,
            observability: Some(rpc::DpuExtensionServiceObservability {
                configs: observability,
            }),
        };

        Ok(self.0.update_dpu_extension_service(request).await?)
    }

    pub async fn find_extension_services(
        &self,
        service_type: Option<i32>,
        name: Option<String>,
        tenant_organization_id: Option<String>,
        page_size: usize,
    ) -> CarbideCliResult<rpc::DpuExtensionServiceList> {
        let filter = rpc::DpuExtensionServiceSearchFilter {
            service_type,
            name,
            tenant_organization_id,
        };
        let ids_response = self.0.find_dpu_extension_service_ids(filter).await?;

        let mut all_list = rpc::DpuExtensionServiceList {
            services: Vec::with_capacity(ids_response.service_ids.len()),
        };

        for ids in ids_response.service_ids.chunks(page_size) {
            let request = rpc::DpuExtensionServicesByIdsRequest {
                service_ids: ids.to_vec(),
            };
            let list = self.0.find_dpu_extension_services_by_ids(request).await?;
            all_list.services.extend(list.services);
        }

        Ok(all_list)
    }

    pub async fn get_extension_service_by_id(
        &self,
        service_id: String,
    ) -> CarbideCliResult<rpc::DpuExtensionService> {
        let request = rpc::DpuExtensionServicesByIdsRequest {
            service_ids: vec![service_id],
        };

        let service_response = self.0.find_dpu_extension_services_by_ids(request).await?;

        service_response.services.into_only_one_or_else(|len| {
            if len == 0 {
                CarbideCliError::GenericError("Extension service not found".to_string())
            } else {
                CarbideCliError::GenericError(
                    "Multiple extension services found for the same ID".to_string(),
                )
            }
        })
    }

    pub async fn modify_dpf_state(
        &self,
        machine_id: MachineId,
        state: bool,
    ) -> CarbideCliResult<()> {
        let request = ModifyDpfStateRequest {
            machine_id: Some(machine_id),
            dpf_enabled: state,
        };

        Ok(self.0.modify_dpf_state(request).await?)
    }

    pub async fn get_dpf_state(
        &self,
        machine_ids: Vec<MachineId>,
        page_size: usize,
    ) -> CarbideCliResult<Vec<rpc::dpf_state_response::DpfState>> {
        let mut all_dpf_states = Vec::with_capacity(machine_ids.len());

        for machine_ids in machine_ids.chunks(page_size) {
            let request = GetDpfStateRequest {
                machine_ids: machine_ids.to_vec(),
            };
            let dpf_states = self.0.get_dpf_state(request).await?;
            all_dpf_states.extend(dpf_states.dpf_states);
        }

        Ok(all_dpf_states)
    }
}
