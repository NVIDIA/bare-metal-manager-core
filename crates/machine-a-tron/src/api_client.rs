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
use std::sync::atomic::{AtomicU32, Ordering};

use base64::prelude::*;
use bmc_mock::MachineInfo;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use mac_address::MacAddress;
use rpc::forge::instance_operating_system_config::Variant;
use rpc::forge::machine_cleanup_info::CleanupStepResult;
use rpc::forge::{
    ConfigSetting, ExpectedMachine, InlineIpxe, InstanceOperatingSystemConfig,
    MachinesByIdsRequest, PxeInstructions, SetDynamicConfigRequest, VpcVirtualizationType,
};
use rpc::protos::forge_api_client::ForgeApiClient;

use crate::MachineConfig;

#[derive(thiserror::Error, Debug)]
pub enum ClientApiError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Unable to connect to carbide API: {0}")]
    ConnectFailed(String),

    #[error("The API call to the Forge API server returned {0}")]
    InvocationError(#[from] tonic::Status),
}

type ClientApiResult<T> = Result<T, ClientApiError>;

// Simple wrapper around the inputs to discover_machine so that callers can see the field names
pub struct MockDiscoveryData {
    pub machine_interface_id: MachineInterfaceId,
    pub tpm_ek_certificate: Option<Vec<u8>>,
}

static SUBNET_COUNTER: AtomicU32 = AtomicU32::new(0);
static VPC_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone)]
pub struct ApiClient(pub ForgeApiClient);

impl From<ForgeApiClient> for ApiClient {
    fn from(value: ForgeApiClient) -> Self {
        ApiClient(value)
    }
}

pub struct DpuNetworkStatusArgs<'a> {
    pub dpu_machine_id: MachineId,
    pub network_config_version: String,
    pub instance_network_config_version: Option<String>,
    pub instance_config_version: Option<String>,
    pub instance_id: Option<InstanceId>,
    pub interfaces: Vec<rpc::forge::InstanceInterfaceStatusObservation>,
    pub machine_config: &'a MachineConfig,
}

impl ApiClient {
    pub async fn discover_dhcp(
        &self,
        mac_address: MacAddress,
        template_dir: String,
        relay_address: String,
        circuit_id: Option<String>,
    ) -> ClientApiResult<rpc::forge::DhcpRecord> {
        let json_path = format!("{}/{}", &template_dir, "dhcp_discovery.json");
        let dhcp_string = std::fs::read_to_string(&json_path).map_err(|e| {
            ClientApiError::ConfigError(format!("Unable to read {json_path}: {e}",))
        })?;
        let default_data: rpc::forge::DhcpDiscovery =
            serde_json::from_str(&dhcp_string).map_err(|e| {
                ClientApiError::ConfigError(format!(
                    "{template_dir}/dhcp_discovery.json does not have correct format: {e}"
                ))
            })?;

        let dhcp_discovery = rpc::forge::DhcpDiscovery {
            mac_address: mac_address.to_string(),
            circuit_id,
            relay_address,
            ..default_data
        };
        let out = self
            .0
            .discover_dhcp(dhcp_discovery)
            .await
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    }

    pub async fn get_machine_interface(
        &self,
        id: MachineInterfaceId,
    ) -> ClientApiResult<rpc::forge::InterfaceList> {
        let interface_search_query = rpc::forge::InterfaceSearchQuery {
            id: Some(id),
            ip: None,
        };
        let out = self
            .0
            .find_interfaces(interface_search_query)
            .await
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    }

    pub async fn discover_machine(
        &self,
        machine_info: &MachineInfo,
        discovery_data: MockDiscoveryData,
    ) -> ClientApiResult<rpc::forge::MachineDiscoveryResult> {
        let MockDiscoveryData {
            machine_interface_id,
            tpm_ek_certificate,
        } = discovery_data;
        let mut machine_discovery_info = machine_info.discovery_info();
        if matches!(machine_info, MachineInfo::Host(_)) {
            machine_discovery_info.tpm_ek_certificate =
                Some(BASE64_STANDARD.encode(tpm_ek_certificate.ok_or(
                    ClientApiError::ConfigError("No TPM EK certificate waa supplied".to_string()),
                )?))
        }
        let mdi = rpc::forge::MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(rpc::DiscoveryData::Info(machine_discovery_info)),
            create_machine: true,
        };

        let out = self
            .0
            .discover_machine(mdi)
            .await
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    }

    pub async fn get_machines(
        &self,
        machine_ids: Vec<MachineId>,
    ) -> ClientApiResult<Vec<rpc::Machine>> {
        let request = MachinesByIdsRequest {
            machine_ids,
            include_history: false,
        };
        let out = self
            .0
            .find_machines_by_ids(request)
            .await
            .map_err(ClientApiError::InvocationError)?;

        Ok(out.machines)
    }

    pub async fn record_dpu_network_status(
        &self,
        DpuNetworkStatusArgs {
            dpu_machine_id,
            network_config_version,
            instance_network_config_version,
            instance_config_version,
            instance_id,
            interfaces,
            machine_config,
        }: DpuNetworkStatusArgs<'_>,
    ) -> ClientApiResult<()> {
        let dpu_machine_id = Some(dpu_machine_id);

        let dpu_agent_version = machine_config
            .dpu_agent_version
            .clone()
            .or(Some(carbide_version::v!(build_version).to_string()));

        self.0
            .record_dpu_network_status(rpc::forge::DpuNetworkStatus {
                dpu_health: Some(rpc::health::HealthReport {
                    source: "forge-dpu-agent".to_string(),
                    triggered_by: None,
                    observed_at: None,
                    successes: Vec::new(),
                    alerts: Vec::new(),
                }),
                dpu_machine_id,
                observed_at: None,
                network_config_version: Some(network_config_version),
                instance_config_version,
                instance_network_config_version,
                interfaces,
                network_config_error: None,
                instance_id,
                dpu_agent_version,
                client_certificate_expiry_unix_epoch_secs: None,
                fabric_interfaces: vec![],
                last_dhcp_requests: vec![],
                dpu_extension_service_version: None,
                dpu_extension_services: vec![],
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn allocate_instance(
        &self,
        host_machine_id: MachineId,
        network_segment_name: &str,
    ) -> ClientApiResult<rpc::forge::Instance> {
        let segment_request = rpc::forge::NetworkSegmentSearchFilter {
            name: Some(network_segment_name.to_owned()),
            tenant_org_id: None,
        };

        let network_segment_ids = self
            .0
            .find_network_segment_ids(segment_request)
            .await
            .map_err(|e| {
                ClientApiError::ConfigError(format!(
                    "network segment: {network_segment_name} retrieval error {e}"
                ))
            })?;

        if network_segment_ids.network_segments_ids.len() >= 2 {
            tracing::warn!(
                "Network segments from previous runs of machine-a-tron have not been cleaned up. Suggested to start again after cleaning db."
            );
        }
        let Some(network_segment_id) = network_segment_ids.network_segments_ids.into_iter().next()
        else {
            return Err(ClientApiError::ConfigError(format!(
                "network segment: {network_segment_name} not found."
            )));
        };

        let interface_config = rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(network_segment_id),
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                    network_segment_id,
                ),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
        };

        let tenant_config = rpc::TenantConfig {
            tenant_organization_id: "Forge-simulation-tenant".to_string(),
            tenant_keyset_ids: vec![],
            hostname: None,
        };

        let instance_config = rpc::InstanceConfig {
            tenant: Some(tenant_config),
            os: Some(InstanceOperatingSystemConfig {
                variant: Some(Variant::Ipxe(InlineIpxe {
                    ipxe_script: "Non-existing-ipxe".to_string(),
                    user_data: None,
                })),
                user_data: None,
                phone_home_enabled: false,
                run_provisioning_instructions_on_every_boot: false,
            }),
            network: Some(rpc::InstanceNetworkConfig {
                interfaces: vec![interface_config],
            }),
            network_security_group_id: None,
            infiniband: None,
            dpu_extension_services: None,
            nvlink: None,
        };

        let instance_request = rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(host_machine_id),
            //  None here means the allocation will simply inherit the
            // instance_type_id of the machine in the request, whatever it is.
            instance_type_id: None,
            config: Some(instance_config),
            metadata: None,
            allow_unhealthy_machine: false,
        };

        self.0
            .allocate_instance(instance_request)
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn force_delete_machine(
        &self,
        machine_id: String,
    ) -> ClientApiResult<rpc::forge::AdminForceDeleteMachineResponse> {
        self.0
            .admin_force_delete_machine(rpc::forge::AdminForceDeleteMachineRequest {
                host_query: machine_id,
                delete_interfaces: true,
                delete_bmc_interfaces: true,
                delete_bmc_credentials: false,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn create_network_segment(
        &self,
        vpc_name: &String,
        network_virtualization_type: Option<VpcVirtualizationType>,
    ) -> ClientApiResult<rpc::NetworkSegment> {
        let subnet_count = SUBNET_COUNTER.fetch_add(1, Ordering::Acquire);

        let vpc_ids_all = self
            .0
            .find_vpc_ids(rpc::forge::VpcSearchFilter {
                tenant_org_id: None,
                name: Some(vpc_name.clone()),
                label: None,
            })
            .await;

        match vpc_ids_all {
            Ok(vpc_id_list) => {
                match vpc_id_list.vpc_ids.len() {
                    0 => tracing::error!(
                        "There are no VPC ids associated with {}. Should not have happened.",
                        *vpc_name
                    ),
                    1 => {}
                    _ => tracing::warn!(
                        "There are {} VPC ids associated with {}. Should not have happened. Clean up DB and start over.",
                        vpc_id_list.vpc_ids.len(),
                        vpc_name
                    ),
                }

                let is_fnn = network_virtualization_type == Some(VpcVirtualizationType::Fnn);

                let mut prefixes = vec![rpc::forge::NetworkPrefix {
                    id: None,
                    prefix: format!("192.5.{subnet_count}.12/24"),
                    gateway: Some(format!("192.5.{subnet_count}.13")),
                    reserve_first: 1,
                    free_ip_count: 0,
                    svi_ip: None,
                }];

                if is_fnn {
                    prefixes.push(rpc::forge::NetworkPrefix {
                        id: None,
                        prefix: format!("2001:db8:{subnet_count}::/112"),
                        gateway: None,
                        reserve_first: 1,
                        free_ip_count: 0,
                        svi_ip: None,
                    });
                }

                self.0
                    .create_network_segment(rpc::forge::NetworkSegmentCreationRequest {
                        id: None,
                        vpc_id: vpc_id_list.vpc_ids.first().copied(),
                        name: format!("subnet_{subnet_count}"),
                        segment_type: rpc::forge::NetworkSegmentType::Tenant.into(),
                        prefixes,
                        mtu: Some(1500),
                        subdomain_id: None,
                    })
                    .await
                    .map_err(ClientApiError::InvocationError)
            }
            Err(e) => Err(ClientApiError::ConnectFailed(format!(
                "Error {} when finding VPC {}",
                e, *vpc_name
            ))),
        }
    }

    pub async fn create_vpc(
        &self,
        network_virtualization_type: Option<VpcVirtualizationType>,
    ) -> ClientApiResult<rpc::forge::Vpc> {
        let vpc_count = VPC_COUNTER.fetch_add(1, Ordering::Acquire);
        self.0
            .create_vpc(rpc::forge::VpcCreationRequest {
                id: None,
                name: "".to_string(),
                tenant_organization_id: "Forge-simulation-tenant".to_string(),
                tenant_keyset_id: None,
                network_security_group_id: None,
                network_virtualization_type: network_virtualization_type.map(|t| t as i32),
                vni: None,
                routing_profile_type: None,
                metadata: Some(rpc::forge::Metadata {
                    name: format!("vpc_{vpc_count}"),
                    description: "".to_string(),
                    labels: vec![rpc::forge::Label {
                        key: "Forge-simulation-vpc".to_string(),
                        value: Some("Machine-a-tron".to_string()),
                    }],
                }),
                default_nvlink_logical_partition_id: None,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn machine_validation_complete(
        &self,
        machine_id: &MachineId,
        validation_id: rpc::common::Uuid,
    ) -> ClientApiResult<()> {
        self.0
            .machine_validation_completed(rpc::forge::MachineValidationCompletedRequest {
                machine_id: Some(*machine_id),
                machine_validation_error: None,
                validation_id: Some(validation_id),
            })
            .await
            .map_err(ClientApiError::InvocationError)
            .map(|_| ())
    }

    pub async fn cleanup_complete(&self, machine_id: &MachineId) -> ClientApiResult<()> {
        let cleanup_info = rpc::MachineCleanupInfo {
            machine_id: Some(*machine_id),
            nvme: Some(CleanupStepResult {
                result: 0,
                message: "".to_string(),
            }),
            ram: Some(CleanupStepResult {
                result: 0,
                message: "".to_string(),
            }),
            mem_overwrite: Some(CleanupStepResult {
                result: 0,
                message: "".to_string(),
            }),
            ib: Some(CleanupStepResult {
                result: 0,
                message: "".to_string(),
            }),
            result: 0,
        };

        self.0
            .cleanup_machine_completed(cleanup_info)
            .await
            .map_err(ClientApiError::InvocationError)
            .map(|_| ())
    }

    pub async fn get_pxe_instructions(
        &self,
        arch: rpc::forge::MachineArchitecture,
        interface_id: MachineInterfaceId,
        product: Option<String>,
    ) -> ClientApiResult<PxeInstructions> {
        self.0
            .get_pxe_instructions(rpc::forge::PxeInstructionRequest {
                arch: arch.into(),
                interface_id: Some(interface_id),
                product,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn configure_bmc_proxy_host(&self, host: String) -> ClientApiResult<()> {
        self.0
            .set_dynamic_config(SetDynamicConfigRequest {
                setting: ConfigSetting::BmcProxy as i32,
                value: host,
                expiry: None,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    /// Registers a mock expected machine. Static BMC (`bmc_ip_address`) is left unset here;
    /// real environments set it through the admin CLI / API when DHCP discovery is not used.
    pub async fn add_expected_machine(
        &self,
        bmc_mac_address: String,
        chassis_serial_number: String,
    ) -> ClientApiResult<()> {
        self.0
            .add_expected_machine(ExpectedMachine {
                bmc_mac_address,
                bmc_username: "root".to_string(),
                bmc_password: "factory_password".to_string(),
                chassis_serial_number,
                fallback_dpu_serial_numbers: Vec::new(),
                metadata: None,
                sku_id: None,
                id: None,
                host_nics: vec![],
                rack_id: None,
                default_pause_ingestion_and_poweron: None,
                #[allow(deprecated)]
                dpf_enabled: true,
                is_dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: None,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }
}
