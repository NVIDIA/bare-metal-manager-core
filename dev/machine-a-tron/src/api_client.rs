use crate::MachineConfig;
use base64::prelude::*;
use mac_address::MacAddress;
use rpc::forge::MachineType;
use rpc::forge::machine_cleanup_info::CleanupStepResult;
use rpc::forge::{
    ConfigSetting, ExpectedMachine, MachinesByIdsRequest, PxeInstructions, SetDynamicConfigRequest,
};
use rpc::protos::forge_api_client::ForgeApiClient;
use std::sync::atomic::{AtomicU32, Ordering};

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
    pub machine_interface_id: rpc::Uuid,
    pub network_interface_macs: Vec<String>,
    pub product_serial: Option<String>,
    pub chassis_serial: Option<String>,
    pub tpm_ek_certificate: Option<Vec<u8>>,
    pub host_mac_address: Option<MacAddress>,
    pub dpu_nic_version: Option<String>,
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
    pub dpu_machine_id: rpc::MachineId,
    pub network_config_version: String,
    pub instance_network_config_version: Option<String>,
    pub instance_config_version: Option<String>,
    pub instance_id: Option<rpc::Uuid>,
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
            ClientApiError::ConfigError(format!("Unable to read {}: {}", json_path, e,))
        })?;
        let default_data: rpc::forge::DhcpDiscovery =
            serde_json::from_str(&dhcp_string).map_err(|e| {
                ClientApiError::ConfigError(format!(
                    "{}/dhcp_discovery.json does not have correct format: {}",
                    template_dir, e
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
        id: &str,
    ) -> ClientApiResult<rpc::forge::InterfaceList> {
        let interface_search_query = rpc::forge::InterfaceSearchQuery {
            id: Some(id.to_string().into()),
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
        template_dir: &str,
        machine_type: MachineType,
        discovery_data: MockDiscoveryData,
    ) -> ClientApiResult<rpc::forge::MachineDiscoveryResult> {
        let MockDiscoveryData {
            machine_interface_id,
            network_interface_macs,
            product_serial,
            chassis_serial,
            host_mac_address,
            tpm_ek_certificate,
            dpu_nic_version,
        } = discovery_data;
        let json_path = if machine_type == MachineType::Dpu {
            format!("{}/dpu_discovery_info.json", template_dir)
        } else {
            format!("{}/host_discovery_info.json", template_dir)
        };
        let dhcp_string = std::fs::read_to_string(&json_path).map_err(|e| {
            ClientApiError::ConfigError(format!("Unable to read {}: {}", json_path, e))
        })?;
        let mut discovery_data: rpc::machine_discovery::DiscoveryInfo =
            serde_json::from_str(&dhcp_string).map_err(|e| {
                ClientApiError::ConfigError(format!(
                    "{} does not have correct format: {}",
                    json_path, e
                ))
            })?;

        if let Some(ref mut dmi_data) = discovery_data.dmi_data {
            if let Some(product_serial) = product_serial {
                dmi_data.product_serial = product_serial;
            }
            if let Some(chassis_serial) = chassis_serial {
                dmi_data.chassis_serial = chassis_serial;
            }
        }
        if machine_type == MachineType::Host {
            discovery_data.tpm_ek_certificate =
                Some(BASE64_STANDARD.encode(tpm_ek_certificate.ok_or(
                    ClientApiError::ConfigError("No TPM EK certificate waa supplied".to_string()),
                )?));
            discovery_data.dpu_info = None;
        } else if let Some(ref mut dpu_info) = discovery_data.dpu_info {
            if let Some(host_mac_address) = host_mac_address {
                dpu_info.factory_mac_address = host_mac_address.to_string();
            }
            if let Some(dpu_nic_version) = dpu_nic_version {
                dpu_info.firmware_version = dpu_nic_version;
            }
        }
        discovery_data.network_interfaces = network_interface_macs
            .iter()
            .map(|mac| rpc::machine_discovery::NetworkInterface {
                mac_address: mac.clone(),
                pci_properties: None,
            })
            .collect();

        let mdi = rpc::forge::MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(rpc::forge::machine_discovery_info::DiscoveryData::Info(
                discovery_data,
            )),
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
        machine_ids: &[&String],
    ) -> ClientApiResult<Vec<rpc::Machine>> {
        let request = MachinesByIdsRequest {
            machine_ids: machine_ids.iter().map(|i| i.to_string().into()).collect(),
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
            .or(Some(forge_version::v!(build_version).to_string()));

        self.0
            .record_dpu_network_status(rpc::forge::DpuNetworkStatus {
                dpu_health: Some(rpc::health::HealthReport {
                    source: "forge-dpu-agent".to_string(),
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
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn find_network_segments(&self) -> ClientApiResult<rpc::forge::NetworkSegmentList> {
        self.0
            .find_network_segments(rpc::forge::NetworkSegmentQuery {
                id: None,
                search_config: None,
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn allocate_instance(
        &self,
        host_machine_id: &str,
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
                    "network segment: {} retrieval error {}",
                    network_segment_name, e
                ))
            })?;

        if network_segment_ids.network_segments_ids.is_empty() {
            return Err(ClientApiError::ConfigError(format!(
                "network segment: {} not found.",
                network_segment_name
            )));
        } else if network_segment_ids.network_segments_ids.len() >= 2 {
            tracing::warn!(
                "Network segments from previous runs of machine-a-tron have not been cleaned up. Suggested to start again after cleaning db."
            );
        }
        let network_segment_id = network_segment_ids.network_segments_ids.first();

        let interface_config = rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            network_segment_id: network_segment_id.cloned(),
            network_details: network_segment_id
                .cloned()
                .map(rpc::forge::instance_interface_config::NetworkDetails::SegmentId),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        };

        let tenant_config = rpc::TenantConfig {
            user_data: None,
            custom_ipxe: "Non-existing-ipxe".to_string(),
            phone_home_enabled: false,
            always_boot_with_custom_ipxe: false,
            tenant_organization_id: "Forge-simulation-tenant".to_string(),
            tenant_keyset_ids: vec![],
            hostname: None,
        };

        let instance_config = rpc::InstanceConfig {
            tenant: Some(tenant_config),
            os: None,
            network: Some(rpc::InstanceNetworkConfig {
                interfaces: vec![interface_config],
            }),
            network_security_group_id: None,
            infiniband: None,
            storage: None,
        };

        let instance_request = rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_owned(),
            }),
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

                self.0
                    .create_network_segment(rpc::forge::NetworkSegmentCreationRequest {
                        id: None,
                        vpc_id: vpc_id_list.vpc_ids.first().cloned(),
                        name: format!("subnet_{}", subnet_count),
                        segment_type: rpc::forge::NetworkSegmentType::Tenant.into(),
                        prefixes: vec![rpc::forge::NetworkPrefix {
                            id: None,
                            prefix: format!("192.5.{}.12/24", subnet_count),
                            gateway: Some(format!("192.5.{}.13", subnet_count)),
                            reserve_first: 1,
                            state: None,
                            events: vec![],
                            free_ip_count: 1022,
                            svi_ip: None,
                        }],
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

    pub async fn create_vpc(&self) -> ClientApiResult<rpc::forge::Vpc> {
        let vpc_count = VPC_COUNTER.fetch_add(1, Ordering::Acquire);
        self.0
            .create_vpc(rpc::forge::VpcCreationRequest {
                id: None,
                name: "".to_string(),
                tenant_organization_id: "Forge-simulation-tenant".to_string(),
                tenant_keyset_id: None,
                network_security_group_id: None,
                network_virtualization_type: None,
                metadata: Some(rpc::forge::Metadata {
                    name: format!("vpc_{}", vpc_count),
                    description: "".to_string(),
                    labels: vec![rpc::forge::Label {
                        key: "Forge-simulation-vpc".to_string(),
                        value: Some("Machine-a-tron".to_string()),
                    }],
                }),
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }

    pub async fn machine_validation_complete(
        &self,
        machine_id: &rpc::MachineId,
        validation_id: rpc::common::Uuid,
    ) -> ClientApiResult<()> {
        self.0
            .machine_validation_completed(rpc::forge::MachineValidationCompletedRequest {
                machine_id: Some(machine_id.clone()),
                machine_validation_error: None,
                validation_id: Some(validation_id),
            })
            .await
            .map_err(ClientApiError::InvocationError)
            .map(|_| ())
    }

    pub async fn cleanup_complete(&self, machine_id: &rpc::MachineId) -> ClientApiResult<()> {
        let cleanup_info = rpc::MachineCleanupInfo {
            machine_id: Some(machine_id.to_string().into()),
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
        interface_id: rpc::Uuid,
    ) -> ClientApiResult<PxeInstructions> {
        self.0
            .get_pxe_instructions(rpc::forge::PxeInstructionRequest {
                arch: arch.into(),
                interface_id: Some(interface_id),
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
            })
            .await
            .map_err(ClientApiError::InvocationError)
    }
}
