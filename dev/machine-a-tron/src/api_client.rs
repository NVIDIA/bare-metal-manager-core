use crate::config::MachineATronContext;
use base64::prelude::*;
use mac_address::MacAddress;
use rpc::forge::machine_cleanup_info::CleanupStepResult;
use rpc::forge::{ConfigSetting, MachinesByIdsRequest, PxeInstructions, SetDynamicConfigRequest};
use rpc::site_explorer::SiteExplorationReport;
use rpc::{
    forge::{MachineSearchConfig, MachineType},
    forge_tls_client::{self, ApiConfig, ForgeClientT},
};
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum ClientApiError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Unable to connect to carbide API: {0}")]
    ConnectFailed(String),

    #[error("The API call to the Forge API server returned {0}")]
    InvocationError(tonic::Status),
}

type ClientApiResult<T> = Result<T, ClientApiError>;

pub async fn with_forge_client<T, F>(
    app_context: &MachineATronContext,
    callback: impl FnOnce(ForgeClientT) -> F,
) -> ClientApiResult<T>
where
    F: Future<Output = ClientApiResult<T>>,
{
    let api_config = ApiConfig::new(
        app_context
            .app_config
            .carbide_api_url
            .as_ref()
            .ok_or(ClientApiError::ConfigError(
                "missing carbide_api_url".to_string(),
            ))?,
        app_context.forge_client_config.clone(),
    );

    let client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|err| ClientApiError::ConnectFailed(err.to_string()))?;

    callback(client).await
}

pub async fn version(app_context: &MachineATronContext) -> ClientApiResult<rpc::forge::BuildInfo> {
    with_forge_client(app_context, |mut client| async move {
        let out = client
            .version(tonic::Request::new(rpc::forge::VersionRequest {
                display_config: false,
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn discover_dhcp(
    app_context: &MachineATronContext,
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

    with_forge_client(app_context, |mut client| async move {
        let dhcp_discovery = rpc::forge::DhcpDiscovery {
            mac_address: mac_address.to_string(),
            circuit_id,
            relay_address,
            ..default_data
        };
        //        tracing::info!("dhcp_discovery: {:?}", dhcp_discovery);
        let out = client
            .discover_dhcp(tonic::Request::new(dhcp_discovery))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    })
    .await
}

// Simple wrapper around the inputs to discover_machine so that callers can see the field names
pub struct MockDiscoveryData {
    pub machine_interface_id: rpc::Uuid,
    pub network_interface_macs: Vec<String>,
    pub product_serial: Option<String>,
    pub chassis_serial: Option<String>,
    pub tpm_ek_certificate: Option<Vec<u8>>,
    pub host_mac_address: Option<MacAddress>,
}

pub async fn discover_machine(
    app_context: &MachineATronContext,
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
    } = discovery_data;
    /*
    tracing::info!(
        "sending discover info for {:?} {} ({:?})",
        machine_type,
        machine_interface_id,
        network_interface_macs.get(0)
    );
    */
    let json_path = if machine_type == MachineType::Dpu {
        format!("{}/dpu_discovery_info.json", template_dir)
    } else {
        format!("{}/host_discovery_info.json", template_dir)
    };
    let dhcp_string = std::fs::read_to_string(&json_path)
        .map_err(|e| ClientApiError::ConfigError(format!("Unable to read {}: {}", json_path, e)))?;
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
        discovery_data.tpm_ek_certificate = Some(BASE64_STANDARD.encode(
            tpm_ek_certificate.ok_or(ClientApiError::ConfigError(
                "No TPM EK certificate waa supplied".to_string(),
            ))?,
        ));
        discovery_data.dpu_info = None;
    } else if let Some(ref mut dpu_info) = discovery_data.dpu_info {
        if let Some(host_mac_address) = host_mac_address {
            dpu_info.factory_mac_address = host_mac_address.to_string();
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

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .discover_machine(tonic::Request::new(mdi))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn update_bmc_metadata(
    app_context: &MachineATronContext,
    template_dir: &str,
    machine_type: MachineType,
    machine_id: rpc::MachineId,
    bmc_host: Ipv4Addr,
    bmc_mac: MacAddress,
) -> ClientApiResult<rpc::forge::BmcMetaDataUpdateResponse> {
    let json_path = if machine_type == MachineType::Dpu {
        format!("{}/dpu_metadata_update.json", template_dir)
    } else {
        format!("{}/host_metadata_update.json", template_dir)
    };
    let md_request_string = std::fs::read_to_string(&json_path)
        .map_err(|e| ClientApiError::ConfigError(format!("Unable to read {}: {}", json_path, e)))?;

    let mut default_data: rpc::forge::BmcMetaDataUpdateRequest =
        serde_json::from_str(&md_request_string).map_err(|e| {
            ClientApiError::ConfigError(format!(
                "{} does not have correct format: {}",
                json_path, e
            ))
        })?;

    default_data.machine_id = Some(machine_id);

    default_data.bmc_info = Some(rpc::forge::BmcInfo {
        ip: Some(bmc_host.to_string()),
        port: Some(app_context.app_config.bmc_mock_port.into()),
        mac: Some(bmc_mac.to_string()),
        ..Default::default()
    });

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .update_bmc_meta_data(tonic::Request::new(default_data))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn forge_agent_control(
    app_context: &MachineATronContext,
    machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::ForgeAgentControlResponse> {
    let machine_id = Some(machine_id);

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .forge_agent_control(tonic::Request::new(rpc::forge::ForgeAgentControlRequest {
                machine_id,
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn discovery_complete(
    app_context: &MachineATronContext,
    machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::MachineDiscoveryCompletedResponse> {
    let machine_id = Some(machine_id);

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .discovery_completed(tonic::Request::new(
                rpc::forge::MachineDiscoveryCompletedRequest { machine_id },
            ))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn get_machine(
    app_context: &MachineATronContext,
    machine_id: rpc::MachineId,
) -> ClientApiResult<Option<rpc::forge::Machine>> {
    let machine_id = Some(machine_id);

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
                id: machine_id,
                fqdn: None,
                search_config: Some(MachineSearchConfig {
                    include_dpus: true,
                    include_history: false,
                    include_predicted_host: true,
                    only_maintenance: false,
                    exclude_hosts: false,
                }),
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;

        Ok(out.machines.first().cloned())
    })
    .await
}

pub async fn get_machines(
    app_context: &MachineATronContext,
    machine_ids: &[&String],
) -> ClientApiResult<Vec<rpc::Machine>> {
    let request = MachinesByIdsRequest {
        machine_ids: machine_ids
            .iter()
            .map(|i| rpc::MachineId { id: i.to_string() })
            .collect(),
        include_history: false,
    };
    with_forge_client(app_context, |mut client| async move {
        let out = client
            .find_machines_by_ids(tonic::Request::new(request))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;

        Ok(out.machines)
    })
    .await
}

pub async fn identify_serial(
    app_context: &MachineATronContext,
    serial: String,
) -> ClientApiResult<::rpc::common::MachineId> {
    with_forge_client(app_context, |mut client| async move {
        let out = match client
            .identify_serial(tonic::Request::new(rpc::forge::IdentifySerialRequest {
                serial_number: serial,
            }))
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(ClientApiError::ConfigError("SerialNotFound".to_string()));
            }
            Err(err) => {
                tracing::error!(%err, "identify_serial error calling grpc identify_serial");
                return Err(ClientApiError::ConfigError(err.to_string()));
            }
        };

        out.machine_id.ok_or(ClientApiError::ConfigError(
            "Serial number found without associated machine ID".to_string(),
        ))
    })
    .await
}

pub async fn get_managed_host_network_config(
    app_context: &MachineATronContext,
    dpu_machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::ManagedHostNetworkConfigResponse> {
    let dpu_machine_id = Some(dpu_machine_id);

    with_forge_client(app_context, |mut client| async move {
        let out = client
            .get_managed_host_network_config(tonic::Request::new(
                rpc::forge::ManagedHostNetworkConfigRequest { dpu_machine_id },
            ))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    })
    .await
}

pub async fn record_dpu_network_status(
    app_context: &MachineATronContext,
    dpu_machine_id: rpc::MachineId,
    network_config_version: String,
    instance_network_config_version: Option<String>,
    instance_config_version: Option<String>,
    instance_id: Option<rpc::Uuid>,
    interfaces: Vec<rpc::forge::InstanceInterfaceStatusObservation>,
) -> ClientApiResult<()> {
    let dpu_machine_id = Some(dpu_machine_id);

    with_forge_client(app_context, |mut client| async move {
        client
            .record_dpu_network_status(tonic::Request::new(rpc::forge::DpuNetworkStatus {
                dpu_health: Some(rpc::health::HealthReport {
                    source: "forge-dpu-agent".to_string(),
                    observed_at: None,
                    successes: Vec::new(),
                    alerts: Vec::new(),
                }),
                dpu_machine_id,
                observed_at: None,
                health: Some(rpc::forge::NetworkHealth {
                    is_healthy: true,
                    passed: vec![],
                    failed: vec![],
                    message: Some("Hello".to_owned()),
                }),
                network_config_version: Some(network_config_version),
                instance_config_version,
                instance_network_config_version,
                interfaces,
                network_config_error: None,
                instance_id,
                dpu_agent_version: None,
                client_certificate_expiry_unix_epoch_secs: None,
                fabric_interfaces: vec![],
                last_dhcp_requests: vec![],
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

pub async fn find_network_segments(
    app_context: &MachineATronContext,
) -> ClientApiResult<rpc::forge::NetworkSegmentList> {
    with_forge_client(app_context, |mut client| async move {
        client
            .find_network_segments(tonic::Request::new(rpc::forge::NetworkSegmentQuery {
                id: None,
                search_config: None,
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

pub async fn find_machine_ids(
    app_context: &MachineATronContext,
) -> ClientApiResult<rpc::common::MachineIdList> {
    with_forge_client(app_context, |mut client| async move {
        client
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                include_dpus: false,
                include_history: true,
                include_predicted_host: true,
                only_maintenance: false,
                exclude_hosts: false,
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

pub async fn allocate_instance(
    app_context: &MachineATronContext,
    host_machine_id: &str,
    network_segment_name: &str,
) -> ClientApiResult<rpc::forge::Instance> {
    with_forge_client(app_context, |mut client| async move {
        let segment_request = tonic::Request::new(rpc::forge::NetworkSegmentSearchFilter{
                                    name: Some(network_segment_name.to_owned()),
                                    tenant_org_id: None,
                                });

        let network_segment_ids = match client
            .find_network_segment_ids(segment_request).await {
                Ok(response) => {
                    response.into_inner()
                }

                Err(e) => {
                    return Err(ClientApiError::ConfigError(format!(
                            "network segment: {} retrieval error {}",
                            network_segment_name, e)));
                }
            };

        if network_segment_ids.network_segments_ids.is_empty() {
            return Err(ClientApiError::ConfigError(format!(
                "network segment: {} not found.", network_segment_name)));
        } else if  network_segment_ids.network_segments_ids.len() >= 2 {
            tracing::warn!("Network segments from previous runs of machine-a-tron have not been cleaned up. Suggested to start again after cleaning db.");
        }
        let network_segment_id = network_segment_ids.network_segments_ids.first();

        let interface_config = rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            network_segment_id:
            network_segment_id.cloned(),
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
            network: Some(rpc::InstanceNetworkConfig{
                interfaces: vec![interface_config],
            }),
            infiniband: None,
            storage: None,
        };

        let instance_request = tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_owned(),
            }),
            config: Some(instance_config),
            metadata: None,
        });

        client
            .allocate_instance(instance_request)
            .await
            .map(
                |response: tonic::Response<rpc::forge::Instance>| {
                    response.into_inner()
                },
            )
            .map_err(ClientApiError::InvocationError)
    }).await
}

pub async fn force_delete_machine(
    app_context: &MachineATronContext,
    machine_id: String,
) -> ClientApiResult<rpc::forge::AdminForceDeleteMachineResponse> {
    with_forge_client(app_context, |mut client| async move {
        client
            .admin_force_delete_machine(tonic::Request::new(
                rpc::forge::AdminForceDeleteMachineRequest {
                    host_query: machine_id,
                    delete_interfaces: true,
                    delete_bmc_interfaces: true,
                    delete_bmc_credentials: false,
                },
            ))
            .await
            .map(
                |response: tonic::Response<rpc::forge::AdminForceDeleteMachineResponse>| {
                    response.into_inner()
                },
            )
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

static SUBNET_COUNTER: AtomicU32 = AtomicU32::new(0);
pub async fn create_network_segment(
    app_context: &MachineATronContext,
    vpc_name: &String,
) -> ClientApiResult<rpc::NetworkSegment> {
    let subnet_count = SUBNET_COUNTER.fetch_add(1, Ordering::Acquire);

    with_forge_client(app_context, |mut client| async move {
        let vpc_ids_all = client.find_vpc_ids(
            tonic::Request::new(rpc::forge::VpcSearchFilter {
                tenant_org_id: None,
                name: Some(vpc_name.clone()),
                label: None,
            })
        ).await;

        match vpc_ids_all {
            Ok(response) => {
                let vpc_id_list = response.into_inner();

                match vpc_id_list.vpc_ids.len() {
                    0 => tracing::error!("There are no VPC ids associated with {}. Should not have happened.", *vpc_name),
                    1 => {},
                    _ => tracing::warn!("There are {} VPC ids associated with {}. Should not have happened. Clean up DB and start over.",vpc_id_list.vpc_ids.len(), vpc_name),
                }

                client
                    .create_network_segment(tonic::Request::new(rpc::forge::NetworkSegmentCreationRequest {
                        id: None,
                        vpc_id: vpc_id_list.vpc_ids.first().cloned(),
                        name: format!("subnet_{}", subnet_count),
                        segment_type: rpc::forge::NetworkSegmentType::Tenant.into(),
                        prefixes: vec![rpc::forge::NetworkPrefix {
                            id: None,
                            prefix: format!("192.5.{}.12/24",subnet_count ),
                            gateway: Some(format!("192.5.{}.13",subnet_count )),
                            reserve_first: 1,
                            state: None,
                            events: vec![],
                            circuit_id: None,
                            free_ip_count: 1022,
                        }],
                        mtu: Some(1500),
                        subdomain_id: None,
                    }))
                    .await
                    .map(|response| response.into_inner())
                    .map_err(ClientApiError::InvocationError)
            }
            Err(e) => {
                Err(ClientApiError::ConnectFailed(format!("Error {} when finding VPC {}",e, *vpc_name)))
            }
        }
    })
    .await
}

pub async fn delete_network_segment(
    app_context: &MachineATronContext,
    vpc_id: &Uuid,
) -> ClientApiResult<rpc::forge::NetworkSegmentDeletionResult> {
    with_forge_client(app_context, |mut client| async move {
        client
            .delete_network_segment(tonic::Request::new(
                rpc::forge::NetworkSegmentDeletionRequest {
                    id: Some(rpc::Uuid {
                        value: vpc_id.to_string(),
                    }),
                },
            ))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

static VPC_COUNTER: AtomicU32 = AtomicU32::new(0);
pub async fn create_vpc(app_context: &MachineATronContext) -> ClientApiResult<rpc::forge::Vpc> {
    let vpc_count = VPC_COUNTER.fetch_add(1, Ordering::Acquire);
    with_forge_client(app_context, |mut client| async move {
        client
            .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
                id: None,
                name: "".to_string(),
                tenant_organization_id: "Forge-simulation-tenant".to_string(),
                tenant_keyset_id: None,
                network_virtualization_type: None,
                metadata: Some(rpc::forge::Metadata {
                    name: format!("vpc_{}", vpc_count),
                    description: "".to_string(),
                    labels: vec![rpc::forge::Label {
                        key: "Forge-simulation-vpc".to_string(),
                        value: Some("Machine-a-tron".to_string()),
                    }],
                }),
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

pub async fn delete_vpc(
    app_context: &MachineATronContext,
    vpc_id: &Uuid,
) -> ClientApiResult<rpc::forge::VpcDeletionResult> {
    with_forge_client(app_context, |mut client| async move {
        client
            .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
                id: Some(rpc::Uuid {
                    value: vpc_id.to_string(),
                }),
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}

pub async fn machine_validation_complete(
    app_context: &MachineATronContext,
    machine_id: &rpc::MachineId,
    validation_id: rpc::common::Uuid,
) -> ClientApiResult<()> {
    with_forge_client(app_context, |mut client| async move {
        client
            .machine_validation_completed(tonic::Request::new(
                rpc::forge::MachineValidationCompletedRequest {
                    machine_id: Some(machine_id.clone()),
                    machine_validation_error: None,
                    validation_id: Some(validation_id),
                },
            ))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|_| ())
}

pub async fn cleanup_complete(
    app_context: &MachineATronContext,
    machine_id: &rpc::MachineId,
) -> ClientApiResult<()> {
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

    with_forge_client(app_context, |mut client| async move {
        client
            .cleanup_machine_completed(tonic::Request::new(cleanup_info))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|_| ())
}

pub async fn reboot_completed(
    app_context: &MachineATronContext,
    machine_id: rpc::MachineId,
) -> ClientApiResult<()> {
    with_forge_client(app_context, |mut client| async move {
        client
            .reboot_completed(tonic::Request::new(
                rpc::forge::MachineRebootCompletedRequest {
                    machine_id: Some(machine_id),
                },
            ))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|_| ())
}

pub async fn get_pxe_instructions(
    app_context: &MachineATronContext,
    arch: rpc::forge::MachineArchitecture,
    interface_id: rpc::Uuid,
) -> ClientApiResult<PxeInstructions> {
    with_forge_client(app_context, |mut client| async move {
        client
            .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
                arch: arch.into(),
                interface_id: Some(interface_id),
            }))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|r| r.into_inner())
}

pub async fn get_site_exploration_report(
    app_context: &MachineATronContext,
) -> ClientApiResult<SiteExplorationReport> {
    with_forge_client(app_context, |mut client| async move {
        client
            .get_site_exploration_report(tonic::Request::new(
                rpc::forge::GetSiteExplorationRequest {},
            ))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|r| r.into_inner())
}

pub async fn configure_bmc_proxy_host(
    app_context: &MachineATronContext,
    host: String,
) -> ClientApiResult<()> {
    with_forge_client(app_context, |mut client| async move {
        client
            .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
                setting: ConfigSetting::BmcProxy as i32,
                value: host,
                expiry: None,
            }))
            .await
            .map_err(ClientApiError::InvocationError)
    })
    .await
    .map(|r| r.into_inner())
}
