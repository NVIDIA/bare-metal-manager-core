use base64::prelude::*;
use std::future::Future;
use std::net::Ipv4Addr;

use rpc::{
    forge::{MachineSearchConfig, MachineType},
    forge_tls_client::{self, ApiConfig, ForgeClientT},
};

use crate::config::MachineATronContext;

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
    mac_address: String,
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
            mac_address,
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

pub async fn discover_machine(
    app_context: &MachineATronContext,
    template_dir: &str,
    machine_type: MachineType,
    machine_interface_id: rpc::Uuid,
    network_interface_macs: Vec<String>,
    product_serial: String,
    host_mac_address: String,
) -> ClientApiResult<rpc::forge::MachineDiscoveryResult> {
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
        dmi_data.product_serial = product_serial;
    }
    if machine_type == MachineType::Host {
        discovery_data.tpm_ek_certificate =
            Some(BASE64_STANDARD.encode(machine_interface_id.to_string()));
        discovery_data.dpu_info = None;
    } else if let Some(ref mut dpu_info) = discovery_data.dpu_info {
        dpu_info.factory_mac_address = host_mac_address;
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
    bmc_host: Option<Ipv4Addr>,
    bmc_port: Option<u16>,
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
        ip: bmc_host.map(|i| i.to_string()),
        port: bmc_port.map(|i| i.into()),
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
                rpc::forge::MachineDiscoveryCompletedRequest {
                    machine_id,
                    discovery_error: None,
                },
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
                    include_associated_machine_id: false,
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
    version: Option<String>,
) -> ClientApiResult<()> {
    let dpu_machine_id = Some(dpu_machine_id);

    with_forge_client(app_context, |mut client| async move {
        client
            .record_dpu_network_status(tonic::Request::new(rpc::forge::DpuNetworkStatus {
                dpu_machine_id,
                observed_at: None,
                health: Some(rpc::forge::NetworkHealth {
                    is_healthy: true,
                    passed: vec![],
                    failed: vec![],
                    message: Some("Hello".to_owned()),
                }),
                network_config_version: version,
                instance_config_version: None,
                interfaces: vec![],
                network_config_error: None,
                instance_id: None,
                dpu_agent_version: None,
                client_certificate_expiry_unix_epoch_secs: None,
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
                },
            ))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)
    })
    .await
}
