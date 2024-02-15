use base64::prelude::*;
use std::future::Future;

use rpc::{
    forge::{MachineSearchConfig, MachineType},
    forge_tls_client::{self, ForgeClientT},
};

use crate::AppConfig;

#[derive(thiserror::Error, Debug)]
pub enum ClientApiError {
    #[error("Unable to connect to carbide API: {0}")]
    ConnectFailed(String),

    #[error("The API call to the Forge API server returned {0}")]
    InvocationError(tonic::Status),
}

type ClientApiResult<T> = Result<T, ClientApiError>;

pub async fn with_forge_client<T, F>(
    app_config: &AppConfig,
    callback: impl FnOnce(ForgeClientT) -> F,
) -> ClientApiResult<T>
where
    F: Future<Output = ClientApiResult<T>>,
{
    let client = forge_tls_client::ForgeTlsClient::new(app_config.forge_client_config.clone())
        .connect(app_config.carbide_api_url.clone())
        .await
        .map_err(|err| ClientApiError::ConnectFailed(err.to_string()))?;

    callback(client).await
}

pub async fn version(app_config: &AppConfig) -> ClientApiResult<rpc::forge::BuildInfo> {
    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    mac_address: String,
    circuit_id: Option<String>,
) -> ClientApiResult<rpc::forge::DhcpRecord> {
    tracing::info!("dhcp request for {}", mac_address);
    let dhcp_string =
        std::fs::read_to_string(app_config.template_dir.clone() + "/dhcp_discovery.json")
            .expect("Unable to read dhcp_discovery.json");
    let default_data: rpc::forge::DhcpDiscovery = serde_json::from_str(&dhcp_string)
        .expect("dhcp_discovery.json does not have correct format.");

    with_forge_client(app_config, |mut client| async move {
        let out = client
            .discover_dhcp(tonic::Request::new(rpc::forge::DhcpDiscovery {
                mac_address,
                circuit_id,
                relay_address: app_config.relay_address.clone(),
                ..default_data
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;

        Ok(out)
    })
    .await
}

pub async fn discover_machine(
    app_config: &AppConfig,
    machine_type: MachineType,
    machine_interface_id: rpc::Uuid,
    network_interface_macs: Vec<String>,
    product_serial: String,
    host_mac_address: String,
) -> ClientApiResult<rpc::forge::MachineDiscoveryResult> {
    tracing::info!(
        "sending discover info for {:?} {} ({})",
        machine_type,
        machine_interface_id,
        host_mac_address
    );
    let dhcp_string = if machine_type == MachineType::Dpu {
        std::fs::read_to_string(app_config.template_dir.clone() + "/dpu_discovery_info.json")
            .expect("Unable to read dpu_discovery_info.json")
    } else {
        std::fs::read_to_string(app_config.template_dir.clone() + "/host_discovery_info.json")
            .expect("Unable to read host_discovery_info.json")
    };
    let mut discovery_data: rpc::machine_discovery::DiscoveryInfo =
        serde_json::from_str(&dhcp_string)
            .expect("discover_machine json does not have correct format.");

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
    };

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    machine_type: MachineType,
    machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::BmcMetaDataUpdateResponse> {
    let machine_id = Some(machine_id);
    let md_request_string = if machine_type == MachineType::Dpu {
        std::fs::read_to_string(app_config.template_dir.clone() + "/dpu_metadata_update.json")
            .expect("Unable to read dpu_metadata_update.json")
    } else {
        std::fs::read_to_string(app_config.template_dir.clone() + "/host_metadata_update.json")
            .expect("Unable to read host_metadata_update.json")
    };

    let default_data: rpc::forge::BmcMetaDataUpdateRequest =
        serde_json::from_str(&md_request_string)
            .expect("metadata_update json does not have correct format.");

    with_forge_client(app_config, |mut client| async move {
        let out = client
            .update_bmc_meta_data(tonic::Request::new(rpc::forge::BmcMetaDataUpdateRequest {
                machine_id,
                ..default_data
            }))
            .await
            .map(|response| response.into_inner())
            .map_err(ClientApiError::InvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn forge_agent_control(
    app_config: &AppConfig,
    machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::ForgeAgentControlResponse> {
    let machine_id = Some(machine_id);

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::MachineDiscoveryCompletedResponse> {
    let machine_id = Some(machine_id);

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    machine_id: rpc::MachineId,
) -> ClientApiResult<Option<rpc::forge::Machine>> {
    let machine_id = Some(machine_id);

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    dpu_machine_id: rpc::MachineId,
) -> ClientApiResult<rpc::forge::ManagedHostNetworkConfigResponse> {
    let dpu_machine_id = Some(dpu_machine_id);

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
    dpu_machine_id: rpc::MachineId,
    version: Option<String>,
) -> ClientApiResult<()> {
    let dpu_machine_id = Some(dpu_machine_id);

    with_forge_client(app_config, |mut client| async move {
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
    app_config: &AppConfig,
) -> ClientApiResult<rpc::forge::NetworkSegmentList> {
    with_forge_client(app_config, |mut client| async move {
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
