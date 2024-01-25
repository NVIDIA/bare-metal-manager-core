use crate::{errors::DhcpError, Config};
use forge_tls::default::{default_client_cert, default_client_key, default_root_ca};
use rpc::{
    forge::{DhcpDiscovery, DhcpRecord},
    forge_tls_client::{ForgeClientCert, ForgeClientConfig, ForgeTlsClient},
};

pub async fn discover_dhcp(
    discovery_request: DhcpDiscovery,
    config: &Config,
) -> Result<DhcpRecord, DhcpError> {
    let forge_tls_config = ForgeClientConfig::new(
        default_root_ca().to_string(),
        Some(ForgeClientCert {
            cert_path: default_client_cert().to_string(),
            key_path: default_client_key().to_string(),
        }),
    );

    let Some(carbide_api_url) = &config.dhcp_config.carbide_api_url else {
        return Err(DhcpError::MissingArgument("carbide_api_url in DhcpConfig".to_string()));
    };

    let mut client = ForgeTlsClient::new(forge_tls_config)
        .connect(carbide_api_url)
        .await
        .map_err(|x| DhcpError::GenericError(x.to_string()))?;

    let request = tonic::Request::new(discovery_request);

    Ok(client.discover_dhcp(request).await?.into_inner())
}
