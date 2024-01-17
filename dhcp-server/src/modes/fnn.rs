use super::DhcpMode;

use lru::LruCache;
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use tonic::async_trait;

use crate::{cache::CacheEntry, errors::DhcpError, Config, FnnConfig, HostConfig, SubnetInfo};

#[derive(Debug)]
pub struct Fnn {}

fn from_fnn_conf(value: &SubnetInfo, giaddr: &str) -> Result<DhcpRecord, DhcpError> {
    let ip_info = value
        .ip
        .iter()
        .find(|x| x.giaddr.to_string() == giaddr)
        .ok_or_else(|| DhcpError::MissingArgument(format!("No entry for giaddr: {giaddr}")))?;

    // Fill only needed fields. Rest are left empty or none.
    Ok(DhcpRecord {
        machine_id: None,
        machine_interface_id: None,
        segment_id: None,
        subdomain_id: None,
        fqdn: ip_info.fqdn.clone(),
        mac_address: "dummy".to_string(),
        address: ip_info.address.to_string(),
        mtu: 0,
        prefix: value.prefix.clone(),
        gateway: Some(value.gateway.to_string()),
        booturl: None,
    })
}

#[async_trait]
impl DhcpMode for Fnn {
    async fn discover_dhcp(
        &self,
        discovery_request: DhcpDiscovery,
        config: &Config,
        _machine_cache: &mut LruCache<String, CacheEntry>,
    ) -> Result<DhcpRecord, DhcpError> {
        let Some(circuit_id) = discovery_request.circuit_id else {
            return Err(DhcpError::MissingArgument(
                "Missing circuit id.".to_string(),
            ));
        };

        let subnet_info = config
            .fnn_config
            .as_ref()
            .ok_or_else(|| DhcpError::InvalidInput("host input is invalid.".to_string()))?
            .config
            .get(&circuit_id)
            .ok_or_else(|| {
                DhcpError::MissingArgument(format!(
                    "Could not find Subnet details for {}",
                    circuit_id
                ))
            })?;

        from_fnn_conf(subnet_info, &discovery_request.relay_address)
    }

    async fn get_remote_id(
        &self,
        _host_config: &Option<HostConfig>,
    ) -> Result<Option<String>, DhcpError> {
        Ok(None)
    }
}

pub async fn get_fnn_config(
    fnn_config_path: Option<String>,
) -> Result<Option<FnnConfig>, DhcpError> {
    let Some(fnn_config) = fnn_config_path else {
            return Err(DhcpError::MissingArgument(
                "--fnn_config is missing.".to_string(),
            ));
        };

    let f = tokio::fs::read_to_string(fnn_config).await?;
    let fnn_config: FnnConfig = serde_yaml::from_str(&f)?;

    Ok(Some(fnn_config))
}
