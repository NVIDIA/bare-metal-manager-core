use crate::forge_resolver::read_resolv_conf;
use eyre::Report;
use hickory_resolver::config::{NameServerConfigGroup, ResolverOpts};
use hickory_resolver::Name;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

const DEFAULT_PORT: u16 = 53;
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

#[derive(Clone, Default)]
pub struct ForgeResolverConfig {
    pub inner: NameServerConfigGroup,
    pub search_domain: Vec<Name>,
    pub domain: Option<Name>,
}

#[derive(Clone, Debug)]
pub struct ForgeResolveConf {
    parsed_configuration: Option<resolv_conf::Config>,
}

impl ForgeResolveConf {
    pub fn new(path: &Path) -> Result<Self, Report> {
        let resolv_conf_file = Path::new(&path);
        let parsed_data = read_resolv_conf(resolv_conf_file)?;

        Ok(Self {
            parsed_configuration: Some(parsed_data),
        })
    }

    pub fn with_system_resolv_conf() -> Result<Self, Report> {
        let resolv_conf_file = Path::new(RESOLV_CONF_PATH);
        let parsed_data = read_resolv_conf(resolv_conf_file)?;

        Ok(Self {
            parsed_configuration: Some(parsed_data),
        })
    }

    pub fn parsed_configuration(self) -> resolv_conf::Config {
        self.parsed_configuration
            .unwrap_or_else(resolv_conf::Config::new)
    }
}

impl ForgeResolverConfig {
    pub fn new() -> Self {
        Self {
            inner: NameServerConfigGroup::new(),
            search_domain: vec![],
            domain: None,
        }
    }
}

pub fn into_forge_resolver_config(
    parsed_config: resolv_conf::Config,
) -> Result<(ForgeResolverConfig, ResolverOpts), Report> {
    let mut frc = ForgeResolverConfig::new();

    if let Some(domain) = parsed_config.get_domain() {
        frc.domain = Some(Name::from_str(domain.as_str())?);
    } else {
        frc.domain = None
    }

    let ips: Vec<IpAddr> = parsed_config
        .get_nameservers_or_local()
        .into_iter()
        .map(|scoped_ip| -> IpAddr { scoped_ip.into() })
        .collect();

    let nameservers = NameServerConfigGroup::from_ips_clear(&ips, DEFAULT_PORT, false);

    if nameservers.is_empty() {
        tracing::warn!("no nameservers found in config");
    }

    for search_domain in parsed_config.get_last_search_or_domain() {
        // Ignore invalid search domains
        if search_domain == "--" {
            continue;
        }

        frc.search_domain
            .push(Name::from_str_relaxed(search_domain).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error parsing resolv.conf: {e}"),
                )
            })?);
    }

    frc.inner = nameservers;

    // TODO: Allow passing through Custom ResolverOpts
    Ok((frc, ResolverOpts::default()))
}
