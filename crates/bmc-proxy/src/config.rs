use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;

use carbide_authn::config::{AllowedCertCriteria, TrustConfig};
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Serialize};
use utils::HostPortPair;

use crate::acl::AclConfig;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Read(String),
    #[error(transparent)]
    Figment(Box<figment::Error>),
    #[error("Invalid database url: {0}")]
    DatabaseUrl(String),
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "Defaults::listen")]
    pub listen: SocketAddr,
    pub database_url: String,
    #[serde(default = "Defaults::max_database_connections")]
    pub max_database_connections: u32,
    #[serde(default = "Defaults::metrics_endpoint")]
    pub metrics_endpoint: SocketAddr,
    #[serde(default)]
    pub allowed_principals: HashSet<String>,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    pub bmc_proxy: Option<HostPortPair>,
}

struct Defaults;

impl Defaults {
    fn listen() -> SocketAddr {
        SocketAddr::from_str("[::]:1079").expect("BUG: default listen endpoint doesn't parse")
    }

    fn max_database_connections() -> u32 {
        16
    }

    fn metrics_endpoint() -> SocketAddr {
        SocketAddr::from_str("[::]:1080").expect("BUG: default metrics endpoint doesn't parse")
    }

    fn trust_config() -> TrustConfig {
        TrustConfig {
            spiffe_trust_domain: "forge.local".to_string(),
            spiffe_service_base_paths: vec![
                "/forge-system/sa/".to_string(),
                "/default/sa/".to_string(),
            ],
            spiffe_machine_base_path: "/forge-system/machine/".to_string(),
            additional_issuer_cns: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub identity_pemfile_path: String,
    pub identity_keyfile_path: String,
    pub root_cafile_path: String,
    pub admin_root_cafile_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            identity_pemfile_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            identity_keyfile_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
            root_cafile_path: "/var/run/secrets/spiffe.io/ca.crt".to_string(),
            admin_root_cafile_path: "/etc/forge/carbide-bmc-proxy/site/admin_root_cert_pem"
                .to_string(),
        }
    }
}

/// Authentication related configuration
#[derive(Clone, Deserialize)]
pub struct AuthConfig {
    /// Additional nico-admin-cli certs allowed.  This does not include actually allowing the cert to connect, just that certs that can be verified which match these criteria can do GRPC requests.
    #[serde(default)]
    pub cli_certs: Option<AllowedCertCriteria>,

    /// Configuration for the root of trust for client cert auth
    #[serde(default = "Defaults::trust_config")]
    pub trust: TrustConfig,

    #[serde(default)]
    pub acls: AclConfig,
}

impl Config {
    pub fn parse(s: &str) -> Result<Config, ConfigError> {
        Figment::new()
            .merge(Toml::string(s))
            .merge(Env::prefixed("CARBIDE_BMC_PROXY_"))
            .extract()
            .map_err(Into::into)
    }
}
