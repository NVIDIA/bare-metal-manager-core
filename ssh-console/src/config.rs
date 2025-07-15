/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::bmc_vendor::BmcVendor;
use duration_str::deserialize_duration;
use eyre::Context;
use russh::keys::ssh_key::Fingerprint;
use serde::{Deserialize, Serialize, Serializer};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug)]
/// Configuration for ssh-console. Fields are documented as comments in the output of [`default_config_file`].
pub struct Config {
    pub listen_address: SocketAddr,
    pub carbide_uri: http::Uri,
    pub authorized_keys_path: Option<PathBuf>,
    pub host_key_path: PathBuf,
    pub override_bmcs: Option<Vec<BmcConfig>>,
    pub dpus: bool,
    pub insecure: bool,
    pub bmc_ssh_port: u16,
    pub ipmi_port: u16,
    pub insecure_ipmi_ciphers: bool,
    pub forge_root_ca_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub openssh_certificate_ca_fingerprints: Vec<Fingerprint>,
    pub admin_certificate_role: String,
    pub api_poll_interval: Duration,
    pub console_logging_enabled: bool,
    pub console_logs_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self::try_from(File::default()).expect("BUG: default config file can't be parsed?")
    }
}

impl Config {
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let cfg = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file at {}", path.display()))?;
        toml::from_str::<File>(&cfg)
            .with_context(|| format!("TOML error reading config file at {}", path.display()))?
            .try_into()
    }
}

pub fn default_config_file() -> String {
    let File {
        listen_address,
        authorized_keys_path: _,
        bmcs: _,
        host_key,
        dpus,
        insecure,
        carbide_url,
        bmc_ssh_port,
        ipmi_port,
        insecure_ipmi_ciphers,
        forge_root_ca_path,
        client_cert_path,
        client_key_path,
        openssh_certificate_ca_fingerprints,
        admin_certificate_role,
        api_poll_interval,
        console_logs_path,
        console_logging_enabled,
    } = File::default();
    let api_poll_interval = format!("{}s", api_poll_interval.as_secs());

    format!(
        r#"
#####
## This is a default config file for ssh-console. Everything in this file is optional: Any
## non-comment line in this file simply represents default values. Commented lines with a single `#`
## represent examples for optional configuration which is not part of the default config.
#####

## What address to listen on.
listen_address = {listen_address:?}

## Address for carbide-api
carbide_url = {carbide_url:?}

## Path to root CA cert for carbide-api
forge_root_ca_path = {forge_root_ca_path:?}

## Client cert path to communicate with carbide-api
client_cert_path = {client_cert_path:?}

## Client key path to communicate with carbide-api
client_key_path = {client_key_path:?}

## Path to the SSH host key path.
host_key = {host_key:?}

## Allow SSH'ing to DPU consoles
dpus = {dpus}

## Disable client SSH auth enforcement. This must NEVER be set in production: It forces all incoming
## client connections to succeed.
insecure = {insecure}

## Ports to use when connecting to BMC's
bmc_ssh_port = {bmc_ssh_port}
ipmi_port = {ipmi_port}

## Signing CA fingerprints for openssh certificates. Defaults to one that's valid for production
## nvinit certs
openssh_certificate_ca_fingerprints = {openssh_certificate_ca_fingerprints:?}

## Roles which determine admin access (logins with an openssh certificate, signed by the above
## fingerprints, containing this role in its Key ID, are considered admins and can log into machines
## directly.)
admin_certificate_role = {admin_certificate_role:?}

## If true, use insecure ciphers when connecting to IPMI, like SHA1. Useful for ipmi_sim.
insecure_ipmi_ciphers = {insecure_ipmi_ciphers}

## Optional: For development mode, gives keys that are authorized to connect to ssh-console. Meant
## for integration tests. For interactive use, consider using openssh certificates instead.
# authorized_keys_path = <path>

## How often to poll the carbide API server for what machines are available
api_poll_interval = {api_poll_interval:?}

## Whether to output the console data for each machine to a log file
console_logging_enabled = {console_logging_enabled:?}

## Where to write console logs for each machine, if enabled
console_logs_path = {console_logs_path:?}

## Optional: For development mode, you can hardcode a list of BMC's to talk to.
# [[bmcs]]
# # machine_id: the machine ID this BMC overrides
# machine_id = "fm100hteau2jdt69qg575qld4lj05me09u2qp7ei38uv7volvprkck9enkg"
# # instance_id: Optional, the instance_id to declare for this machine
# instance_id = "2020eb71-7674-4a15-a05b-c7d73da747b4"
# ip = "127.0.0.1"
# port = 22
# user = "user"                     # User to authenticate as when ssh-console connects to BMC
# password = "password"             # Password to use when ssh-console connects to BMC
# ssh_key_path = "/path/to/ssh_key" # Path to an SSH key to use when ssh-console connects to BMC (optional, overrides password.)
# bmc_vendor = "dell"               # Vendor for this BMC, determines connection behavior (currently supported: "dell", "lenovo", "hpe", "supermicro")
#
# # [[bmcs]]
# # ... more bmcs sections can define more than one
"#
    )
}

impl TryFrom<File> for Config {
    type Error = eyre::Error;

    fn try_from(file: File) -> eyre::Result<Self> {
        let openssh_certificate_ca_fingerprints = file
            .openssh_certificate_ca_fingerprints
            .into_iter()
            .map(|f| {
                Fingerprint::from_str(&f).with_context(|| {
                    format!("Invalid openssh CA fingerprint: {f:?}, expected <hash_alg>:<base64>")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            listen_address: file
                .listen_address
                .parse::<SocketAddr>()
                .context("Invalid listen_address")?,
            carbide_uri: file
                .carbide_url
                .as_str()
                .parse::<http::Uri>()
                .context("Invalid carbide_uri")?,
            authorized_keys_path: file.authorized_keys_path,
            host_key_path: file.host_key,
            override_bmcs: file.bmcs,
            dpus: file.dpus,

            insecure: file.insecure,
            bmc_ssh_port: file.bmc_ssh_port,
            ipmi_port: file.ipmi_port,
            insecure_ipmi_ciphers: file.insecure_ipmi_ciphers,
            forge_root_ca_path: file.forge_root_ca_path,
            client_cert_path: file.client_cert_path,
            client_key_path: file.client_key_path,
            openssh_certificate_ca_fingerprints,
            admin_certificate_role: file.admin_certificate_role,
            api_poll_interval: file.api_poll_interval,
            console_logs_path: file.console_logs_path,
            console_logging_enabled: file.console_logging_enabled,
        })
    }
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
struct File {
    #[serde(default = "Defaults::listen_address")]
    listen_address: String,
    #[serde(default = "Defaults::carbide_address")]
    carbide_url: String,
    #[serde(default)]
    authorized_keys_path: Option<PathBuf>,
    #[serde(default)]
    bmcs: Option<Vec<BmcConfig>>,
    #[serde(default = "Defaults::host_key_path")]
    host_key: PathBuf,
    #[serde(default)]
    dpus: bool,
    #[serde(default)]
    insecure: bool,
    #[serde(default = "Defaults::bmc_ssh_port")]
    bmc_ssh_port: u16,
    #[serde(default = "Defaults::ipmi_port")]
    ipmi_port: u16,
    #[serde(default)]
    insecure_ipmi_ciphers: bool,
    #[serde(default = "Defaults::root_ca_path")]
    forge_root_ca_path: PathBuf,
    #[serde(default = "Defaults::client_cert_path")]
    client_cert_path: PathBuf,
    #[serde(default = "Defaults::client_key_path")]
    client_key_path: PathBuf,
    #[serde(default = "Defaults::openssh_certificate_ca_fingerprints")]
    openssh_certificate_ca_fingerprints: Vec<String>,
    #[serde(default = "Defaults::admin_certificate_role")]
    admin_certificate_role: String,
    #[serde(
        default = "Defaults::api_poll_interval",
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    api_poll_interval: Duration,
    #[serde(default = "Defaults::console_logs_path")]
    console_logs_path: PathBuf,
    #[serde(default = "Defaults::console_logging_enabled")]
    console_logging_enabled: bool,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct BmcConfig {
    pub machine_id: String,
    pub instance_id: Option<String>,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub user: String,
    pub password: String,
    pub ssh_key_path: Option<PathBuf>,
    pub bmc_vendor: BmcVendor,
}

impl BmcConfig {
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port.unwrap_or(22))
    }
}

impl Default for File {
    fn default() -> Self {
        Self {
            listen_address: Defaults::listen_address(),
            host_key: Defaults::host_key_path(),
            carbide_url: Defaults::carbide_address(),
            bmc_ssh_port: Defaults::bmc_ssh_port(),
            ipmi_port: Defaults::ipmi_port(),
            forge_root_ca_path: Defaults::root_ca_path(),
            client_cert_path: Defaults::client_key_path(),
            client_key_path: Defaults::client_key_path(),
            admin_certificate_role: Defaults::admin_certificate_role(),
            openssh_certificate_ca_fingerprints: Defaults::openssh_certificate_ca_fingerprints(),
            api_poll_interval: Defaults::api_poll_interval(),
            console_logs_path: Defaults::console_logs_path(),
            console_logging_enabled: Defaults::console_logging_enabled(),
            authorized_keys_path: None,
            bmcs: None,
            dpus: false,
            insecure: false,
            insecure_ipmi_ciphers: false,
        }
    }
}

pub struct Defaults;

impl Defaults {
    pub fn listen_address() -> String {
        "[::]:22".to_string()
    }

    pub fn host_key_path() -> PathBuf {
        "/etc/ssh/ssh_host_ed25519_key".into()
    }

    pub fn carbide_address() -> String {
        "carbide-api.forge-system.svc.cluster.local:1079".to_string()
    }

    pub fn bmc_ssh_port() -> u16 {
        22
    }

    pub fn ipmi_port() -> u16 {
        623
    }

    pub fn root_ca_path() -> PathBuf {
        "/var/run/secrets/spiffe.io/ca.crt".into()
    }

    pub fn client_cert_path() -> PathBuf {
        "/var/run/secrets/spiffe.io/tls.crt".into()
    }

    pub fn client_key_path() -> PathBuf {
        "/var/run/secrets/spiffe.io/tls.key".into()
    }

    pub fn openssh_certificate_ca_fingerprints() -> Vec<String> {
        // Taken from working nvinit cert as of 2025-06-26. No idea how often this changes.
        vec!["SHA256:sPKzOUJwvkR3aCFf2oCyHnc+JoMtFcow2UxcEz+cXo4".to_string()]
    }

    pub fn admin_certificate_role() -> String {
        "swngc-forge-admins".to_string()
    }

    pub fn api_poll_interval() -> Duration {
        Duration::from_secs(180)
    }

    pub fn console_logs_path() -> PathBuf {
        "/var/log/ssh-console".into()
    }

    pub fn console_logging_enabled() -> bool {
        true
    }
}

fn serialize_duration<S>(d: &std::time::Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", d.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_file_is_actually_default() {
        let default_toml: File =
            toml::from_str(&default_config_file()).expect("default toml didn't parse");
        let default_file = File::default();
        assert_eq!(default_toml, default_file);
    }

    #[test]
    fn test_default_file_parses() {
        let default_file = File::default();
        Config::try_from(default_file).expect("default config file is invalid");
    }
}
