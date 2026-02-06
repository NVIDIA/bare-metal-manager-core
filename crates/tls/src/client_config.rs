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
use std::path::Path;
use std::str::FromStr;
use std::{env, fs, io};

use serde::Deserialize;
use tonic::transport::Uri;

use crate::default as tls_default;

#[derive(thiserror::Error, Debug)]
pub enum ClientConfigError {
    #[error("Unable to parse url: {0}")]
    UrlParseError(String),
}

#[derive(Clone, Debug)]
pub struct ClientCert {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize)]
pub struct FileConfig {
    pub carbide_api_url: Option<String>,
    pub forge_root_ca_path: Option<String>,
    pub client_key_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub rms_root_ca_path: Option<String>,
}

pub fn get_carbide_api_url(
    carbide_api: Option<String>,
    file_config: Option<&FileConfig>,
) -> String {
    // First from command line, second env var.
    if let Some(carbide_api) = carbide_api {
        return carbide_api;
    }

    // Third config file
    if let Some(file_config) = file_config
        && let Some(carbide_api_url) = file_config.carbide_api_url.as_ref()
    {
        return carbide_api_url.clone();
    }

    // Otherwise we assume the admin-cli is called from inside a kubernetes pod
    "https://carbide-api.forge-system.svc.cluster.local:1079".to_string()
}

pub fn get_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    file_config: Option<&FileConfig>,
) -> ClientCert {
    // First from command line, second env var.
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return ClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        };
    }

    // Third config file
    if let Some(file_config) = file_config
        && let (Some(client_key_path), Some(client_cert_path)) = (
            file_config.client_key_path.as_ref(),
            file_config.client_cert_path.as_ref(),
        )
    {
        return ClientCert {
            cert_path: client_cert_path.clone(),
            key_path: client_key_path.clone(),
        };
    }

    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return ClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        };
    }

    // this is the location for most compiled clients executing on x86 hosts or DPUs
    if Path::new(tls_default::CLIENT_CERT).exists() && Path::new(tls_default::CLIENT_KEY).exists() {
        return ClientCert {
            cert_path: tls_default::CLIENT_CERT.to_string(),
            key_path: tls_default::CLIENT_KEY.to_string(),
        };
    }

    // and this is the location for developers executing from within carbide's repo
    if let Ok(project_root) = env::var("REPO_ROOT") {
        //TODO: actually fix this cert and give it one that's valid for like 10 years.
        let cert_path = format!("{project_root}/dev/certs/server_identity.pem");
        let key_path = format!("{project_root}/dev/certs/server_identity.key");
        if Path::new(cert_path.as_str()).exists() && Path::new(key_path.as_str()).exists() {
            return ClientCert {
                cert_path,
                key_path,
            };
        }
    }

    // if you make it here, you'll just have to tell me where the client cert is.
    panic!(
        r###"Unknown client cert location. Set (will be read in same sequence.)
           1. --client-cert-path and --client-key-path flag or
           2. environment variables CLIENT_KEY_PATH and CLIENT_CERT_PATH or
           3. add client_key_path and client_cert_path in $HOME/.config/carbide_api_cli.json.
           4. a file existing at "/var/run/secrets/spiffe.io/tls.crt" and "/var/run/secrets/spiffe.io/tls.key".
           5. a file existing at "{}" and "{}".
           6. a file existing at "$REPO_ROOT/dev/certs/server_identity.pem" and "$REPO_ROOT/dev/certs/server_identity.key."###,
        tls_default::CLIENT_CERT,
        tls_default::CLIENT_KEY
    )
}

pub fn get_forge_root_ca_path(
    forge_root_ca_path: Option<String>,
    file_config: Option<&FileConfig>,
) -> String {
    // First from command line, second env var.
    if let Some(forge_root_ca_path) = forge_root_ca_path {
        return forge_root_ca_path;
    }

    // Third config file
    if let Some(file_config) = file_config
        && let Some(forge_root_ca_path) = file_config.forge_root_ca_path.as_ref()
    {
        return forge_root_ca_path.clone();
    }

    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/ca.crt").exists() {
        return "/var/run/secrets/spiffe.io/ca.crt".to_string();
    }

    // this is the location for most compiled clients executing on x86 hosts or DPUs
    if Path::new(tls_default::ROOT_CA).exists() {
        return tls_default::ROOT_CA.to_string();
    }

    // and this is the location for developers executing from within carbide's repo
    if let Ok(project_root) = env::var("REPO_ROOT") {
        let path = format!("{project_root}/dev/certs/localhost/ca.crt");
        if Path::new(path.as_str()).exists() {
            return path;
        }
    }

    // if you make it here, you'll just have to tell me where the root CA is.
    panic!(
        r###"Unknown FORGE_ROOT_CA_PATH. Set (will be read in same sequence.)
           1. --forge-root-ca-path flag or
           2. environment variable FORGE_ROOT_CA_PATH or
           3. add forge_root_ca_path in $HOME/.config/carbide_api_cli.json.
           4. a file existing at "/var/run/secrets/spiffe.io/ca.crt".
           5. a file existing at "{}".
           6. a file existing at "$REPO_ROOT/dev/certs/forge_developer_local_only_root_cert_pem"."###,
        tls_default::ROOT_CA
    )
}

pub fn get_config_from_file() -> Option<FileConfig> {
    // Third config file
    if let Ok(home) = env::var("HOME") {
        let file = Path::new(&home).join(".config/carbide_api_cli.json");
        if file.exists() {
            let file = fs::File::open(file).unwrap();
            let reader = io::BufReader::new(file);
            let file_config: FileConfig = serde_json::from_reader(reader).unwrap();

            return Some(file_config);
        }
    }

    None
}

pub fn get_proxy_info() -> Result<Option<String>, ClientConfigError> {
    std::env::var("http_proxy")
        .ok()
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("HTTP_PROXY").ok())
        .or_else(|| std::env::var("HTTPS_PROXY").ok())
        .map_or(Ok(None), |proxy| {
            let uri = Uri::from_str(&proxy).map_err(|_| ClientConfigError::UrlParseError(proxy))?;
            if uri
                .scheme_str()
                .is_some_and(|s| !s.eq_ignore_ascii_case("socks5"))
            {
                return Err(ClientConfigError::UrlParseError(
                    "Only SOCKS5 Proxy supported".to_owned(),
                ));
            }
            let host = uri.host().map_or("".to_owned(), |h| h.to_owned());
            let port = uri
                .port_u16()
                .map_or("".to_owned(), |port| port.to_string());
            if host.is_empty() {
                Ok(None)
            } else {
                Ok(Some(host + ":" + &port))
            }
        })
}
