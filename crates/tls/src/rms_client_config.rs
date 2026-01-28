use std::env;
use std::path::Path;

use crate::client_config::{ClientCert, FileConfig};
use crate::default as tls_default;

// No file support for now
pub fn get_rms_api_url(rms_api_url: Option<String>) -> String {
    // First from command line, second env var.
    if let Some(rms_api_url) = rms_api_url {
        return rms_api_url;
    }
    "http://rms-api-server.rack-manager:8801".to_string()
}

pub fn rms_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
) -> Option<ClientCert> {
    // First from command line
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return Some(ClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        });
    }

    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return Some(ClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        });
    }

    // this is the location for most compiled clients executing on x86 hosts or DPUs
    if Path::new(tls_default::CLIENT_CERT).exists() && Path::new(tls_default::CLIENT_KEY).exists() {
        return Some(ClientCert {
            cert_path: tls_default::CLIENT_CERT.to_string(),
            key_path: tls_default::CLIENT_KEY.to_string(),
        });
    }

    // and this is the location for developers executing from within carbide's repo
    if let Ok(project_root) = env::var("REPO_ROOT") {
        let cert_path = format!("{}/dev/certs/server_identity.pem", project_root);
        let key_path = format!("{}/dev/certs/server_identity.key", project_root);
        if Path::new(cert_path.as_str()).exists() && Path::new(key_path.as_str()).exists() {
            return Some(ClientCert {
                cert_path,
                key_path,
            });
        }
    }

    // RMS client cert is optional - if not found, return None instead of panicking
    None
}

pub fn rms_root_ca_path(
    rms_root_ca_path: Option<String>,
    file_config: Option<&FileConfig>,
) -> String {
    // First from command line, second env var.
    if let Some(rms_root_ca_path) = rms_root_ca_path {
        return rms_root_ca_path;
    }

    // Second config file
    if let Some(file_config) = file_config
        && let Some(rms_root_ca_path) = file_config.rms_root_ca_path.as_ref()
        && Path::new(rms_root_ca_path).exists()
    {
        return rms_root_ca_path.clone();
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
        let path = format!("{}/dev/certs/localhost/ca.crt", project_root);
        if Path::new(path.as_str()).exists() {
            return path;
        }
    }

    panic!(
        r###"Unknown RMS Root CA path. Set (will be read in same sequence.)
           1. Use --rms-root-ca-path CLI option or RMS_ROOT_CA_PATH env var, or
           2. add rms_root_ca_path in $HOME/.config/carbide_api_cli.json, or
           3. a file existing at "/var/run/secrets/spiffe.io/ca.crt" or
           4. a file existing at "{}" or
           5. a file existing at "$REPO_ROOT/dev/certs/localhost/ca.crt"."###,
        tls_default::ROOT_CA
    )
}
