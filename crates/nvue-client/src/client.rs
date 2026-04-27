use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use reqwest::{Client, ClientBuilder, Method, Response, Url};
pub use serde_json::Value as JsonValue;

use crate::NvueConfig;
use crate::config::NvueRevision;

#[derive(Debug)]
pub struct NvueClient {
    server_address: NvueServerAddress,
    client: Client,
}

impl NvueClient {
    pub fn new(server_address: NvueServerAddress) -> Result<Self, NvueClientError> {
        build_client(&server_address).map(|client| Self {
            server_address,
            client,
        })
    }

    pub fn new_https_from_env() -> Result<Self, NvueClientError> {
        NvueServerAddress::https_from_env().and_then(Self::new)
    }

    // Construct a URL string using the internal server address and the
    // specified path.
    fn construct_url_string(&self, path: &str) -> String {
        let (scheme, address) = match &self.server_address {
            NvueServerAddress::UnixSocket { .. } => ("http", "localhost"),
            NvueServerAddress::TcpTls { address, .. } => ("https", address.as_str()),
        };
        format!("{scheme}://{address}{path}")
    }

    // Get the auth creds, if applicable.
    fn auth_creds(&self) -> Option<&NvueAuth> {
        match &self.server_address {
            NvueServerAddress::UnixSocket { .. } => None,
            NvueServerAddress::TcpTls { auth, .. } => auth.as_ref(),
        }
    }

    // Helper for constructing a request.
    fn request(
        &self,
        method: Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, NvueClientError> {
        let url = self.construct_url_string(path);
        let builder = self.client.request(method, url);
        let builder = match self.auth_creds() {
            Some(creds) => builder.basic_auth(&creds.username, Some(&creds.password)),
            None => builder,
        };
        Ok(builder)
    }

    async fn execute(&self, request: reqwest::Request) -> Result<Response, NvueClientError> {
        let method = request.method().clone();
        let url = request.url().clone();
        let body = request
            .body()
            .and_then(|b| b.as_bytes())
            .map(|b| String::from_utf8_lossy(b).into_owned());
        self.client
            .execute(request)
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|source| {
                NvueClientError::RequestFailed(Box::new(RequestFailed {
                    method,
                    url,
                    body,
                    source,
                }))
            })
    }

    pub async fn get_api(&self) -> Result<Response, NvueClientError> {
        const PATH: &str = "/nvue_v1/system/api?rev=applied";
        let request = self.request(Method::GET, PATH)?.build()?;
        self.execute(request).await
    }

    /// Return the config that is tagged as "applied" (in other words, the one
    /// that is currently running on the system).
    pub async fn get_applied_config(&self) -> Result<NvueConfig, NvueClientError> {
        const PATH: &str = "/nvue_v1/?rev=applied&filled=false";
        let request = self.request(Method::GET, PATH)?.build()?;
        let response = self.execute(request).await?;
        let nvue_config = response.json().await?;
        Ok(nvue_config)
    }

    /// Create a new NVUE config revision, returning the revision ID.
    pub async fn create_config_revision(&self) -> Result<String, NvueClientError> {
        const PATH: &str = "/nvue_v1/revision";
        let request = self.request(Method::POST, PATH)?.build()?;
        let response = self.execute(request).await?;
        let revision: NvueRevision = response.json().await?;
        let revision_id = revision
            .get_revision_id()
            .ok_or(NvueClientError::SchemaMismatch("Missing revision id"))?;
        Ok(revision_id)
    }

    /// Replace the specified config revision. Under the hood, this is a
    /// two-stage operation where the configuration is deleted and then new
    /// values are inserted.
    pub async fn replace_config_revision(
        &self,
        revision_id: &str,
        config: &NvueConfig,
    ) -> Result<(), NvueClientError> {
        let revision_path = format!("/nvue_v1/?rev={revision_id}");

        let builder = self.request(Method::DELETE, &revision_path)?;
        let empty_config: HashMap<String, String> = HashMap::new();
        let builder = builder.json(&empty_config);
        let request = builder.build()?;
        let _response = self.execute(request).await?;

        let builder = self.request(Method::PATCH, &revision_path)?;
        let mut config = config.clone();
        // Just in case the config we got was derived from an older one,
        // let's clear the rev-id from the header.
        config.remove_rev_id();
        let builder = builder.json(&config);
        let request = builder.build()?;
        let _response = self.execute(request).await?;
        Ok(())
    }

    pub async fn apply_config_revision(&self, revision_id: &str) -> Result<(), NvueClientError> {
        let revision_path = format!("/nvue_v1/revision/{revision_id}");
        let builder = self.request(Method::PATCH, &revision_path)?;
        let body = NvueApplyData::force_apply();
        let builder = builder.json(&body);
        let request = builder.build()?;
        let _response = self.execute(request).await?;

        // FIXME: we should poll on the revision path until it reaches an
        // "applied" state
        Ok(())
    }

    /// Create a new configuration using the values from `config`, then  apply
    /// it, returning the revision ID. This is a convenience method that
    /// creates, replaces, and then applies the configuration (which a caller
    /// could do manually if more control is desired).
    pub async fn push_config(&self, config: &NvueConfig) -> Result<String, NvueClientError> {
        let revision_id = self.create_config_revision().await?;
        self.replace_config_revision(&revision_id, config).await?;
        self.apply_config_revision(&revision_id).await?;
        Ok(revision_id)
    }

    // Retrieve the system information from the NVUE server. The fields returned
    // seem to vary depending on which platform NVUE is running on, so we just
    // return a JSON value.
    pub async fn system_info(&self) -> Result<JsonValue, NvueClientError> {
        let path = "/nvue_v1/system";
        let builder = self.request(Method::GET, path)?;
        let request = builder.build()?;
        let response = self.execute(request).await?;
        let resonse_body = response.json().await?;
        Ok(resonse_body)
    }

    /// Using the system_info() method, try to extract the value of the "build"
    /// key from the system info.
    pub async fn system_build_info(&self) -> Result<String, NvueClientError> {
        let system = self.system_info().await?;
        let system_object = match system {
            JsonValue::Object(map) => Ok(map),
            _ => {
                let msg = "System info is not a JSON object";
                Err(NvueClientError::SchemaMismatch(msg))
            }
        }?;
        let build = system_object.get("build").ok_or({
            let msg = "System info object has no \"build\" key";
            NvueClientError::SchemaMismatch(msg)
        })?;
        let build_value = match build {
            JsonValue::String(value) => Ok(value),
            _ => {
                let msg = "System info \"build\" value was not a string";
                Err(NvueClientError::SchemaMismatch(msg))
            }
        }?;
        Ok(build_value.into())
    }

    /// Get the MAC table for a bridge.
    pub async fn bridge_mac_table(
        &self,
        bridge_domain: &str,
    ) -> Result<Vec<crate::types::MacTableEntry>, NvueClientError> {
        let path = format!("/nvue_v1/bridge/domain/{bridge_domain}/mac-table");
        let builder = self.request(Method::GET, &path)?;
        let request = builder.build()?;
        let response = self.execute(request).await?;
        let resonse_body: BTreeMap<String, _> = response.json().await?;
        let response = resonse_body.into_values().collect();
        Ok(response)
    }
}

fn build_client(server_address: &NvueServerAddress) -> Result<Client, NvueClientError> {
    let builder = ClientBuilder::new().default_headers(default_nvue_headers());
    let builder = match server_address {
        NvueServerAddress::UnixSocket { socket_path } => builder.unix_socket(socket_path.as_path()),
        NvueServerAddress::TcpTls { .. } => {
            // NVUE uses a self-signed cert out of the box.
            builder.danger_accept_invalid_certs(true)
        }
    };
    builder.build().map_err(NvueClientError::from)
}

#[derive(Debug, serde::Serialize)]
struct NvueApplyData {
    state: String,
    #[serde(rename = "auto-prompt")]
    auto_prompt: NvueAutoPrompt,
}

impl NvueApplyData {
    pub fn force_apply() -> Self {
        let state = "apply".into();
        let auto_prompt = NvueAutoPrompt::ays_yes();
        Self { state, auto_prompt }
    }
}

#[derive(Debug, serde::Serialize)]
// This controls what NVUE does with configurations where the validator produced
// warnings or errors.
struct NvueAutoPrompt {
    ays: String,
}

impl NvueAutoPrompt {
    pub fn ays_yes() -> Self {
        let ays = "ays_yes".into();
        Self { ays }
    }
}

fn default_nvue_headers() -> HeaderMap {
    HeaderMap::from_iter([(ACCEPT, HeaderValue::from_static("application/json"))])
}

#[derive(Debug)]
pub enum NvueServerAddress {
    UnixSocket {
        socket_path: PathBuf,
    },
    TcpTls {
        address: String,
        auth: Option<NvueAuth>,
    },
}

impl NvueServerAddress {
    /// Construct the server address using an undocumented internal Unix socket,
    /// which sidesteps authentication entirely but may not be available unless
    /// you're on the same host as the server.
    pub fn default_unix_socket() -> Self {
        let socket_path = "/run/nvue/nvue.sock".into();
        Self::UnixSocket { socket_path }
    }

    /// Construct the server address using values from the environment.
    /// `NVUE_HTTPS_ADDRESS` should just be the address part of the URL, so
    /// something like `localhost:8765`. `NVUE_USERNAME` and `NVUE_PASSWORD`
    /// should contain the username and password used during HTTP basic auth to
    /// the API.
    pub fn https_from_env() -> Result<Self, NvueClientError> {
        let address = get_nvue_envvar("NVUE_HTTPS_ADDRESS")?;
        let username = get_nvue_envvar("NVUE_USERNAME")?;
        let password = get_nvue_envvar("NVUE_PASSWORD")?;
        let auth = Some(NvueAuth { username, password });
        Ok(Self::TcpTls { address, auth })
    }
}

fn get_nvue_envvar(var: &'static str) -> Result<String, NvueClientError> {
    std::env::var(var).map_err(|e| NvueClientError::EnvVarError(var, e))
}

pub struct NvueAuth {
    username: String,
    password: String,
}

impl std::fmt::Debug for NvueAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NvueAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NvueClientError {
    #[error("Reqwest client error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    RequestFailed(Box<RequestFailed>),

    #[error("Environment variable error ({0}): {1}")]
    EnvVarError(&'static str, std::env::VarError),

    #[error("Schema mismatch between NVUE client and server: {0}")]
    SchemaMismatch(&'static str),
}

#[derive(thiserror::Error, Debug)]
#[error("NVUE request failed ({method} {url}{}): {source}",
    body.as_deref().map(|b| format!(" body={b}")).unwrap_or_default())]
pub struct RequestFailed {
    pub method: Method,
    pub url: Url,
    pub body: Option<String>,
    #[source]
    pub source: reqwest::Error,
}
