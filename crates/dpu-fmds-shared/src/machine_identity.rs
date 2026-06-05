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

//! IMDS-style `GET …/meta-data/identity` (shared between carbide-agent and carbide-fmds).
//!
//! Defaults and numeric bounds are in [`forge_dpu_agent_utils::machine_identity`] (`defaults`, `limits`;
//! the latter is also used by carbide-host-support validation).

use std::convert::TryFrom;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::http::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use forge_dpu_agent_utils::machine_identity::defaults::{
    BURST, REQUESTS_PER_SECOND, SIGN_TIMEOUT_SECS, WAIT_TIMEOUT_SECS,
};
use forge_dpu_agent_utils::machine_identity::limits::{
    BURST_MAX, BURST_MIN, REQUESTS_PER_SECOND_MAX, REQUESTS_PER_SECOND_MIN, SIGN_TIMEOUT_SECS_MAX,
    SIGN_TIMEOUT_SECS_MIN, WAIT_TIMEOUT_SECS_MAX, WAIT_TIMEOUT_SECS_MIN,
};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter, clock};
use rpc::fmds::FmdsMachineIdentityConfig;
use rpc::forge::MachineIdentityResponse;

/// `meta-data` leaf name for machine identity (`…/meta-data/identity`).
pub const META_DATA_IDENTITY_CATEGORY: &str = "identity";

/// Upstream path appended to `sign-proxy-url` for HTTP pass-through (`{base}/latest/...`).
pub const SIGN_PROXY_UPSTREAM_IMDS_PREFIX: &str = "latest/meta-data/identity";

/// Validated, normalized machine-identity limits.
///
/// Construct only through [`Self::try_from_limits`], [`TryFrom`] from `FmdsMachineIdentityConfig`,
/// or [`Default`] (known-good defaults, aligned with agent `MachineIdentityConfig` serde).
///
/// ## What is validated where
///
/// - [`MachineIdentityParams::try_from_limits`] and [`TryFrom`] from [`FmdsMachineIdentityConfig`]:
///   numeric ranges, trim/empty normalization for proxy URL and TLS root CA path, and the rule that a CA
///   path requires a proxy URL.
/// - **Agent `MachineIdentityConfig::validate()`** (carbide-host-support): the above bounds **plus** HTTP(S)
///   scheme checks for `sign-proxy-url`, PEM file readability/parsing for `sign-proxy-tls-root-ca`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentityParams {
    pub requests_per_second: u8,
    pub burst: u8,
    pub wait_timeout_secs: u8,
    pub sign_timeout_secs: u8,
    pub sign_proxy_url: Option<String>,
    pub sign_proxy_tls_root_ca: Option<String>,
}

impl Default for MachineIdentityParams {
    /// Matches [`forge_dpu_agent_utils::machine_identity::defaults`] (agent `MachineIdentityConfig`
    /// serde and this crate).
    fn default() -> Self {
        Self {
            requests_per_second: REQUESTS_PER_SECOND,
            burst: BURST,
            wait_timeout_secs: WAIT_TIMEOUT_SECS,
            sign_timeout_secs: SIGN_TIMEOUT_SECS,
            sign_proxy_url: None,
            sign_proxy_tls_root_ca: None,
        }
    }
}

impl MachineIdentityParams {
    /// Single normalization path: range checks (see [`limits`]), trim,
    /// empty→`None`, and CA path requires proxy URL.
    ///
    /// Call after agent **`MachineIdentityConfig::validate()`** for file-backed config, or use
    /// [`TryFrom`] with `&FmdsMachineIdentityConfig` and [`From`] / `.into()` into [`FmdsMachineIdentityConfig`] for the FMDS boundary.
    pub fn try_from_limits(
        requests_per_second: u8,
        burst: u8,
        wait_timeout_secs: u8,
        sign_timeout_secs: u8,
        sign_proxy_url: Option<&str>,
        sign_proxy_tls_root_ca: Option<&str>,
    ) -> Result<Self, String> {
        if !(REQUESTS_PER_SECOND_MIN..=REQUESTS_PER_SECOND_MAX).contains(&requests_per_second) {
            return Err(format!(
                "machine-identity.requests-per-second: must be between {REQUESTS_PER_SECOND_MIN} and {REQUESTS_PER_SECOND_MAX} (inclusive)"
            ));
        }
        if !(BURST_MIN..=BURST_MAX).contains(&burst) {
            return Err(format!(
                "machine-identity.burst: must be between {BURST_MIN} and {BURST_MAX} (inclusive)"
            ));
        }
        if !(WAIT_TIMEOUT_SECS_MIN..=WAIT_TIMEOUT_SECS_MAX).contains(&wait_timeout_secs) {
            return Err(format!(
                "machine-identity.wait-timeout-secs: must be between {WAIT_TIMEOUT_SECS_MIN} and {WAIT_TIMEOUT_SECS_MAX} (inclusive)"
            ));
        }
        if !(SIGN_TIMEOUT_SECS_MIN..=SIGN_TIMEOUT_SECS_MAX).contains(&sign_timeout_secs) {
            return Err(format!(
                "machine-identity.sign-timeout-secs: must be between {SIGN_TIMEOUT_SECS_MIN} and {SIGN_TIMEOUT_SECS_MAX} (inclusive)"
            ));
        }

        let sign_proxy_url = sign_proxy_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let sign_proxy_tls_root_ca = sign_proxy_tls_root_ca
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        if sign_proxy_url.is_none() && sign_proxy_tls_root_ca.is_some() {
            return Err(
                "machine-identity.sign-proxy-tls-root-ca: requires machine-identity.sign-proxy-url"
                    .to_string(),
            );
        }

        Ok(Self {
            requests_per_second,
            burst,
            wait_timeout_secs,
            sign_timeout_secs,
            sign_proxy_url,
            sign_proxy_tls_root_ca,
        })
    }
}

impl From<MachineIdentityParams> for FmdsMachineIdentityConfig {
    fn from(p: MachineIdentityParams) -> Self {
        Self {
            requests_per_second: u32::from(p.requests_per_second),
            burst: u32::from(p.burst),
            wait_timeout_secs: u32::from(p.wait_timeout_secs),
            sign_timeout_secs: u32::from(p.sign_timeout_secs),
            sign_proxy_url: p.sign_proxy_url,
            sign_proxy_tls_root_ca: p.sign_proxy_tls_root_ca,
        }
    }
}

impl TryFrom<&FmdsMachineIdentityConfig> for MachineIdentityParams {
    type Error = String;

    fn try_from(p: &FmdsMachineIdentityConfig) -> Result<Self, Self::Error> {
        let requests_per_second = u8::try_from(p.requests_per_second).map_err(|_| {
            "machine-identity.requests-per-second: does not fit in u8 (proto field requests_per_second)"
                .to_string()
        })?;
        let burst = u8::try_from(p.burst).map_err(|_| {
            "machine-identity.burst: does not fit in u8 (proto field burst)".to_string()
        })?;
        let wait_timeout_secs = u8::try_from(p.wait_timeout_secs).map_err(|_| {
            "machine-identity.wait-timeout-secs: does not fit in u8 (proto field wait_timeout_secs)"
                .to_string()
        })?;
        let sign_timeout_secs = u8::try_from(p.sign_timeout_secs).map_err(|_| {
            "machine-identity.sign-timeout-secs: does not fit in u8 (proto field sign_timeout_secs)"
                .to_string()
        })?;

        Self::try_from_limits(
            requests_per_second,
            burst,
            wait_timeout_secs,
            sign_timeout_secs,
            p.sign_proxy_url.as_deref(),
            p.sign_proxy_tls_root_ca.as_deref(),
        )
    }
}

/// Rate limiting, timeouts, and optional HTTP sign-proxy client for `GET …/meta-data/identity`.
#[derive(Debug)]
pub struct MachineIdentityServing {
    pub governor: Arc<IdentityRateLimiter>,
    pub wait_timeout: Duration,
    pub forge_call_timeout: Duration,
    pub sign_proxy_base: Option<String>,
    pub sign_proxy_http_client: Option<reqwest::Client>,
}

impl MachineIdentityServing {
    /// Defaults match [`MachineIdentityParams::default`].
    pub fn try_default() -> Result<Self, String> {
        Self::try_from_params(MachineIdentityParams::default())
    }

    /// Builds serving state from parsed [`MachineIdentityParams`] (via [`MachineIdentityParams::try_from_limits`]
    /// or `TryFrom<&FmdsMachineIdentityConfig>`). Input must already be normalized (trimmed option strings).
    pub fn try_from_params(params: MachineIdentityParams) -> Result<Self, String> {
        let rps = NonZeroU32::new(u32::from(params.requests_per_second)).ok_or_else(|| {
            "machine-identity.requests-per-second: expected a positive value (internal error)"
                .to_string()
        })?;
        let burst_nz = NonZeroU32::new(u32::from(params.burst)).ok_or_else(|| {
            "machine-identity.burst: expected a positive value (internal error)".to_string()
        })?;
        let identity_quota = Quota::per_second(rps).allow_burst(burst_nz);

        let sign_proxy_base = params.sign_proxy_url.clone();
        let call_timeout = Duration::from_secs(u64::from(params.sign_timeout_secs));
        let sign_proxy_http_client = if sign_proxy_base.is_some() {
            Some(build_sign_proxy_http_client(
                call_timeout,
                params.sign_proxy_tls_root_ca.as_deref(),
            )?)
        } else {
            None
        };

        Ok(Self {
            governor: Arc::new(RateLimiter::direct(identity_quota)),
            wait_timeout: Duration::from_secs(u64::from(params.wait_timeout_secs)),
            forge_call_timeout: call_timeout,
            sign_proxy_base,
            sign_proxy_http_client,
        })
    }
}

/// `governor::RateLimiter` used for `GET …/meta-data/identity` (carbide-agent + carbide-fmds).
pub type IdentityRateLimiter =
    RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>;

/// Wait for an IMDS machine-identity rate-limit permit (bounded by `wait_timeout`).
///
/// Returns [`Err`] with [`tokio::time::error::Elapsed`] when waiting exceeds `wait_timeout`.
pub async fn wait_identity_rate_limit_permit(
    governor: &Arc<IdentityRateLimiter>,
    wait_timeout: Duration,
) -> Result<(), tokio::time::error::Elapsed> {
    let lim = Arc::clone(governor);
    tokio::time::timeout(wait_timeout, lim.until_ready()).await?;
    Ok(())
}

/// Call Carbide `SignMachineIdentity` using [`forge_dpu_agent_utils::utils::create_forge_client`] and
/// `machine_identity.sign_timeout_secs` as the overall deadline.
pub async fn sign_machine_identity_with_forge(
    forge_api: &str,
    forge_client_config: &rpc::forge_tls_client::ForgeClientConfig,
    call_timeout: Duration,
    audiences: Vec<String>,
) -> Result<MachineIdentityResponse, tonic::Status> {
    use rpc::forge::MachineIdentityRequest;

    tokio::time::timeout(call_timeout, async {
        let mut client =
            forge_dpu_agent_utils::utils::create_forge_client(forge_api, forge_client_config)
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
        client
            .sign_machine_identity(MachineIdentityRequest {
                audience: audiences,
            })
            .await
            .map(|r| r.into_inner())
    })
    .await
    .map_err(|_| {
        tonic::Status::deadline_exceeded(
            "timed out calling Forge for machine identity (machine-identity.sign-timeout-secs)",
        )
    })?
}

/// Result of [`MetaDataIdentitySigner::machine_identity_response`] and
/// [`MetaDataIdentitySigner::rate_limited_identity_request`]: HTTP sign-proxy response, or
/// Forge payload to build the JSON/text identity body.
pub enum MetaDataIdentityOutcome {
    /// Response from the HTTP sign-proxy (`sign-proxy-url`).
    HttpProxy(Response),
    /// Successful `SignMachineIdentity` result to encode for the client.
    Forge(MachineIdentityResponse),
}

#[async_trait]
pub trait MetaDataIdentitySigner: Send + Sync {
    /// Acquire a rate-limit permit before [`Self::machine_identity_response`].
    async fn wait_identity_permit(&self) -> Result<(), tonic::Status>;

    /// HTTP sign-proxy (if configured), otherwise Carbide `SignMachineIdentity` with `audiences`.
    ///
    /// Implementations should try the sign-proxy first when enabled, then fall back to Forge.
    /// Hold any `Arc`/lock guard across `.await` so sign-proxy config borrows stay valid (see
    /// [`forward_sign_proxy_if_ready`] / [`forward_sign_proxy_http`]).
    async fn machine_identity_response(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
        audiences: Vec<String>,
    ) -> Result<MetaDataIdentityOutcome, tonic::Status>;

    /// Waits for rate-limit capacity, then runs [`Self::machine_identity_response`].
    ///
    /// Default implementation encodes the required ordering; override only if you preserve the same
    /// policy (permit before proxy or Carbide).
    async fn rate_limited_identity_request(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<MetaDataIdentityOutcome, tonic::Status> {
        self.wait_identity_permit().await?;
        let audiences = parse_identity_audiences(uri);
        self.machine_identity_response(uri, headers, audiences)
            .await
    }
}

/// Parses repeated `aud` query parameters (URL-decoded).
pub fn parse_identity_audiences(uri: &Uri) -> Vec<String> {
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| k == "aud")
        .map(|(_, v)| v.into_owned())
        .collect()
}

pub fn metadata_header_is_true(headers: &HeaderMap) -> bool {
    headers
        .get("metadata")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("true"))
}

pub fn accept_text_plain(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| {
            a.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("text/plain"))
        })
}

/// HTTP status for failed machine-identity signing (Carbide / implementation errors on the IMDS path).
///
/// gRPC status codes from Carbide are all map to **503 Service Unavailable**
/// The exception is **429 Too Many Requests** for [`tonic::Code::ResourceExhausted`],
/// used for identity rate-limit wait timeouts in this crate.
///
/// The returned message is safe to expose to IMDS clients; details are logged at `WARN`.
pub fn map_machine_identity_signing_error_to_http(status: &tonic::Status) -> (StatusCode, String) {
    use tonic::Code;
    match status.code() {
        Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, status.message().to_string()),
        code => {
            tracing::warn!(
                ?code,
                message = %status.message(),
                "machine-identity: upstream signing failed"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "machine identity signing is temporarily unavailable\n".to_string(),
            )
        }
    }
}

pub fn build_sign_proxy_http_client(
    timeout: Duration,
    root_ca_pem_path: Option<&str>,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(path) = root_ca_pem_path {
        let pem = std::fs::read(path).map_err(|e| {
            format!("machine-identity.sign-proxy-tls-root-ca: failed to read {path}: {e}")
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            format!("machine-identity.sign-proxy-tls-root-ca: invalid PEM in {path}: {e}")
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| format!("machine-identity.sign-proxy-url: failed to build HTTP client ({e})"))
}

pub fn build_sign_proxy_request_url(base_url: &str, query: Option<&str>) -> Result<String, String> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("machine-identity.sign-proxy-url: base URL is empty".to_string());
    }
    let q = query
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    Ok(format!("{base}/{SIGN_PROXY_UPSTREAM_IMDS_PREFIX}{q}"))
}

pub async fn forward_sign_proxy_http(
    client: &reqwest::Client,
    base_url: &str,
    request_uri: &Uri,
    headers: &HeaderMap,
) -> Response {
    let upstream_url = match build_sign_proxy_request_url(base_url, request_uri.query()) {
        Ok(u) => u,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    tracing::debug!(%upstream_url, "forwarding machine identity request to HTTP sign proxy");

    let mut req = client.get(upstream_url);
    if let Some(v) = headers.get("metadata")
        && let Ok(s) = v.to_str()
    {
        req = req.header("Metadata", s);
    }
    if let Some(v) = headers.get(ACCEPT)
        && let Ok(s) = v.to_str()
    {
        req = req.header(ACCEPT, s);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let code = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return (code, e.to_string()).into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok());

    let body_bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };

    let mut res = Response::builder().status(status);
    if let Some(ct) = content_type {
        res = res.header(CONTENT_TYPE, ct);
    }
    match res.body(axum::body::Body::from(body_bytes)) {
        Ok(r) => r,
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("machine-identity.sign-proxy-url: failed to build HTTP response ({e})"),
        )
            .into_response(),
    }
}

/// When `sign-proxy-url` is configured (`sign_proxy_base` is [`Some`]), forward the identity request
/// to the HTTP sign proxy. Returns [`None`] when sign-proxy is not in use (caller should use Forge).
///
/// If the base URL is set but `sign_proxy_http_client` is missing, returns [`Some`] with HTTP 500
/// (misconfiguration).
pub async fn forward_sign_proxy_if_ready(
    sign_proxy_base: Option<&str>,
    sign_proxy_http_client: Option<&reqwest::Client>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<Response> {
    let base = sign_proxy_base?;
    let Some(client) = sign_proxy_http_client else {
        return Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "machine-identity.sign-proxy-url: HTTP client is not configured\n",
            )
                .into_response(),
        );
    };
    Some(forward_sign_proxy_http(client, base, uri, headers).await)
}

#[derive(serde::Serialize)]
struct IdentityTokenJsonBody {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    expires_in: u32,
}

pub async fn serve_meta_data_identity<S: MetaDataIdentitySigner + ?Sized>(
    signer: &S,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if !metadata_header_is_true(&headers) {
        return (
            StatusCode::BAD_REQUEST,
            "Metadata: true header is required for meta-data/identity\n",
        )
            .into_response();
    }

    match signer.rate_limited_identity_request(&uri, &headers).await {
        Ok(MetaDataIdentityOutcome::HttpProxy(resp)) => resp,
        Ok(MetaDataIdentityOutcome::Forge(resp)) => {
            let body = IdentityTokenJsonBody {
                access_token: resp.access_token,
                issued_token_type: resp.issued_token_type,
                token_type: resp.token_type,
                expires_in: resp.expires_in_sec,
            };
            let json = match serde_json::to_string(&body) {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("machine-identity: failed to serialize identity response ({e})"),
                    )
                        .into_response();
                }
            };

            let content_type = if accept_text_plain(&headers) {
                "text/plain; charset=utf-8"
            } else {
                "application/json"
            };
            let mut res = (StatusCode::OK, json).into_response();
            res.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(content_type),
            );
            res
        }
        Err(e) => {
            let (code, body) = map_machine_identity_signing_error_to_http(&e);
            (code, body).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use http_body_util::BodyExt;

    use super::*;

    #[test]
    fn parse_identity_audiences_repeated_and_decoded() {
        let uri: Uri = "http://127.0.0.1/latest/meta-data/identity?aud=spiffe%3A%2F%2Fa&aud=b"
            .parse()
            .unwrap();
        assert_eq!(
            parse_identity_audiences(&uri),
            vec!["spiffe://a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn map_machine_identity_signing_error_resource_exhausted_is_429_with_message() {
        let s = tonic::Status::resource_exhausted("rate limit wait");
        let (code, body) = map_machine_identity_signing_error_to_http(&s);
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, "rate limit wait");
    }

    #[test]
    fn map_machine_identity_signing_error_permission_denied_is_503_generic() {
        let s = tonic::Status::permission_denied("internal detail");
        let (code, body) = map_machine_identity_signing_error_to_http(&s);
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            "machine identity signing is temporarily unavailable\n"
        );
    }

    #[test]
    fn metadata_header_is_true_accepts_case_insensitive() {
        let mut h = HeaderMap::new();
        assert!(!metadata_header_is_true(&h));
        h.insert("metadata", HeaderValue::from_static("true"));
        assert!(metadata_header_is_true(&h));
        let mut h2 = HeaderMap::new();
        h2.insert("metadata", HeaderValue::from_static("TRUE"));
        assert!(metadata_header_is_true(&h2));
    }

    #[test]
    fn machine_identity_params_try_from_proto_trims_url() {
        let p = FmdsMachineIdentityConfig {
            requests_per_second: 5,
            burst: 10,
            wait_timeout_secs: 3,
            sign_timeout_secs: 6,
            sign_proxy_url: Some("  https://sign.example  ".to_string()),
            sign_proxy_tls_root_ca: None,
        };
        let params = MachineIdentityParams::try_from(&p).unwrap();
        assert_eq!(
            params.sign_proxy_url.as_deref(),
            Some("https://sign.example")
        );
    }

    #[test]
    fn try_from_proto_matches_try_from_limits() {
        let proto = FmdsMachineIdentityConfig {
            requests_per_second: 5,
            burst: 10,
            wait_timeout_secs: 3,
            sign_timeout_secs: 6,
            sign_proxy_url: Some("  https://sign.example  ".to_string()),
            sign_proxy_tls_root_ca: None,
        };
        let a = MachineIdentityParams::try_from(&proto).unwrap();
        let b = MachineIdentityParams::try_from_limits(
            5,
            10,
            3,
            6,
            Some("  https://sign.example  "),
            None,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(
            FmdsMachineIdentityConfig::from(a),
            FmdsMachineIdentityConfig {
                requests_per_second: 5,
                burst: 10,
                wait_timeout_secs: 3,
                sign_timeout_secs: 6,
                sign_proxy_url: Some("https://sign.example".to_string()),
                sign_proxy_tls_root_ca: None,
            }
        );
    }

    #[test]
    fn accept_text_plain_detects_header() {
        let mut h = HeaderMap::new();
        assert!(!accept_text_plain(&h));
        h.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!accept_text_plain(&h));
        let mut h2 = HeaderMap::new();
        h2.insert(ACCEPT, HeaderValue::from_static("text/plain"));
        assert!(accept_text_plain(&h2));
    }

    #[test]
    fn build_sign_proxy_request_url_appends_path_and_query() {
        assert_eq!(
            build_sign_proxy_request_url("http://127.0.0.1:9/foo", Some("aud=x")).unwrap(),
            "http://127.0.0.1:9/foo/latest/meta-data/identity?aud=x"
        );
        assert_eq!(
            build_sign_proxy_request_url("http://127.0.0.1:9/foo/", None).unwrap(),
            "http://127.0.0.1:9/foo/latest/meta-data/identity"
        );
    }

    #[tokio::test]
    async fn forward_sign_proxy_http_passes_through() {
        let path = format!("/{}", SIGN_PROXY_UPSTREAM_IMDS_PREFIX);
        let app = Router::new().route(
            path.as_str(),
            get(|| async {
                (
                    StatusCode::CREATED,
                    [(CONTENT_TYPE, "application/special")],
                    "custom-token-body",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let base = format!("http://{}", addr);
        let uri: Uri = "http://client/latest/meta-data/identity?aud=test"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("metadata", HeaderValue::from_static("true"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let res = forward_sign_proxy_http(&client, &base, &uri, &headers).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap().as_bytes(),
            b"application/special"
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"custom-token-body");
        server.abort();
    }

    #[tokio::test]
    async fn forward_sign_proxy_if_ready_returns_none_without_base_url() {
        let uri: Uri = "http://127.0.0.1/latest/meta-data/identity"
            .parse()
            .unwrap();
        let headers = HeaderMap::new();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();

        assert!(
            forward_sign_proxy_if_ready(None, Some(&client), &uri, &headers)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn forward_sign_proxy_if_ready_returns_500_when_http_client_missing() {
        let uri: Uri = "http://127.0.0.1/latest/meta-data/identity"
            .parse()
            .unwrap();
        let headers = HeaderMap::new();

        let res = forward_sign_proxy_if_ready(Some("http://127.0.0.1:1"), None, &uri, &headers)
            .await
            .expect("expected misconfiguration response");
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn forward_sign_proxy_if_ready_delegates_to_forward_http() {
        let path = format!("/{}", SIGN_PROXY_UPSTREAM_IMDS_PREFIX);
        let app = Router::new().route(
            path.as_str(),
            get(|| async {
                (
                    StatusCode::CREATED,
                    [(CONTENT_TYPE, "application/special")],
                    "custom-token-body",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let base = format!("http://{}", addr);
        let uri: Uri = "http://client/latest/meta-data/identity?aud=test"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("metadata", HeaderValue::from_static("true"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let res = forward_sign_proxy_if_ready(Some(base.as_str()), Some(&client), &uri, &headers)
            .await
            .expect("expected forward response");
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap().as_bytes(),
            b"application/special"
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"custom-token-body");
        server.abort();
    }
}
