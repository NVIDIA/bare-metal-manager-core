/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::{
    extract::{Host, Path as AxumPath, State as AxumState},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    Extension,
};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar};
use base64::prelude::*;
use hyper::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::http::{HeaderMap, Request, StatusCode};
use itertools::Itertools;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use tonic::service::AxumBody;
use tower_http::normalize_path::NormalizePath;

use crate::api::Api;
use crate::cfg::CarbideConfig;
use crate::CarbideError;

mod auth;
mod domain;
mod dpu_versions;
mod expected_machine;
mod explored_endpoint;
mod filters;
mod health;
mod ib_partition;
mod instance;
mod interface;
mod machine;
mod managed_host;
mod network_device;
mod network_segment;
mod network_status;
mod resource_pool;
mod search;
mod tenant;
mod tenant_keyset;
mod vpc;

const WEB_AUTH: &str = "admin:Welcome123";

const AUTH_TYPE_ENV: &str = "CARBIDE_WEB_AUTH_TYPE";
const AUTH_CALLBACK_ROOT: &str = "auth-callback";

// Details https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false
const OAUTH2_AUTH_ENDPOINT_ENV: &str = "CARBIDE_WEB_OAUTH2_AUTH_ENDPOINT";
const DEFAULT_OAUTH2_AUTH_ENDPOINT: &str =
    "https://login.microsoftonline.com/43083d15-7273-40c1-b7db-39efd9ccc17a/oauth2/v2.0/authorize";

const OAUTH2_TOKEN_ENDPOINT_ENV: &str = "CARBIDE_WEB_OAUTH2_TOKEN_ENDPOINT";
const DEFAULT_OAUTH2_TOKEN_ENDPOINT: &str =
    "https://login.microsoftonline.com/43083d15-7273-40c1-b7db-39efd9ccc17a/oauth2/v2.0/token";

const CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY_ENV: &str = "CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY";
const CARBIDE_WEB_HOSTNAME_ENV: &str = "CARBIDE_WEB_HOSTNAME";

const OAUTH2_CLIENT_SECRET_ENV: &str = "CARBIDE_WEB_OAUTH2_CLIENT_SECRET";
const OAUTH2_CLIENT_ID_ENV: &str = "CARBIDE_WEB_OAUTH2_CLIENT_ID";
const DEFAULT_OAUTH2_CLIENT_ID: &str = "5ae5fa35-be8e-44cc-be7b-01ff76af5315";

const ALLOWED_ACCESS_GROUPS_LIST_ENV: &str = "CARBIDE_WEB_ALLOWED_ACCESS_GROUPS";
const DEFAULT_ALLOWED_ACCESS_GROUPS_LIST: &str = "swngc-forge-admins,ngc-forge-sre,swngc-forge-dev";

const ALLOWED_ACCESS_GROUPS_ID_LIST_ENV: &str = "CARBIDE_WEB_ALLOWED_ACCESS_GROUPS_ID_LIST";
const DEFAULT_ALLOWED_ACCESS_GROUPS_ID_LIST: &str =
    "1f13d1bb-6d7e-4fa5-9abf-93e24e7b5a4e,80f709a0-77a7-4a15-899d-7abba0ffdc1f,d03b7e2a-673b-4088-9af0-545a2d2f4c5d";

const SORTABLE_JS: &str = include_str!("../../templates/static/sortable.min.js");
const SORTABLE_CSS: &str = include_str!("../../templates/static/sortable.min.css");

#[derive(Clone)]
pub(crate) struct Oauth2Layer {
    client: BasicClient,
    http_client: reqwest::Client,
    private_cookiejar_key: Key,
    allowed_access_groups_filter: String,
    allowed_access_groups_ids: Vec<String>,
}

/// All the URLs in the admin interface. Nested under /admin in api.rs.
pub fn routes(api: Arc<Api>) -> eyre::Result<NormalizePath<Router>> {
    // Just something to let us transition more easily.
    // By default, everything will be the original basic-auth,
    // so we can deploy this all over and flip on azure auth with
    // some env-vars.  When everything is switched over, we can
    // clean this up this up, maybe directly send the struct without the option wrapper,
    // and only ever use oauth2 if we want.
    let oauth_extension_layer = match env::var(AUTH_TYPE_ENV)
        .unwrap_or("basic".to_string())
        .to_lowercase()
        .as_str()
    {
        "oauth2" => {
            // Get our cookiejar key so we can add it as an extension.
            let private_cookiejar_key = Key::try_from(
                env::var(CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY_ENV)
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "{}: {}",
                            CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY_ENV, e
                        ))
                    })?
                    .as_bytes(),
            )?;

            // Grab the details for which groups are allowed to access the web UI.
            let allowed_access_groups_ids = env::var(ALLOWED_ACCESS_GROUPS_ID_LIST_ENV)
                .unwrap_or(DEFAULT_ALLOWED_ACCESS_GROUPS_ID_LIST.to_string())
                .split(",")
                .map(|s| s.to_lowercase())
                .collect();

            let allowed_access_groups_filter = env::var(ALLOWED_ACCESS_GROUPS_LIST_ENV)
                .unwrap_or(DEFAULT_ALLOWED_ACCESS_GROUPS_LIST.to_string())
                .split(",")
                .map(|s| format!("\"displayName:{}\"", s.to_lowercase()))
                .join(" OR ");

            // Build the  OAuth2 client.
            let client = BasicClient::new(
                ClientId::new(
                    env::var(OAUTH2_CLIENT_ID_ENV).unwrap_or(DEFAULT_OAUTH2_CLIENT_ID.to_string()),
                ),
                Some(ClientSecret::new(
                    env::var(OAUTH2_CLIENT_SECRET_ENV).map_err(|e| {
                        CarbideError::GenericError(format!("{}: {}", OAUTH2_CLIENT_SECRET_ENV, e))
                    })?,
                )),
                AuthUrl::new(
                    env::var(OAUTH2_AUTH_ENDPOINT_ENV)
                        .unwrap_or(DEFAULT_OAUTH2_AUTH_ENDPOINT.to_string()),
                )?,
                Some(TokenUrl::new(
                    env::var(OAUTH2_TOKEN_ENDPOINT_ENV)
                        .unwrap_or(DEFAULT_OAUTH2_TOKEN_ENDPOINT.to_string()),
                )?),
            )
            .set_redirect_uri(RedirectUrl::new(format!(
                "https://{}/admin/{}",
                env::var(CARBIDE_WEB_HOSTNAME_ENV).unwrap_or("localhost:1079".to_string()),
                AUTH_CALLBACK_ROOT,
            ))?);

            let http_client = {
                let builder = reqwest::Client::builder();
                let builder = builder
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::new(5, 0)) // Limit connections to 5 seconds
                    .timeout(Duration::new(15, 0)); // Limit the overall request to 15 seconds

                builder.build()?
            };

            Some(Oauth2Layer {
                client,
                private_cookiejar_key,
                allowed_access_groups_filter,
                allowed_access_groups_ids,
                http_client,
            })
        }
        _ => None,
    };

    Ok(NormalizePath::trim_trailing_slash(
        Router::new()
            .route("/", get(root))
            .route("/static/:filename", get(static_data))
            .route("/domain", get(domain::show_html))
            .route("/domain.json", get(domain::show_json))
            .route("/dpu", get(machine::show_dpus_html))
            .route("/dpu.json", get(machine::show_dpus_json))
            .route("/dpu/versions", get(dpu_versions::list_html))
            .route("/explored-endpoint", get(explored_endpoint::show_html_all))
            .route("/explored-endpoint.json", get(explored_endpoint::show_json))
            .route(
                "/explored-endpoint/paired",
                get(explored_endpoint::show_html_paired),
            )
            .route(
                "/explored-endpoint/unpaired",
                get(explored_endpoint::show_html_unpaired),
            )
            .route(
                "/explored-endpoint/:endpoint_ip",
                get(explored_endpoint::detail),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/reexplore",
                post(explored_endpoint::re_explore),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/power-control",
                post(explored_endpoint::power_control),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/bmc-reset",
                post(explored_endpoint::bmc_reset),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/clear-last-error",
                post(explored_endpoint::clear_last_exploration_error),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/forge-setup",
                post(explored_endpoint::forge_setup),
            )
            .route(
                "/explored-endpoint/:endpoint_ip/clear-credentials",
                post(explored_endpoint::clear_bmc_credentials),
            )
            .route("/host", get(machine::show_hosts_html))
            .route("/host.json", get(machine::show_hosts_json))
            .route("/ib-partition", get(ib_partition::show_html))
            .route("/ib-partition.json", get(ib_partition::show_json))
            .route("/ib-partition/:partition_id", get(ib_partition::detail))
            .route("/instance", get(instance::show_html))
            .route("/instance.json", get(instance::show_json))
            .route("/instance/:instance_id", get(instance::detail))
            .route("/interface", get(interface::show_html))
            .route("/interface.json", get(interface::show_json))
            .route("/interface/:interface_id", get(interface::detail))
            .route("/machine", get(machine::show_all_html))
            .route("/machine.json", get(machine::show_all_json))
            .route("/machine/:machine_id", get(machine::detail))
            .route("/machine/health/:machine_id", get(health::health))
            .route(
                "/machine/health/:machine_id/override/add",
                post(health::add_override),
            )
            .route(
                "/machine/health/:machine_id/override/remove",
                post(health::remove_override),
            )
            .route("/managed-host", get(managed_host::show_html))
            .route("/managed-host.json", get(managed_host::show_json))
            .route("/managed-host/:machine_id", get(managed_host::detail))
            .route(
                "/managed-host/:machine_id/maintenance",
                post(managed_host::maintenance),
            )
            .route("/expected-machine", get(expected_machine::show_all_html))
            .route(
                "/expected-machine-definition.json",
                get(expected_machine::show_expected_machine_raw_json),
            )
            .route("/network-device", get(network_device::show_html))
            .route("/network-device.json", get(network_device::show_json))
            .route("/network-segment", get(network_segment::show_html))
            .route("/network-segment.json", get(network_segment::show_json))
            .route("/network-segment/:segment_id", get(network_segment::detail))
            .route("/network-status", get(network_status::show_html))
            .route("/network-status.json", get(network_status::show_json))
            .route("/resource-pool", get(resource_pool::show_html))
            .route("/resource-pool.json", get(resource_pool::show_json))
            .route("/vpc", get(vpc::show_html))
            .route("/vpc.json", get(vpc::show_json))
            .route("/vpc/:vpc_id", get(vpc::detail))
            .route("/search", get(search::find))
            .route("/tenant", get(tenant::show_html))
            .route("/tenant.json", get(tenant::show_json))
            .route("/tenant/:organization_id", get(tenant::detail))
            .route("/tenant_keyset", get(tenant_keyset::show_html))
            .route("/tenant_keyset.json", get(tenant_keyset::show_json))
            .route(
                "/tenant_keyset/:organization_id/:keyset_id",
                get(tenant_keyset::detail),
            )
            .route(&format!("/{AUTH_CALLBACK_ROOT}"), get(auth::callback))
            .layer(axum::middleware::from_fn(auth_oauth2))
            .layer(Extension(oauth_extension_layer))
            .with_state(api),
    ))
}

pub async fn auth_oauth2(
    Host(hostname): Host,
    headers: HeaderMap,
    req: Request<AxumBody>,
    next: Next,
) -> Result<Response, StatusCode> {
    let oauth_extension_layer = match req.extensions().get::<Option<Oauth2Layer>>() {
        None => {
            tracing::error!("failed to find oauth2 extension layer");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Some(o) => match o {
            None => {
                return auth_basic(req, next).await;
            }
            Some(oa) => oa.to_owned(),
        },
    };

    // /auth-callback should pass through because that's
    // where microsoft will call back after the auth attempt.
    if req.uri().path().starts_with("/auth-callback") {
        return Ok(next.run(req).await);
    }

    let cookiejar: PrivateCookieJar = PrivateCookieJar::from_headers(
        &headers,
        oauth_extension_layer.private_cookiejar_key.clone(),
    );

    // If it exists, do we still want to accept it?
    if let Some(c) = cookiejar.get("sid").map(|cookie| cookie.value().to_owned()) {
        if let Ok(expiraton_timestamp) = c.parse::<u64>() {
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    tracing::error!(%e, "failed to get system time for oauth2 expiration check");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .as_secs();

            // Still valid?  Let'em pass through to where they wanted
            // to go.
            if now_seconds < expiraton_timestamp {
                return Ok(next.run(req).await);
            }
        }
    }

    // If not found or expired, we'll grab the oauth client and redirect to Azure for auth.

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = oauth_extension_layer
        .client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("User.Read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store the pkce verifier so we can use it later
    // during code exchange when they hit our callback URL.
    // Using this with a cookie is a little weird, but it'll be encrypted.
    let pkce_cookie = Cookie::build(("pkce_verifier", pkce_verifier.secret().to_owned()))
        .domain(hostname.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .build();

    // Store the csrf state so we can compare the state we get back from Azure
    // when they hit our callback URL.
    let csrf_cookie = Cookie::build(("csrf_state", csrf_state.secret().to_owned()))
        .domain(hostname)
        .path("/")
        .secure(true)
        .http_only(true)
        .build();

    Ok((
        cookiejar
            .remove(csrf_cookie.clone())
            .remove(pkce_cookie.clone())
            .add(csrf_cookie)
            .add(pkce_cookie),
        Redirect::to(auth_url.as_ref()),
    )
        .into_response())
}

pub async fn auth_basic(req: Request<AxumBody>, next: Next) -> Result<Response, StatusCode> {
    let must_auth = (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Basic realm=Carbide")],
    );
    match req.headers().get("Authorization") {
        None => {
            return Ok(must_auth.into_response());
        }
        Some(auth_val) => {
            let Ok(auth_val) = auth_val.to_str() else {
                tracing::error!("Invalid auth header");
                return Err(StatusCode::BAD_REQUEST);
            };
            if !is_valid_auth(auth_val) {
                return Ok(must_auth.into_response());
            }
        }
    };

    let mut peer = String::new();
    if let Some(conn) = req
        .extensions()
        .get::<Arc<crate::listener::ConnectionAttributes>>()
    {
        peer = conn.peer_address().ip().to_string();
    }
    let path = req.uri().path();
    let at = format!("{:?}", chrono::Utc::now());
    tracing::info!(client_ip=%peer, path=%path, at=%at, "carbide-web_authorized_request");

    Ok(next.run(req).await)
}

fn is_valid_auth(auth_str: &str) -> bool {
    let parts: Vec<&str> = auth_str.split(' ').collect();
    if parts.len() != 2 || parts[0] != "Basic" {
        tracing::trace!(auth_str, "Auth must match 'Basic <str>'");
        return false;
    }
    let Ok(plain) = BASE64_STANDARD.decode(parts[1]) else {
        tracing::trace!(auth_str, "Auth should be base64");
        return false;
    };
    let plain = String::from_utf8_lossy(&plain);
    if plain != WEB_AUTH {
        tracing::trace!(auth_str, "Wrong username or password");
        return false;
    }
    true
}

#[derive(Template)]
#[template(path = "index.html")]
struct Index {
    version: &'static str,
    agent_upgrade_policy: &'static str,
    log_filter: String,
    create_machines: String,
    carbide_config: CarbideConfig,
    bmc_proxy: String,
}

pub async fn root(state: AxumState<Arc<Api>>) -> impl IntoResponse {
    let request = tonic::Request::new(forgerpc::DpuAgentUpgradePolicyRequest { new_policy: None });
    use forgerpc::AgentUpgradePolicy::*;
    let agent_upgrade_policy = match state
        .dpu_agent_upgrade_policy_action(request)
        .await
        .map(|response| response.into_inner())
        .map(|p| p.active_policy)
    {
        Ok(x) if x == Off as i32 => "Off",
        Ok(x) if x == UpOnly as i32 => "Upgrade only",
        Ok(x) if x == UpDown as i32 => "Upgade and Downgrade",
        Ok(_) => "Unknown",
        Err(err) => {
            tracing::error!(%err, "dpu_agent_upgrade_policy_action");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };

    let create_machines = state.dynamic_settings.create_machines.load().to_string();
    let bmc_proxy = state
        .dynamic_settings
        .bmc_proxy
        .load()
        .as_ref()
        .clone()
        .map(|p| p.to_string())
        .unwrap_or("<None>".to_string());

    let index = Index {
        version: forge_version::v!(build_version),
        log_filter: state.log_filter_string(),
        agent_upgrade_policy,
        create_machines,
        carbide_config: (*state.runtime_config).clone(),
        bmc_proxy,
    };

    (StatusCode::OK, Html(index.render().unwrap()))
}

pub async fn static_data(
    _state: AxumState<Arc<Api>>,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    match filename.as_str() {
        "sortable.js" => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/javascript")],
            SORTABLE_JS,
        )
            .into_response(),
        "sortable.css" => {
            (StatusCode::OK, [(CONTENT_TYPE, "text/css")], SORTABLE_CSS).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "No such file").into_response(),
    }
}

/// Creates a response that describes that `resource` was not found
pub(crate) fn not_found_response(resource: String) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(format!("Not found: {resource}")),
    )
        .into_response()
}

pub(crate) fn invalid_machine_id() -> rpc::common::MachineId {
    rpc::common::MachineId {
        id: "INVALID_MACHINE".to_string(),
    }
}

pub(crate) fn default_uuid() -> rpc::common::Uuid {
    rpc::common::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}
