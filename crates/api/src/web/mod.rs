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

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Extension;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{Router, get, post};
use axum_extra::extract::Host;
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar};
use base64::prelude::*;
use http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, Request, StatusCode, Uri};
use itertools::Itertools;
use oauth2::basic::{
    BasicClient, BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenResponse,
};
use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, Scope, StandardRevocableToken, TokenUrl,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use tonic::service::AxumBody;
use tower_http::normalize_path::NormalizePath;

use crate::CarbideError;
use crate::api::Api;
use crate::auth::{AuthContext, Principal};
use crate::cfg::file::CarbideConfig;

mod attestation;
mod auth;
mod domain;
mod dpa;
mod dpu_versions;
mod expected_machine;
mod explored_endpoint;
mod filters;
mod health;
mod health_history;
mod ib_fabric;
mod ib_partition;
mod instance;
mod instance_type;
mod interface;
mod machine;
mod machine_state_history;
mod machine_validation;
pub mod managed_host;
mod network_device;
mod network_security_group;
mod network_segment;
mod network_status;
mod nmxm_browser;
mod nvlink;
mod power_shelf;
mod power_shelf_state_history;
mod rack;
mod redfish_actions;
mod redfish_browser;
mod resource_pool;
mod search;
mod sku;
mod switch;
mod switch_state_history;
mod tenant;
mod tenant_keyset;
mod ufm_browser;
mod vpc;

const WEB_AUTH: &str = "admin:Welcome123";

const AUTH_TYPE_ENV: &str = "CARBIDE_WEB_AUTH_TYPE";
const AUTH_CALLBACK_ROOT: &str = "auth-callback";

// Details https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false
const OAUTH2_AUTH_ENDPOINT_ENV: &str = "CARBIDE_WEB_OAUTH2_AUTH_ENDPOINT";

const OAUTH2_TOKEN_ENDPOINT_ENV: &str = "CARBIDE_WEB_OAUTH2_TOKEN_ENDPOINT";

const CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY_ENV: &str = "CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY";
const CARBIDE_WEB_HOSTNAME_ENV: &str = "CARBIDE_WEB_HOSTNAME";

const OAUTH2_CLIENT_SECRET_ENV: &str = "CARBIDE_WEB_OAUTH2_CLIENT_SECRET";
const OAUTH2_CLIENT_ID_ENV: &str = "CARBIDE_WEB_OAUTH2_CLIENT_ID";

const ALLOWED_ACCESS_GROUPS_LIST_ENV: &str = "CARBIDE_WEB_ALLOWED_ACCESS_GROUPS";

const ALLOWED_ACCESS_GROUPS_ID_LIST_ENV: &str = "CARBIDE_WEB_ALLOWED_ACCESS_GROUPS_ID_LIST";

const SORTABLE_JS: &str = include_str!("../../templates/static/sortable.min.js");
const SORTABLE_CSS: &str = include_str!("../../templates/static/sortable.min.css");
const CARBIDE_CSS: &str = include_str!("../../templates/static/carbide.css");

// It would appear the oauth2 author read about the typestate pattern and decided making
// everyone declare 10 type parameters when storing a Client sounds like a great idea.
// https://github.com/ramosbugs/oauth2-rs/blob/main/UPGRADE.md#add-typestate-generic-types-to-client
pub(crate) type Oauth2ClientWithPropertiesSet = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

#[derive(Clone)]
pub(crate) struct Oauth2Layer {
    client: Oauth2ClientWithPropertiesSet,
    http_client: reqwest::Client,
    private_cookiejar_key: Key,
    allowed_access_groups_filter: String,
    allowed_access_groups_ids_to_name: HashMap<String, String>,
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
                        CarbideError::internal(format!(
                            "{CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY_ENV}: {e}"
                        ))
                    })?
                    .as_bytes(),
            )?;

            // Grab the details for which groups are allowed to access the web UI.
            let allowed_groups = env::var(ALLOWED_ACCESS_GROUPS_LIST_ENV).map_err(|e| {
                CarbideError::internal(format!("{ALLOWED_ACCESS_GROUPS_LIST_ENV}: {e}"))
            })?;
            let allowed_access_groups_names = allowed_groups.split(",");
            let allowed_access_groups_filter = allowed_access_groups_names
                .clone()
                .map(|s| format!("\"displayName:{}\"", s.to_lowercase()))
                .join(" OR ");
            let allowed_access_groups_ids_to_name = env::var(ALLOWED_ACCESS_GROUPS_ID_LIST_ENV)
                .map_err(|e| {
                    CarbideError::internal(format!("{ALLOWED_ACCESS_GROUPS_ID_LIST_ENV}: {e}"))
                })?
                .split(",")
                .map(|s| s.to_lowercase())
                .zip(allowed_access_groups_names)
                .map(|(id, name)| (id, name.to_string()))
                .collect::<HashMap<String, String>>();

            let client_id = env::var(OAUTH2_CLIENT_ID_ENV)
                .map_err(|e| CarbideError::internal(format!("{OAUTH2_CLIENT_ID_ENV}: {e}")))?;
            let client_secret = env::var(OAUTH2_CLIENT_SECRET_ENV)
                .map_err(|e| CarbideError::internal(format!("{OAUTH2_CLIENT_SECRET_ENV}: {e}")))?;
            let auth_endpoint = env::var(OAUTH2_AUTH_ENDPOINT_ENV)
                .map_err(|e| CarbideError::internal(format!("{OAUTH2_AUTH_ENDPOINT_ENV}: {e}")))?;
            let token_endpoint = env::var(OAUTH2_TOKEN_ENDPOINT_ENV)
                .map_err(|e| CarbideError::internal(format!("{OAUTH2_TOKEN_ENDPOINT_ENV}: {e}")))?;

            // Build the  OAuth2 client.
            let client = BasicClient::new(ClientId::new(client_id))
                .set_client_secret(ClientSecret::new(client_secret))
                .set_auth_uri(AuthUrl::new(auth_endpoint)?)
                .set_token_uri(TokenUrl::new(token_endpoint)?)
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
                allowed_access_groups_ids_to_name,
                http_client,
            })
        }
        _ => None,
    };

    Ok(NormalizePath::trim_trailing_slash(
        Router::new()
            .route("/", get(root))
            .route("/static/{filename}", get(static_data))
            .route("/domain", get(domain::show_html))
            .route("/domain.json", get(domain::show_all_json))
            .route("/dpa", get(dpa::show_dpas_html))
            .route("/dpa.json", get(dpa::show_dpas_json))
            .route("/dpa/{dpa_id}", get(dpa::detail))
            .route("/dpu", get(machine::show_dpus_html))
            .route("/dpu.json", get(machine::show_dpus_json))
            .route("/dpu/versions", get(dpu_versions::list_html))
            .route("/dpu/versions.json", get(dpu_versions::list_json))
            .route(
                "/explored-endpoint.json",
                get(explored_endpoint::show_all_json),
            )
            .route("/explored-endpoint", get(explored_endpoint::show_html_all))
            .route(
                "/explored-endpoint/paired",
                get(explored_endpoint::show_html_paired),
            )
            .route(
                "/explored-endpoint/unpaired",
                get(explored_endpoint::show_html_unpaired),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}",
                get(explored_endpoint::detail),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/reexplore",
                post(explored_endpoint::re_explore),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/power-control",
                post(explored_endpoint::power_control),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/bmc-reset",
                post(explored_endpoint::bmc_reset),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/clear-last-error",
                post(explored_endpoint::clear_last_exploration_error),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/pause-remediation",
                post(explored_endpoint::pause_remediation),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/machine-setup",
                post(explored_endpoint::machine_setup),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/set-dpu-first-boot-order",
                post(explored_endpoint::set_dpu_first_boot_order),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/clear-credentials",
                post(explored_endpoint::clear_bmc_credentials),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/delete",
                post(explored_endpoint::delete_endpoint),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/disable-secure-boot",
                post(explored_endpoint::disable_secure_boot),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/disable-lockdown",
                post(explored_endpoint::disable_lockdown),
            )
            .route(
                "/explored-endpoint/{endpoint_ip}/enable-lockdown",
                post(explored_endpoint::enable_lockdown),
            )
            .route("/host", get(machine::show_hosts_html))
            .route("/host.json", get(machine::show_hosts_json))
            .route("/ib-partition", get(ib_partition::show_html))
            .route("/ib-partition.json", get(ib_partition::show_all_json))
            .route("/ib-partition/{partition_id}", get(ib_partition::detail))
            .route("/ib-fabric", get(ib_fabric::show_html))
            .route("/ib-fabric.json", get(ib_fabric::show_all_json))
            .route("/instance", get(instance::show_html))
            .route("/instance.json", get(instance::show_all_json))
            .route("/instance/{instance_id}", get(instance::detail))
            .route("/instance-type", get(instance_type::show))
            .route(
                "/instance-type/{instance_type_id}",
                get(instance_type::show_detail),
            )
            .route("/interface", get(interface::show_html))
            .route("/interface.json", get(interface::show_all_json))
            .route("/interface/{interface_id}", get(interface::detail))
            .route("/machine", get(machine::show_all_html))
            .route("/machine.json", get(machine::show_all_json))
            .route("/machine/{machine_id}", get(machine::detail))
            .route(
                "/machine/{machine_id}/maintenance",
                post(machine::maintenance),
            )
            .route(
                "/machine/{machine_id}/quarantine",
                post(machine::quarantine),
            )
            .route(
                "/machine/{machine_id}/set-dpu-first-boot-order",
                post(machine::set_dpu_first_boot_order),
            )
            .route("/machine/{machine_id}/health", get(health::health))
            .route(
                "/machine/{machine_id}/health-history",
                get(health_history::show_health_history),
            )
            .route(
                "/machine/{machine_id}/health-history.json",
                get(health_history::show_health_history_json),
            )
            .route(
                "/machine/{machine_id}/state-history",
                get(machine_state_history::show_state_history),
            )
            .route(
                "/machine/{machine_id}/state-history.json",
                get(machine_state_history::show_state_history_json),
            )
            .route("/power-shelf", get(power_shelf::show_html))
            .route("/power-shelf.json", get(power_shelf::show_json))
            .route(
                "/power-shelf/{power_shelf_id}/state-history",
                get(power_shelf_state_history::show_state_history),
            )
            .route(
                "/power-shelf/{power_shelf_id}/state-history.json",
                get(power_shelf_state_history::show_state_history_json),
            )
            .route("/rack", get(rack::show_html))
            .route("/rack.json", get(rack::show_json))
            .route("/switch", get(switch::show_html))
            .route("/switch.json", get(switch::show_json))
            .route(
                "/switch/{switch_id}/state-history",
                get(switch_state_history::show_state_history),
            )
            .route(
                "/switch/{switch_id}/state-history.json",
                get(switch_state_history::show_state_history_json),
            )
            .route(
                "/machine/{machine_id}/health/override/add",
                post(health::add_override),
            )
            .route(
                "/machine/{machine_id}/health/override/remove",
                post(health::remove_override),
            )
            .route(
                "/machine/{machine_id}/attestation-results",
                get(attestation::show_attestation_results),
            )
            .route(
                "/attestation-summary",
                get(attestation::show_attestation_summary),
            )
            .route(
                "/machine/{machine_id}/attestation-submit-report-promotion",
                get(attestation::submit_report_promotion),
            )
            .route("/managed-host", get(managed_host::show_html))
            .route("/managed-host.json", get(managed_host::show_all_json))
            .route("/managed-host/{machine_id}", get(managed_host::detail))
            .route("/expected-machine", get(expected_machine::show_all_html))
            .route(
                "/expected-machine-definition.json",
                get(expected_machine::show_expected_machine_raw_json),
            )
            .route("/network-device", get(network_device::show_html))
            .route("/network-device.json", get(network_device::show_all_json))
            .route("/network-security-group", get(network_security_group::show))
            .route(
                "/network-security-group",
                post(network_security_group::create),
            )
            .route(
                "/network-security-group/{network_security_group_id}",
                get(network_security_group::show_detail),
            )
            .route(
                "/network-security-group/{network_security_group_id}",
                post(network_security_group::update),
            )
            .route(
                "/network-security-group/{network_security_group_id}/delete",
                post(network_security_group::delete),
            )
            .route("/network-segment", get(network_segment::show_html))
            .route("/network-segment.json", get(network_segment::show_all_json))
            .route(
                "/network-segment/{segment_id}",
                get(network_segment::detail),
            )
            .route("/network-status", get(network_status::show_html))
            .route("/network-status.json", get(network_status::show_all_json))
            .route("/nmxm-browser", get(nmxm_browser::query))
            .route(
                "/nvlink-partition",
                get(nvlink::show_nvlink_logical_partitions_html),
            )
            .route(
                "/nvlink-partition.json",
                get(nvlink::show_nvlink_logical_partitions_json),
            )
            .route("/nvlink-partition/{id}", get(nvlink::detail))
            .route("/resource-pool", get(resource_pool::show_html))
            .route("/resource-pool.json", get(resource_pool::show_all_json))
            .route("/vpc", get(vpc::show_html))
            .route("/vpc.json", get(vpc::show_all_json))
            .route("/vpc/{vpc_id}", get(vpc::detail))
            .route("/redfish-browser", get(redfish_browser::query))
            .route("/redfish-actions", get(redfish_actions::query))
            .route("/redfish-actions/create", post(redfish_actions::create))
            .route("/redfish-actions/approve", post(redfish_actions::approve))
            .route("/redfish-actions/apply", post(redfish_actions::apply))
            .route("/redfish-actions/cancel", post(redfish_actions::cancel))
            .route("/search", get(search::find))
            .route("/sku", get(sku::show_html))
            .route("/sku.json", get(sku::show_all_json))
            .route("/sku/{sku_id}", get(sku::detail))
            .route("/tenant", get(tenant::show_html))
            .route("/tenant.json", get(tenant::show_all_json))
            .route("/tenant/{organization_id}", get(tenant::detail))
            .route("/tenant_keyset", get(tenant_keyset::show_html))
            .route("/tenant_keyset.json", get(tenant_keyset::show_all_json))
            .route(
                "/tenant_keyset/{organization_id}/{keyset_id}",
                get(tenant_keyset::detail),
            )
            .route(&format!("/{AUTH_CALLBACK_ROOT}"), get(auth::callback))
            .route(
                "/machinevalidation/runs/{validation_id}",
                get(machine_validation::results),
            )
            .route(
                "/machinevalidation/resultdetails/{validation_id}/{test_id}",
                get(machine_validation::result_details),
            )
            .route(
                "/machinevalidation/tests",
                get(machine_validation::show_tests_html),
            )
            .route("/machinevalidation", get(machine_validation::runs))
            .route(
                "/machinevalidation/tests/{test_id}",
                get(machine_validation::show_tests_details_html),
            )
            .route(
                "/machinevalidation/external-config",
                get(machine_validation::external_configs),
            )
            .route("/ufm-browser", get(ufm_browser::query))
            .layer(axum::middleware::from_fn(auth_oauth2))
            .layer(Extension(oauth_extension_layer))
            .with_state(api),
    ))
}

pub async fn auth_oauth2(
    Host(hostname): Host,
    headers: HeaderMap,
    mut req: Request<AxumBody>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Remove the port (this matters on localhost) since a cookie for localhost:1079
    // does not apply for the a page hosted on localhost:1079. Instead the cookie
    // must be for localhost.

    let Some(hostname) = Uri::try_from(hostname)
        .ok()
        .and_then(|uri| uri.host().map(|host| host.to_owned()))
    else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

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

    // Add an auth context (mocking grpc certificate auth context) if we have a unique name.
    let unique_name = cookiejar.get("unique_name");
    let group = cookiejar.get("group_name");
    if let Some((unique_name, group)) = unique_name.zip(group) {
        let extensions = req.extensions_mut();
        // Extend auth context if it exists.
        let auth_context: &mut AuthContext = extensions.get_or_insert_default();
        auth_context.principals.push(Principal::from_web_cookie(
            unique_name.value().to_string(),
            group.value().to_string(),
        ));
    }

    // If it exists, do we still want to accept it?
    if let Some(c) = cookiejar.get("sid").map(|cookie| cookie.value().to_owned())
        && let Ok(expiraton_timestamp) = c.parse::<u64>()
    {
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
        .domain(hostname.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .build();

    // Store the page the user originally wanted so we can send them back after auth.
    let requested_page_cookie = Cookie::build((
        "requested_page",
        req.uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or_else(|| req.uri().path())
            .to_string(),
    ))
    .domain(hostname)
    .path("/")
    .secure(true)
    .http_only(true)
    .build();

    Ok((
        cookiejar
            .remove(requested_page_cookie.clone())
            .remove(csrf_cookie.clone())
            .remove(pkce_cookie.clone())
            .add(requested_page_cookie)
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string()));
        }
    };

    let create_machines = state
        .dynamic_settings
        .create_machines
        .load(Ordering::Relaxed)
        .to_string();
    let bmc_proxy = state
        .dynamic_settings
        .bmc_proxy
        .load()
        .as_ref()
        .clone()
        .map(|p| p.to_string())
        .unwrap_or("<None>".to_string());

    let index = Index {
        version: carbide_version::v!(build_version),
        log_filter: state.log_filter_string(),
        agent_upgrade_policy,
        create_machines,
        carbide_config: state.runtime_config.redacted(),
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
        "carbide.css" => {
            (StatusCode::OK, [(CONTENT_TYPE, "text/css")], CARBIDE_CSS).into_response()
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

pub(crate) fn invalid_machine_id() -> String {
    "INVALID_MACHINE".to_string()
}
