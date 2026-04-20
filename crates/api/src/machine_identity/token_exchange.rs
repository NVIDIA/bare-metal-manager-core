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

//! RFC 8693 token exchange HTTP client for tenant `token_endpoint` (machine identity delegation).

use std::time::Duration;

use ::rpc::forge::MachineIdentityResponse;
use base64::Engine;
use serde::Deserialize;
use tonic::Status;

use crate::CarbideError;

const OAUTH_GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const OAUTH_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

#[derive(Debug, Deserialize)]
struct TokenExchangeHttpResponseBody {
    access_token: String,
    #[serde(default)]
    issued_token_type: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    /// RFC 6749 `expires_in` (seconds). JSON must be a non-negative integer in `u32` range.
    #[serde(default)]
    expires_in: Option<u32>,
}

/// Builds the HTTP client used only for RFC 8693 calls to per-org `token_endpoint`.
/// When `token_endpoint_http_proxy` is set and non-empty, all those requests go through that proxy.
pub(crate) fn token_exchange_http_client(
    token_endpoint_http_proxy: Option<&str>,
) -> Result<reqwest::Client, Status> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy_url) = token_endpoint_http_proxy.filter(|s| !s.is_empty()) {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
            CarbideError::InvalidArgument(format!(
                "invalid machine_identity.token_endpoint_http_proxy: {e}"
            ))
        })?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| CarbideError::internal(format!("token exchange HTTP client: {e}")).into())
}

pub(crate) fn rfc8693_token_exchange_form(
    subject_jwt: &str,
    workload_audiences: &[String],
) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    ser.append_pair("grant_type", OAUTH_GRANT_TYPE_TOKEN_EXCHANGE);
    ser.append_pair("subject_token", subject_jwt);
    ser.append_pair("subject_token_type", OAUTH_TOKEN_TYPE_JWT);
    for a in workload_audiences {
        ser.append_pair("audience", a);
    }
    ser.finish()
}

/// Sends an [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange **request** to
/// the tenant `token_endpoint` (HTTP POST, `application/x-www-form-urlencoded` body from
/// [`rfc8693_token_exchange_form`]) and maps the JSON response to [`MachineIdentityResponse`].
pub(crate) async fn token_exchange_request(
    http: &reqwest::Client,
    token_endpoint: &str,
    subject_jwt: &str,
    workload_audiences: &[String],
    basic_credentials: Option<&(String, String)>,
) -> Result<MachineIdentityResponse, Status> {
    let body = rfc8693_token_exchange_form(subject_jwt, workload_audiences);

    let mut req = http
        .post(token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body);

    if let Some((client_id, client_secret)) = basic_credentials {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{client_secret}"));
        req = req.header(reqwest::header::AUTHORIZATION, format!("Basic {encoded}"));
    }

    let resp = req.send().await.map_err(|e| {
        tracing::error!(
            error = %e,
            token_endpoint = %token_endpoint,
            "token exchange HTTP request failed"
        );
        CarbideError::internal(format!("token exchange request failed: {e}"))
    })?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "token exchange response body read failed");
        CarbideError::internal(format!("token exchange response failed: {e}"))
    })?;

    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
        tracing::warn!(
            status = %status,
            body_prefix = %snippet,
            "token exchange endpoint returned error"
        );
        return Err(CarbideError::InvalidArgument(format!(
            "token exchange endpoint returned HTTP {status}"
        ))
        .into());
    }

    let parsed: TokenExchangeHttpResponseBody = serde_json::from_slice(&bytes).map_err(|e| {
        tracing::warn!(error = %e, body = %String::from_utf8_lossy(&bytes[..bytes.len().min(256)]), "token exchange JSON parse failed");
        CarbideError::internal("token exchange response was not valid JSON".to_string())
    })?;

    let issued = parsed
        .issued_token_type
        .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:jwt".to_string());
    let token_type = parsed.token_type.unwrap_or_else(|| "Bearer".to_string());
    let expires_in_sec = parsed.expires_in.unwrap_or(0);

    Ok(MachineIdentityResponse {
        access_token: parsed.access_token,
        issued_token_type: issued,
        token_type,
        expires_in_sec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_exchange_body_deserializes_expires_in_as_json_number() {
        let n: TokenExchangeHttpResponseBody =
            serde_json::from_str(r#"{"access_token":"t","expires_in":3600}"#).unwrap();
        assert_eq!(n.expires_in, Some(3600_u32));
        let omitted: TokenExchangeHttpResponseBody =
            serde_json::from_str(r#"{"access_token":"t"}"#).unwrap();
        assert_eq!(omitted.expires_in, None);
    }

    #[test]
    fn token_exchange_body_rejects_expires_in_as_string() {
        let err = serde_json::from_str::<TokenExchangeHttpResponseBody>(
            r#"{"access_token":"t","expires_in":"7200"}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("expires_in") || err.to_string().contains("invalid type"),
            "{err}"
        );
    }

    #[test]
    fn token_exchange_body_rejects_negative_expires_in() {
        assert!(
            serde_json::from_str::<TokenExchangeHttpResponseBody>(
                r#"{"access_token":"t","expires_in":-1}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn rfc8693_token_exchange_form_encoding() {
        let form = rfc8693_token_exchange_form(
            "header.payload.sig",
            &["spiffe://z/a".to_string(), "spiffe://z/b".to_string()],
        );
        assert!(
            form.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
        );
        assert!(form.contains("subject_token=header.payload.sig"));
        assert!(form.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"));
        assert!(form.contains("audience=spiffe%3A%2F%2Fz%2Fa"));
        assert!(form.contains("audience=spiffe%3A%2F%2Fz%2Fb"));
    }

    #[tokio::test]
    async fn token_exchange_request_success_parses_json_response() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"exchanged","issued_token_type":"urn:ietf:params:oauth:token-type:jwt","token_type":"Bearer","expires_in":42}"#,
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/token", server.url());
        let out = token_exchange_request(
            &client,
            &url,
            "sub.jwt",
            &["spiffe://workload".to_string()],
            None,
        )
        .await
        .unwrap();

        assert_eq!(out.access_token, "exchanged");
        assert_eq!(
            out.issued_token_type,
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(out.token_type, "Bearer");
        assert_eq!(out.expires_in_sec, 42);
    }

    #[tokio::test]
    async fn token_exchange_request_http_error_maps_to_status() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/token")
            .with_status(401)
            .with_body(r#"{"error":"invalid_client"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/token", server.url());
        let err = token_exchange_request(&client, &url, "sub.jwt", &["aud".to_string()], None)
            .await
            .unwrap_err();
        assert!(err.message().contains("401"));
    }

    #[tokio::test]
    async fn token_exchange_request_sends_basic_auth() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/token")
            .match_header("authorization", "Basic Zm9vOmJhcg==")
            .with_status(200)
            .with_body(r#"{"access_token":"t"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/token", server.url());
        let creds = ("foo".to_string(), "bar".to_string());
        let out = token_exchange_request(&client, &url, "j", &[], Some(&creds))
            .await
            .unwrap();
        assert_eq!(out.access_token, "t");
    }
}
