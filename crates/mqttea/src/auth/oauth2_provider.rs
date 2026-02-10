/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! OAuth2 token provider for MQTT authentication.
//!
//! This module provides an OAuth2 token provider that fetches access tokens
//! using the client credentials flow. The token can then be used as the MQTT
//! password by composing with [`TokenCredentialsProvider`].
//!
//! # MQTT OAuth2 Convention
//!
//! Many MQTT brokers that support OAuth2 use this convention:
//! - Username: A fixed string like "oauth2token" or the client_id
//! - Password: The OAuth2 access token
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use std::time::Duration;
//! use mqttea::auth::{OAuth2TokenProvider, OAuth2Config, TokenCredentialsProvider};
//! use mqttea::{MqtteaClient, ClientOptions};
//!
//! let config = OAuth2Config::new(
//!     "https://auth.example.com/oauth/token",
//!     "my-mqtt-client",
//!     "client-secret",
//!     vec!["mqtt:publish".into(), "mqtt:subscribe".into()],
//!     Duration::from_secs(30),
//! );
//!
//! let token_provider = OAuth2TokenProvider::new(config)?;
//! let credentials_provider = TokenCredentialsProvider::new(token_provider, "oauth2token");
//!
//! let options = ClientOptions::default()
//!     .with_credentials_provider(Arc::new(credentials_provider));
//!
//! let client = MqtteaClient::new("broker.example.com", 8883, "my-client", Some(options)).await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AccessToken, AsyncHttpClient, ClientId, ClientSecret, HttpRequest, HttpResponse, Scope,
    TokenResponse, TokenUrl,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use super::traits::TokenProvider;
use crate::errors::MqtteaClientError;

/// Configuration for OAuth2 token acquisition.
///
/// This struct contains only the parameters needed to obtain an access token
/// from an OAuth2 authorization server using the client credentials flow.
#[derive(Clone)]
pub struct OAuth2Config {
    /// The token endpoint URL (e.g., "https://auth.example.com/oauth/token").
    pub token_url: String,

    /// The OAuth2 client ID.
    pub client_id: String,

    /// The OAuth2 client secret.
    pub client_secret: String,

    /// Scopes to request (optional, depends on the auth server).
    pub scopes: Vec<String>,

    /// HTTP timeout for token requests.
    pub http_timeout: Duration,
}

impl std::fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Config")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("http_timeout", &self.http_timeout)
            .finish()
    }
}

impl OAuth2Config {
    /// Create a new OAuth2Config with all required fields.
    ///
    /// # Arguments
    ///
    /// * `token_url` - The OAuth2 token endpoint URL
    /// * `client_id` - The OAuth2 client ID
    /// * `client_secret` - The OAuth2 client secret
    /// * `scopes` - Scopes to request (can be empty if the server doesn't require them)
    /// * `http_timeout` - HTTP timeout for token requests
    pub fn new(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scopes: Vec<String>,
        http_timeout: Duration,
    ) -> Self {
        Self {
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes,
            http_timeout,
        }
    }
}

/// OAuth2 token provider that fetches access tokens using client credentials flow.
///
/// This provider handles:
/// - Token acquisition via OAuth2 client credentials flow
/// - Token caching with automatic refresh at 90% of expiry time
/// - Thread-safe concurrent access
///
/// Use [`TokenCredentialsProvider`] to combine this with an MQTT username.
pub struct OAuth2TokenProvider {
    http_client: reqwest::Client,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
    token_url: TokenUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    scopes: Vec<Scope>,
}

impl std::fmt::Debug for OAuth2TokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2TokenProvider")
            .field("token_url", &self.token_url.url().as_str())
            .field("client_id", &self.client_id.as_str())
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Cached token with expiry tracking.
#[derive(Clone)]
struct CachedToken {
    access_token: AccessToken,
    expires_at: Instant,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

impl OAuth2TokenProvider {
    /// Create a new OAuth2TokenProvider with the given configuration.
    ///
    /// This does NOT immediately fetch a token. The first call to `get_token()`
    /// will trigger the initial token fetch.
    pub fn new(config: OAuth2Config) -> Result<Self, MqtteaClientError> {
        let token_url = TokenUrl::new(config.token_url.clone())
            .map_err(|e| MqtteaClientError::CredentialsError(format!("Invalid token URL: {e}")))?;

        let http_client = reqwest::Client::builder()
            .timeout(config.http_timeout)
            .build()
            .map_err(|e| {
                MqtteaClientError::CredentialsError(format!("Failed to create HTTP client: {e}"))
            })?;

        let scopes = config.scopes.into_iter().map(Scope::new).collect();

        Ok(Self {
            http_client,
            token_cache: Arc::new(RwLock::new(None)),
            token_url,
            client_id: ClientId::new(config.client_id),
            client_secret: ClientSecret::new(config.client_secret),
            scopes,
        })
    }

    /// Fetch a fresh token from the OAuth2 server.
    async fn fetch_token(&self) -> Result<CachedToken, MqtteaClientError> {
        info!(
            token_url = %self.token_url.url(),
            client_id = %self.client_id.as_str(),
            "Fetching OAuth2 access token"
        );

        let client = BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_token_uri(self.token_url.clone());

        let mut request = client.exchange_client_credentials();
        for scope in &self.scopes {
            request = request.add_scope(scope.clone());
        }

        let http_client = AsyncHttpClientWrapper::new(&self.http_client);
        let token_result = request.request_async(&http_client).await.map_err(|e| {
            MqtteaClientError::CredentialsError(format!("OAuth2 token request failed: {e}"))
        })?;

        let access_token = token_result.access_token().clone();

        // Calculate expiry time at 90% of the total time to ensure the token is valid when used.
        // This matches the pattern from nvcf-invocation-service.
        let expires_in = token_result
            .expires_in()
            .ok_or_else(|| {
                MqtteaClientError::CredentialsError(
                    "Missing expiry time from OAuth2 token response".to_string(),
                )
            })?
            .mul_f32(0.90);

        let expires_at = Instant::now() + expires_in;

        debug!(
            expires_in_secs = expires_in.as_secs(),
            "Successfully obtained OAuth2 access token"
        );

        Ok(CachedToken {
            access_token,
            expires_at,
        })
    }
}

#[async_trait]
impl TokenProvider for OAuth2TokenProvider {
    async fn get_token(&self) -> Result<String, MqtteaClientError> {
        // Check if we have a valid cached token
        {
            let cache = self.token_cache.read().await;
            if let Some(ref token) = *cache
                && !token.is_expired()
            {
                debug!("Using cached OAuth2 token");
                return Ok(token.access_token.secret().clone());
            }
        }

        // Need to fetch a new token - acquire write lock
        let mut cache = self.token_cache.write().await;

        // Double-check: another task might have fetched while we waited for the write lock
        if let Some(ref token) = *cache
            && !token.is_expired()
        {
            debug!("Using cached OAuth2 token (fetched by another task)");
            return Ok(token.access_token.secret().clone());
        }

        // Fetch new token
        let new_token = self.fetch_token().await?;
        let token_value = new_token.access_token.secret().clone();
        *cache = Some(new_token);

        Ok(token_value)
    }
}

/// Async HTTP client wrapper for OAuth2 requests.
///
/// This is based on the `AsyncRequestHandlerWithTimeouts` pattern from
/// `crates/api/src/web/auth.rs`, providing a simple wrapper around
/// `reqwest::Client` that implements the `oauth2::AsyncHttpClient` trait.
struct AsyncHttpClientWrapper<'a> {
    client: &'a reqwest::Client,
}

impl<'a> AsyncHttpClientWrapper<'a> {
    fn new(client: &'a reqwest::Client) -> Self {
        Self { client }
    }
}

impl<'c> AsyncHttpClient<'c> for AsyncHttpClientWrapper<'_> {
    type Error = reqwest::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.client.execute(request.try_into()?).await?;
            let status = response.status();

            let mut builder = oauth2::http::Response::builder().status(status);
            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            let body = response.text().await?.into_bytes();

            if status.is_server_error() || status.is_client_error() {
                let body_str = std::str::from_utf8(&body).unwrap_or_default();
                error!(
                    body_str = %body_str,
                    "Error response when making HTTP request for OAuth2 flow"
                );
            }

            Ok(builder.body(body).unwrap())
        })
    }
}
