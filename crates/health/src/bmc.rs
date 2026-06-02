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

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::TryStreamExt;
use http::HeaderMap;
use http::header::{self, InvalidHeaderValue};
use nv_redfish::bmc_http::reqwest::{BmcError, Client as ReqwestClient};
use nv_redfish::bmc_http::{CacheSettings, HttpBmc};
use nv_redfish::core::query::{ExpandQuery, FilterQuery};
use nv_redfish::core::upload::{MultipartUpdateRequest, UploadReader};
use nv_redfish::core::{
    Action, Bmc, BoxTryStream, EntityTypeRef, Expandable, ModificationResponse, ODataETag, ODataId,
    SessionCreateResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell};
use url::Url;

use crate::HealthError;
use crate::endpoint::{BmcAddr, BmcCredentials};

pub(crate) const CREDENTIAL_REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub trait CredentialProvider: Send + Sync {
    fn fetch_credentials<'a>(
        &'a self,
        endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>>;
}

#[derive(Clone)]
pub struct FixedCredentialProvider {
    credentials: BmcCredentials,
}

impl FixedCredentialProvider {
    pub fn new(credentials: BmcCredentials) -> Self {
        Self { credentials }
    }
}

impl CredentialProvider for FixedCredentialProvider {
    fn fetch_credentials<'a>(
        &'a self,
        _endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
        let credentials = self.credentials.clone();
        Box::pin(async move { Ok(credentials) })
    }
}

pub struct BmcClient {
    inner: HttpBmc<ReqwestClient>,
    addr: BmcAddr,
    provider: Arc<dyn CredentialProvider>,
    credential_generation: AtomicU64,
    init: OnceCell<()>,
    refresh_lock: Mutex<()>,
}

impl BmcClient {
    pub fn new(
        reqwest: ReqwestClient,
        addr: BmcAddr,
        provider: Arc<dyn CredentialProvider>,
        proxy_url: Option<Url>,
        cache_size: usize,
    ) -> Result<Self, HealthError> {
        let bmc_url = bmc_url(&addr, proxy_url.as_ref())?;
        let headers = bmc_headers(&addr, proxy_url.as_ref())?;

        // Currently nv-redfish BMC, requires credentials, so this placeholder is sued
        // they will be replaced as soon as we call ensure_credentials
        let placeholder =
            nv_redfish::bmc_http::BmcCredentials::username_password(String::new(), None::<String>);
        let inner = HttpBmc::with_custom_headers(
            reqwest,
            bmc_url,
            placeholder,
            CacheSettings::with_capacity(cache_size),
            headers,
        );
        Ok(Self {
            inner,
            addr,
            provider,
            credential_generation: AtomicU64::new(0),
            init: OnceCell::new(),
            refresh_lock: Mutex::new(()),
        })
    }

    pub async fn ensure_credentials(&self) -> Result<(), HealthError> {
        self.init
            .get_or_try_init(|| async {
                let credentials = tokio::time::timeout(
                    CREDENTIAL_REFRESH_TIMEOUT,
                    self.provider.fetch_credentials(&self.addr),
                )
                .await
                .map_err(|_elapsed| {
                    HealthError::GenericError(format!(
                        "Timed out after {}s fetching initial BMC credentials",
                        CREDENTIAL_REFRESH_TIMEOUT.as_secs(),
                    ))
                })??;
                self.inner.set_credentials(credentials.into());
                self.credential_generation.fetch_add(1, Ordering::AcqRel);
                Ok::<_, HealthError>(())
            })
            .await?;
        Ok(())
    }

    pub fn credential_provider(&self) -> Arc<dyn CredentialProvider> {
        self.provider.clone()
    }

    async fn refresh_credentials(
        &self,
        error: &HealthError,
        observed_generation: Option<u64>,
    ) -> Result<(), HealthError> {
        let _guard = self.refresh_lock.lock().await;
        if observed_generation.is_some_and(|generation| {
            generation != self.credential_generation.load(Ordering::Acquire)
        }) {
            return Ok(());
        }

        tracing::warn!(
            error = ?error,
            endpoint = ?self.addr,
            "Authentication failed, refreshing BMC credentials"
        );

        let credentials = tokio::time::timeout(
            CREDENTIAL_REFRESH_TIMEOUT,
            self.provider.fetch_credentials(&self.addr),
        )
        .await
        .map_err(|_elapsed| {
            HealthError::GenericError(format!(
                "Timed out after {}s refreshing BMC credentials following auth error {error}",
                CREDENTIAL_REFRESH_TIMEOUT.as_secs(),
            ))
        })?
        .map_err(|refresh_error| {
            HealthError::GenericError(format!(
                "Failed to refresh credentials after auth error {error}: {refresh_error}"
            ))
        })?;
        self.inner.set_credentials(credentials.into());
        self.credential_generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn refresh_auth_if_needed(
        &self,
        error: HealthError,
        observed_generation: u64,
    ) -> HealthError {
        if is_auth_error(&error)
            && let Err(refresh_error) = self
                .refresh_credentials(&error, Some(observed_generation))
                .await
        {
            tracing::error!(
                error = ?refresh_error,
                original_error = ?error,
                endpoint = ?self.addr,
                "Failed to refresh BMC credentials after authentication error"
            );
        }

        error
    }
}

fn bmc_url(addr: &BmcAddr, proxy_url: Option<&Url>) -> Result<Url, HealthError> {
    match proxy_url {
        Some(url) => Ok(url.clone()),
        None => addr
            .to_url()
            .map_err(|e| HealthError::GenericError(e.to_string())),
    }
}

fn bmc_headers(addr: &BmcAddr, proxy_url: Option<&Url>) -> Result<HeaderMap, HealthError> {
    let mut headers = HeaderMap::new();
    if proxy_url.is_some() {
        headers.insert(
            header::FORWARDED,
            format!("host={}", addr.ip)
                .parse()
                .map_err(|e: InvalidHeaderValue| HealthError::GenericError(e.to_string()))?,
        );
    }
    Ok(headers)
}

impl Bmc for BmcClient {
    type Error = HealthError;

    async fn expand<T: Expandable>(
        &self,
        id: &ODataId,
        query: ExpandQuery,
    ) -> Result<Arc<T>, Self::Error> {
        self.ensure_credentials().await?;
        let credential_generation = self.credential_generation.load(Ordering::Acquire);
        match self
            .inner
            .expand(id, query)
            .await
            .map_err(HealthError::from)
        {
            Ok(value) => Ok(value),
            Err(error) => Err(self
                .refresh_auth_if_needed(error, credential_generation)
                .await),
        }
    }

    async fn get<T: EntityTypeRef + for<'de> Deserialize<'de> + 'static>(
        &self,
        id: &ODataId,
    ) -> Result<Arc<T>, Self::Error> {
        self.ensure_credentials().await?;
        let credential_generation = self.credential_generation.load(Ordering::Acquire);
        match self.inner.get(id).await.map_err(HealthError::from) {
            Ok(value) => Ok(value),
            Err(error) => Err(self
                .refresh_auth_if_needed(error, credential_generation)
                .await),
        }
    }

    async fn filter<T: EntityTypeRef + for<'de> Deserialize<'de> + 'static>(
        &self,
        id: &ODataId,
        query: FilterQuery,
    ) -> Result<Arc<T>, Self::Error> {
        self.ensure_credentials().await?;
        let credential_generation = self.credential_generation.load(Ordering::Acquire);
        match self
            .inner
            .filter(id, query)
            .await
            .map_err(HealthError::from)
        {
            Ok(value) => Ok(value),
            Err(error) => Err(self
                .refresh_auth_if_needed(error, credential_generation)
                .await),
        }
    }

    async fn create<V: Send + Sync + Serialize, R: Send + Sync + for<'de> Deserialize<'de>>(
        &self,
        id: &ODataId,
        query: &V,
    ) -> Result<ModificationResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.inner
            .create(id, query)
            .await
            .map_err(HealthError::from)
    }

    async fn update<
        V: Sync + Send + Serialize,
        R: Send + Sync + Sized + for<'de> Deserialize<'de>,
    >(
        &self,
        id: &ODataId,
        etag: Option<&ODataETag>,
        update: &V,
    ) -> Result<ModificationResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.inner
            .update(id, etag, update)
            .await
            .map_err(HealthError::from)
    }

    async fn multipart_update<U, V, R>(
        &self,
        uri: &str,
        request: MultipartUpdateRequest<'_, U, V>,
    ) -> Result<ModificationResponse<R>, Self::Error>
    where
        U: UploadReader,
        R: Send + Sync + for<'de> Deserialize<'de>,
        V: Send + Sync + Serialize,
    {
        self.ensure_credentials().await?;
        self.inner
            .multipart_update(uri, request)
            .await
            .map_err(HealthError::from)
    }

    async fn delete<R: EntityTypeRef + for<'de> Deserialize<'de>>(
        &self,
        id: &ODataId,
    ) -> Result<ModificationResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.inner.delete(id).await.map_err(HealthError::from)
    }

    async fn action<
        T: Send + Sync + Serialize,
        R: Send + Sync + Sized + for<'de> Deserialize<'de>,
    >(
        &self,
        action: &Action<T, R>,
        params: &T,
    ) -> Result<ModificationResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.inner
            .action(action, params)
            .await
            .map_err(HealthError::from)
    }

    async fn stream<T: Sized + for<'de> Deserialize<'de> + Send + 'static>(
        &self,
        uri: &str,
    ) -> Result<BoxTryStream<T, Self::Error>, Self::Error> {
        self.ensure_credentials().await?;
        let credential_generation = self.credential_generation.load(Ordering::Acquire);
        match self.inner.stream(uri).await.map_err(HealthError::from) {
            Ok(stream) => Ok(Box::pin(stream.map_err(HealthError::from))),
            Err(error) => Err(self
                .refresh_auth_if_needed(error, credential_generation)
                .await),
        }
    }

    async fn create_session<
        V: Send + Sync + Serialize,
        R: Send + Sync + for<'de> Deserialize<'de>,
    >(
        &self,
        id: &ODataId,
        query: &V,
    ) -> Result<SessionCreateResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.inner
            .create_session(id, query)
            .await
            .map_err(HealthError::from)
    }
}

pub(crate) fn is_auth_error(error: &HealthError) -> bool {
    match error {
        HealthError::HttpError(message) => {
            message.contains("HTTP 401") || message.contains("HTTP 403")
        }
        HealthError::BmcError(inner) => is_auth_bmc_source_error(inner.as_ref()),
        _ => false,
    }
}

pub(crate) fn is_auth_bmc_source_error(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<BmcError>()
        .is_some_and(is_auth_bmc_error)
        || error
            .downcast_ref::<HealthError>()
            .is_some_and(is_auth_error)
}

fn is_auth_bmc_error(error: &BmcError) -> bool {
    matches!(
        error,
        BmcError::InvalidResponse { status, .. }
            if *status == http::StatusCode::UNAUTHORIZED || *status == http::StatusCode::FORBIDDEN
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use mac_address::MacAddress;
    use nv_redfish::bmc_http::reqwest::ClientParams as ReqwestClientParams;

    use super::*;
    use crate::endpoint::BmcAddr;

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        delay: Option<Duration>,
        credentials: BmcCredentials,
    }

    impl CountingProvider {
        fn new(
            credentials: BmcCredentials,
            delay: Option<Duration>,
        ) -> (Arc<Self>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let provider = Arc::new(Self {
                calls: calls.clone(),
                delay,
                credentials,
            });
            (provider, calls)
        }
    }

    impl CredentialProvider for CountingProvider {
        fn fetch_credentials<'a>(
            &'a self,
            _endpoint: &'a BmcAddr,
        ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
            let delay = self.delay;
            let credentials = self.credentials.clone();
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Box::pin(async move {
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
                Ok(credentials)
            })
        }
    }

    fn test_addr() -> BmcAddr {
        BmcAddr {
            ip: "10.0.0.1".parse().unwrap(),
            port: Some(443),
            mac: MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        }
    }

    fn reqwest() -> ReqwestClient {
        ReqwestClient::with_params(ReqwestClientParams::new().accept_invalid_certs(true))
            .expect("reqwest client builds")
    }

    fn bmc_status_error(status: http::StatusCode) -> BmcError {
        BmcError::InvalidResponse {
            url: Url::parse("https://127.0.0.1/redfish/v1").expect("valid url"),
            status,
            text: String::new(),
        }
    }

    #[test]
    fn detects_auth_bmc_errors() {
        assert!(is_auth_bmc_error(&bmc_status_error(
            http::StatusCode::UNAUTHORIZED
        )));
        assert!(is_auth_bmc_error(&bmc_status_error(
            http::StatusCode::FORBIDDEN
        )));
        assert!(!is_auth_bmc_error(&bmc_status_error(
            http::StatusCode::NOT_FOUND
        )));
    }

    #[test]
    fn detects_auth_health_errors() {
        assert!(is_auth_error(&HealthError::BmcError(Box::new(
            bmc_status_error(http::StatusCode::UNAUTHORIZED),
        ))));
        assert!(is_auth_error(&HealthError::HttpError(
            "request failed with HTTP 403".to_string(),
        )));
        assert!(!is_auth_error(&HealthError::HttpError(
            "request failed with HTTP 404".to_string(),
        )));
    }

    #[tokio::test]
    async fn new_does_not_fetch_credentials_eagerly() {
        let (provider, calls) = CountingProvider::new(
            BmcCredentials::UsernamePassword {
                username: "u".to_string(),
                password: Some("p".to_string()),
            },
            None,
        );
        let client = BmcClient::new(reqwest(), test_addr(), provider, None, 10)
            .expect("constructor succeeds");

        assert_eq!(
            calls.load(AtomicOrdering::SeqCst),
            0,
            "construction must not call the credential provider"
        );
        assert_eq!(
            client.credential_generation.load(Ordering::Acquire),
            0,
            "generation stays 0 until first successful fetch"
        );
    }

    #[tokio::test]
    async fn ensure_credentials_calls_provider_exactly_once_under_concurrency() {
        let (provider, calls) = CountingProvider::new(
            BmcCredentials::SessionToken {
                token: "t".to_string(),
            },
            Some(Duration::from_millis(50)),
        );
        let client =
            Arc::new(BmcClient::new(reqwest(), test_addr(), provider, None, 10).expect("ok"));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let client = client.clone();
            handles.push(tokio::spawn(
                async move { client.ensure_credentials().await },
            ));
        }
        for h in handles {
            h.await.expect("task").expect("ensure ok");
        }

        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(client.credential_generation.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn ensure_credentials_retries_after_failed_fetch() {
        struct FlakyProvider {
            attempts: AtomicUsize,
        }

        impl CredentialProvider for FlakyProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                let attempt = self.attempts.fetch_add(1, AtomicOrdering::SeqCst);
                Box::pin(async move {
                    if attempt == 0 {
                        Err(HealthError::GenericError("transient".to_string()))
                    } else {
                        Ok(BmcCredentials::SessionToken {
                            token: "t".to_string(),
                        })
                    }
                })
            }
        }

        let provider = Arc::new(FlakyProvider {
            attempts: AtomicUsize::new(0),
        });
        let client = BmcClient::new(reqwest(), test_addr(), provider.clone(), None, 10)
            .expect("constructor succeeds");

        assert!(client.ensure_credentials().await.is_err());
        assert_eq!(client.credential_generation.load(Ordering::Acquire), 0);
        assert!(client.ensure_credentials().await.is_ok());
        assert_eq!(client.credential_generation.load(Ordering::Acquire), 1);
        assert_eq!(provider.attempts.load(AtomicOrdering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_refresh_collapses_to_a_single_provider_call() {
        let (provider, calls) = CountingProvider::new(
            BmcCredentials::SessionToken {
                token: "t".to_string(),
            },
            Some(Duration::from_millis(50)),
        );
        let client =
            Arc::new(BmcClient::new(reqwest(), test_addr(), provider, None, 10).expect("ok"));
        client.ensure_credentials().await.expect("init ok");
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);

        let observed = client.credential_generation.load(Ordering::Acquire);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                client
                    .refresh_credentials(
                        &HealthError::HttpError("HTTP 401".to_string()),
                        Some(observed),
                    )
                    .await
            }));
        }
        for h in handles {
            h.await.expect("task").expect("refresh ok");
        }

        // One init fetch + exactly one refresh fetch.
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(client.credential_generation.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn refresh_consumes_provider_and_bumps_generation() {
        struct SequenceProvider {
            tokens: StdMutex<Vec<&'static str>>,
            handed_out: StdMutex<Vec<&'static str>>,
            calls: Arc<AtomicUsize>,
        }

        impl CredentialProvider for SequenceProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                self.calls.fetch_add(1, AtomicOrdering::SeqCst);
                let token = self
                    .tokens
                    .lock()
                    .unwrap()
                    .pop()
                    .expect("token sequence exhausted");
                self.handed_out.lock().unwrap().push(token);
                Box::pin(async move {
                    Ok(BmcCredentials::SessionToken {
                        token: token.to_string(),
                    })
                })
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(SequenceProvider {
            tokens: StdMutex::new(vec!["second", "first"]),
            handed_out: StdMutex::new(Vec::new()),
            calls: calls.clone(),
        });
        let client = BmcClient::new(reqwest(), test_addr(), provider.clone(), None, 10)
            .expect("constructor ok");

        client.ensure_credentials().await.expect("init ok");
        assert_eq!(client.credential_generation.load(Ordering::Acquire), 1);

        client
            .refresh_credentials(&HealthError::HttpError("HTTP 401".to_string()), None)
            .await
            .expect("refresh ok");

        assert_eq!(client.credential_generation.load(Ordering::Acquire), 2);
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(
            provider.handed_out.lock().unwrap().as_slice(),
            &["first", "second"],
            "init must consume the first token, refresh the second"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_credentials_respects_timeout() {
        struct HangingProvider;

        impl CredentialProvider for HangingProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                Box::pin(std::future::pending())
            }
        }

        let client = Arc::new(
            BmcClient::new(reqwest(), test_addr(), Arc::new(HangingProvider), None, 10)
                .expect("constructor ok"),
        );
        let refresh_client = client.clone();
        let refresh = tokio::spawn(async move {
            refresh_client
                .refresh_credentials(&HealthError::HttpError("HTTP 401".to_string()), None)
                .await
        });

        // Sleep just past the timeout so the timer fires; tokio's paused
        // clock auto-advances via tokio::time::advance.
        tokio::time::advance(CREDENTIAL_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        let result = refresh.await.expect("task joined");
        assert!(result.is_err(), "hanging provider must surface as timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_credentials_respects_timeout() {
        struct HangingProvider;

        impl CredentialProvider for HangingProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                Box::pin(std::future::pending())
            }
        }

        let client = Arc::new(
            BmcClient::new(reqwest(), test_addr(), Arc::new(HangingProvider), None, 10)
                .expect("constructor ok"),
        );
        let ensure_client = client.clone();
        let ensure = tokio::spawn(async move { ensure_client.ensure_credentials().await });

        tokio::time::advance(CREDENTIAL_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        let result = ensure.await.expect("task joined");
        let error = result.expect_err("hanging provider must surface as timeout");
        match error {
            HealthError::GenericError(msg) => assert!(
                msg.contains("Timed out") && msg.contains("initial BMC credentials"),
                "expected timeout message, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }

        // OnceCell must not have latched the failure — a subsequent call
        // with a working provider has to be able to succeed.
        let (recovery_provider, recovery_calls) = CountingProvider::new(
            BmcCredentials::SessionToken {
                token: "t".to_string(),
            },
            None,
        );
        let recovered = BmcClient::new(reqwest(), test_addr(), recovery_provider, None, 10)
            .expect("constructor ok");
        recovered.ensure_credentials().await.expect("recovery ok");
        assert_eq!(recovery_calls.load(AtomicOrdering::SeqCst), 1);
    }
}
