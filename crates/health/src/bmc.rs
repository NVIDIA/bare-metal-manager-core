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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

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

/// How long the per-endpoint circuit stays open after the first connect-level
/// failure. Subsequent failed probes double this up to [`CIRCUIT_MAX_BACKOFF`].
const CIRCUIT_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
/// Upper bound on the circuit backoff window.
const CIRCUIT_MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How long a single half-open probe is allowed to run before the circuit lets
/// another caller probe. This only matters if a probe is lost (e.g. its future
/// is cancelled) — it stops the circuit from latching half-open forever. It is
/// deliberately longer than a BMC connect timeout.
const CIRCUIT_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-endpoint connection circuit breaker state.
///
/// When a BMC stops answering at the network level, every collector sharing the
/// endpoint's [`BmcClient`] would otherwise keep firing requests that each block
/// for a full TCP connect timeout — hundreds of them per sensor sweep — and log
/// a warning apiece. The breaker short-circuits those requests after the first
/// connect-level failure so a dead endpoint costs one failed probe per backoff
/// window instead of a flood. See NVBug 6036327.
#[derive(Debug)]
enum CircuitState {
    /// Requests flow normally.
    Closed,
    /// Requests fast-fail until `until`; `backoff` is the window that was applied.
    Open { until: Instant, backoff: Duration },
    /// A single probe has been let through and is in flight until `deadline`;
    /// other callers fast-fail. `backoff` is the window to escalate from if the
    /// probe fails.
    Probing {
        deadline: Instant,
        backoff: Duration,
    },
}

/// What a batch-oriented collector should do this iteration, derived from the
/// endpoint's circuit state via [`BmcClient::collector_sweep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorSweep {
    /// Circuit closed — run the full batch as normal.
    Full,
    /// Backoff window elapsed — send a single probe to test reachability instead
    /// of the full fan-out, so a still-dead BMC costs one request, not hundreds.
    Probe,
    /// Circuit open within the backoff window — skip entirely.
    Skip,
}

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
    circuit: StdMutex<CircuitState>,
    /// Lock-free fast-path hint mirroring `circuit`: `false` iff the circuit is
    /// `Closed`. Lets the healthy request path (the overwhelmingly common case)
    /// skip the mutex entirely. It is only ever set to `true` while holding the
    /// `circuit` lock as the state leaves `Closed`, and cleared while holding it
    /// as the state returns to `Closed`, so the invariant "circuit is blocking
    /// ⟹ `circuit_tripped` is `true`" always holds. A stale `false` read just
    /// means a request that was already racing an open-transition proceeds —
    /// harmless, identical to a request already in flight when the circuit trips.
    circuit_tripped: AtomicBool,
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
            circuit: StdMutex::new(CircuitState::Closed),
            circuit_tripped: AtomicBool::new(false),
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

    /// Run a BMC operation through the connection circuit breaker.
    ///
    /// Fast-fails (without touching the network) while the circuit is open, and
    /// updates the breaker based on the outcome. A connect-level failure trips
    /// it. Any other outcome — a success, or a non-connection error such as a
    /// 404/auth/decode — means the BMC actually answered, so it closes the
    /// circuit. Closing on a non-connection error matters for the half-open
    /// probe: without it a reachable-but-erroring BMC would stay fast-failed
    /// until the probe deadline.
    async fn guarded<T>(
        &self,
        op: impl std::future::Future<Output = Result<T, HealthError>>,
    ) -> Result<T, HealthError> {
        self.check_circuit()?;
        match op.await {
            Ok(value) => {
                self.note_reachable();
                Ok(value)
            }
            Err(error) => {
                if is_connection_error(&error) {
                    self.trip_circuit(&error);
                } else {
                    // The BMC responded (just not happily); it is reachable.
                    self.note_reachable();
                }
                Err(error)
            }
        }
    }

    /// Gate an attempt against the circuit. Returns the fast-fail error while the
    /// circuit is open, and otherwise lets the caller proceed — promoting an
    /// expired `Open` (or a lost `Probing`) circuit to a fresh half-open probe.
    fn check_circuit(&self) -> Result<(), HealthError> {
        // Fast path: a healthy (closed) circuit never touches the mutex.
        if !self.circuit_tripped.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.circuit.lock().expect("circuit mutex poisoned");
        match *state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open { until, backoff } => {
                if Instant::now() >= until {
                    *state = CircuitState::Probing {
                        deadline: Instant::now() + CIRCUIT_PROBE_TIMEOUT,
                        backoff,
                    };
                    Ok(())
                } else {
                    Err(self.circuit_open_error())
                }
            }
            CircuitState::Probing { deadline, backoff } => {
                // A probe is already in flight; everyone else waits. If the probe
                // was lost (deadline passed without a result), let a new one run.
                if Instant::now() >= deadline {
                    *state = CircuitState::Probing {
                        deadline: Instant::now() + CIRCUIT_PROBE_TIMEOUT,
                        backoff,
                    };
                    Ok(())
                } else {
                    Err(self.circuit_open_error())
                }
            }
        }
    }

    /// Record that the BMC answered, closing the circuit if it was open.
    fn note_reachable(&self) {
        // Fast path: already closed — nothing to do, no lock.
        if !self.circuit_tripped.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.circuit.lock().expect("circuit mutex poisoned");
        if !matches!(*state, CircuitState::Closed) {
            tracing::info!(endpoint = ?self.addr, "BMC is reachable again; closing connection circuit");
            *state = CircuitState::Closed;
        }
        // Clear the hint while still holding the lock so it can never lag the
        // state into a `Closed`-but-`tripped` window that the fast path would
        // wrongly treat as blocking.
        self.circuit_tripped.store(false, Ordering::Release);
    }

    /// Open (or escalate) the circuit after a connect-level failure.
    fn trip_circuit(&self, error: &HealthError) {
        let mut state = self.circuit.lock().expect("circuit mutex poisoned");
        match *state {
            CircuitState::Closed => {
                *state = CircuitState::Open {
                    until: Instant::now() + CIRCUIT_INITIAL_BACKOFF,
                    backoff: CIRCUIT_INITIAL_BACKOFF,
                };
                tracing::warn!(
                    endpoint = ?self.addr,
                    backoff_seconds = CIRCUIT_INITIAL_BACKOFF.as_secs(),
                    error = ?error,
                    "BMC connect failure; opening connection circuit to stop request flood"
                );
            }
            CircuitState::Probing { backoff, .. } => {
                // The half-open probe failed: keep the circuit open and back off
                // further before the next probe.
                let next = (backoff * 2).min(CIRCUIT_MAX_BACKOFF);
                *state = CircuitState::Open {
                    until: Instant::now() + next,
                    backoff: next,
                };
                tracing::debug!(
                    endpoint = ?self.addr,
                    backoff_seconds = next.as_secs(),
                    "BMC still unreachable; extending connection circuit backoff"
                );
            }
            // Already open: this is a request that was in flight before the
            // circuit opened. Leave the existing window untouched.
            CircuitState::Open { .. } => {}
        }
        // Every branch above leaves the circuit non-`Closed`; publish the hint
        // while still holding the lock so the fast path observes it.
        self.circuit_tripped.store(true, Ordering::Release);
    }

    /// What a batch-oriented caller (e.g. the sensor sweep) should do this
    /// iteration, so it can avoid both the request flood and its log spam:
    /// run the full batch, send a single probe, or skip entirely. Reading this
    /// once up front — rather than letting each request fast-fail individually —
    /// keeps a dead endpoint from re-emitting a per-request burst every time the
    /// backoff window elapses.
    pub fn collector_sweep(&self) -> CollectorSweep {
        // Fast path: a closed circuit runs normally and never takes the lock.
        if !self.circuit_tripped.load(Ordering::Acquire) {
            return CollectorSweep::Full;
        }
        let state = self.circuit.lock().expect("circuit mutex poisoned");
        match *state {
            CircuitState::Closed => CollectorSweep::Full,
            CircuitState::Open { until, .. } => {
                if Instant::now() < until {
                    CollectorSweep::Skip
                } else {
                    CollectorSweep::Probe
                }
            }
            CircuitState::Probing { deadline, .. } => {
                if Instant::now() < deadline {
                    CollectorSweep::Skip
                } else {
                    CollectorSweep::Probe
                }
            }
        }
    }

    fn circuit_open_error(&self) -> HealthError {
        HealthError::GenericError(format!(
            "BMC {} is unreachable; request skipped while the connection circuit breaker is open",
            self.addr.ip
        ))
    }

    /// Seed the circuit state and its fast-path hint coherently. Tests use this
    /// instead of writing the mutex directly so the `circuit_tripped` invariant
    /// is never violated.
    #[cfg(test)]
    fn set_circuit_for_test(&self, state: CircuitState) {
        let tripped = !matches!(state, CircuitState::Closed);
        *self.circuit.lock().expect("circuit mutex poisoned") = state;
        self.circuit_tripped.store(tripped, Ordering::Release);
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
            .guarded(async {
                self.inner
                    .expand(id, query)
                    .await
                    .map_err(HealthError::from)
            })
            .await
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
        match self
            .guarded(async { self.inner.get(id).await.map_err(HealthError::from) })
            .await
        {
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
            .guarded(async {
                self.inner
                    .filter(id, query)
                    .await
                    .map_err(HealthError::from)
            })
            .await
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
        self.guarded(async {
            self.inner
                .create(id, query)
                .await
                .map_err(HealthError::from)
        })
        .await
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
        self.guarded(async {
            self.inner
                .update(id, etag, update)
                .await
                .map_err(HealthError::from)
        })
        .await
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
        self.guarded(async {
            self.inner
                .multipart_update(uri, request)
                .await
                .map_err(HealthError::from)
        })
        .await
    }

    async fn delete<R: EntityTypeRef + for<'de> Deserialize<'de>>(
        &self,
        id: &ODataId,
    ) -> Result<ModificationResponse<R>, Self::Error> {
        self.ensure_credentials().await?;
        self.guarded(async { self.inner.delete(id).await.map_err(HealthError::from) })
            .await
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
        self.guarded(async {
            self.inner
                .action(action, params)
                .await
                .map_err(HealthError::from)
        })
        .await
    }

    async fn stream<T: Sized + for<'de> Deserialize<'de> + Send + 'static>(
        &self,
        uri: &str,
    ) -> Result<BoxTryStream<T, Self::Error>, Self::Error> {
        self.ensure_credentials().await?;
        let credential_generation = self.credential_generation.load(Ordering::Acquire);
        match self
            .guarded(async { self.inner.stream(uri).await.map_err(HealthError::from) })
            .await
        {
            // Only stream *establishment* runs through the breaker. Per-item
            // errors on the returned long-lived stream (e.g. a mid-stream SSE
            // disconnect) are intentionally not fed back into it: streaming
            // collectors own a reconnect loop with their own exponential backoff,
            // and the breaker is scoped to the periodic-collector request flood —
            // many short requests against a dead endpoint — not a single
            // long-lived connection. Routing item errors here would also couple
            // log-stream health to sensor/discovery collection.
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
        self.guarded(async {
            self.inner
                .create_session(id, query)
                .await
                .map_err(HealthError::from)
        })
        .await
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

/// Whether an error represents the BMC being unreachable at the transport layer
/// (TCP connect refused/timed out, or a request that timed out) — as opposed to
/// the BMC answering with an error. Only these trip the connection circuit
/// breaker; an HTTP 404 or a decode error means the BMC is alive and talking.
pub(crate) fn is_connection_error(error: &HealthError) -> bool {
    match error {
        HealthError::BmcError(inner) => is_connection_bmc_source_error(inner.as_ref()),
        _ => false,
    }
}

fn is_connection_bmc_source_error(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<BmcError>()
        .is_some_and(is_connection_bmc_error)
        || error
            .downcast_ref::<HealthError>()
            .is_some_and(is_connection_error)
}

fn is_connection_bmc_error(error: &BmcError) -> bool {
    matches!(error, BmcError::ReqwestError(e) if e.is_connect() || e.is_timeout())
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

    fn test_client() -> BmcClient {
        let (provider, _) = CountingProvider::new(
            BmcCredentials::SessionToken {
                token: "t".to_string(),
            },
            None,
        );
        BmcClient::new(reqwest(), test_addr(), provider, None, 10).expect("constructor ok")
    }

    fn dummy_error() -> HealthError {
        HealthError::GenericError("boom".to_string())
    }

    #[test]
    fn non_connection_errors_do_not_trip_the_circuit() {
        // 401/403, 404, and generic errors mean the BMC answered (or the failure
        // is unrelated to reachability) — they must not open the breaker.
        assert!(!is_connection_error(&HealthError::BmcError(Box::new(
            bmc_status_error(http::StatusCode::UNAUTHORIZED)
        ))));
        assert!(!is_connection_error(&HealthError::BmcError(Box::new(
            bmc_status_error(http::StatusCode::NOT_FOUND)
        ))));
        assert!(!is_connection_error(&HealthError::HttpError(
            "HTTP 404".to_string()
        )));
        assert!(!is_connection_error(&dummy_error()));
    }

    #[tokio::test]
    async fn real_connect_failure_is_classified_and_trips_the_circuit() {
        // Reserve an ephemeral port, then release it, so connecting to it is
        // refused — a real, deterministic transport-level failure with no
        // fixed-port collision and no waiting on a timeout. This exercises the
        // whole chain end to end (reqwest error -> BmcError -> HealthError ->
        // is_connection_error -> trip_circuit), guarding the assumption that a
        // genuine connect failure — the production flood was `Connect, TimedOut`
        // — is actually classified as a connection error. See NVBug 6036327.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let (provider, _) = CountingProvider::new(
            BmcCredentials::SessionToken {
                token: "t".to_string(),
            },
            None,
        );
        let addr = BmcAddr {
            ip: "127.0.0.1".parse().expect("loopback ip"),
            port: Some(port),
            mac: MacAddress::from_str("00:11:22:33:44:55").expect("mac"),
        };
        let client =
            Arc::new(BmcClient::new(reqwest(), addr, provider, None, 10).expect("constructor ok"));

        assert_eq!(
            client.collector_sweep(),
            CollectorSweep::Full,
            "circuit starts closed"
        );

        // Any real Redfish read against the closed port fails to connect.
        let result = nv_redfish::ServiceRoot::new(client.clone()).await;
        assert!(result.is_err(), "connecting to a closed port must fail");

        assert_eq!(
            client.collector_sweep(),
            CollectorSweep::Skip,
            "a genuine connect failure must be classified as a connection error and open the breaker"
        );
    }

    #[test]
    fn circuit_opens_on_failure_then_closes_on_success() {
        let client = test_client();

        // Starts closed: requests flow.
        assert_eq!(client.collector_sweep(), CollectorSweep::Full);
        assert!(client.check_circuit().is_ok());

        // A connect-level failure opens the circuit.
        client.trip_circuit(&dummy_error());
        assert_eq!(client.collector_sweep(), CollectorSweep::Skip);
        assert!(
            client.check_circuit().is_err(),
            "open circuit must fast-fail"
        );

        // A success closes it again.
        client.note_reachable();
        assert_eq!(client.collector_sweep(), CollectorSweep::Full);
        assert!(client.check_circuit().is_ok());
    }

    #[tokio::test]
    async fn non_connection_error_during_probe_closes_circuit() {
        let client = test_client();

        // An open window that has elapsed: the next caller through `guarded`
        // becomes the half-open probe.
        client.set_circuit_for_test(CircuitState::Open {
            until: Instant::now() - Duration::from_secs(1),
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });

        // The probe reaches the BMC and gets a real (non-connection) error.
        let result: Result<(), HealthError> = client
            .guarded(async {
                Err(HealthError::BmcError(Box::new(bmc_status_error(
                    http::StatusCode::NOT_FOUND,
                ))))
            })
            .await;
        assert!(result.is_err());

        assert_eq!(
            client.collector_sweep(),
            CollectorSweep::Full,
            "a non-connection response proves reachability and must close the circuit, \
             not leave it half-open until the probe deadline"
        );
    }

    #[test]
    fn collector_sweep_probes_once_window_elapses() {
        let client = test_client();
        client.set_circuit_for_test(CircuitState::Open {
            until: Instant::now() - Duration::from_secs(1),
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });
        assert_eq!(
            client.collector_sweep(),
            CollectorSweep::Probe,
            "an elapsed backoff window should admit a single probe, not a full sweep"
        );
    }

    #[test]
    fn fast_path_hint_tracks_circuit_state() {
        let client = test_client();

        // Closed: hint clear.
        assert!(!client.circuit_tripped.load(Ordering::Acquire));

        // Tripped: hint set so the lock-free fast path consults the lock.
        client.trip_circuit(&dummy_error());
        assert!(client.circuit_tripped.load(Ordering::Acquire));

        // Reachable again: hint cleared so the fast path stays lock-free.
        client.note_reachable();
        assert!(!client.circuit_tripped.load(Ordering::Acquire));

        // Promoting an expired Open to a half-open probe keeps the hint set
        // (still non-closed).
        client.set_circuit_for_test(CircuitState::Open {
            until: Instant::now() - Duration::from_secs(1),
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });
        assert!(client.check_circuit().is_ok());
        assert!(client.circuit_tripped.load(Ordering::Acquire));
    }

    #[test]
    fn expired_open_circuit_admits_exactly_one_probe() {
        let client = test_client();

        // Simulate an open window that has already elapsed.
        client.set_circuit_for_test(CircuitState::Open {
            until: Instant::now() - Duration::from_secs(1),
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });

        // The first caller is let through as the probe...
        assert!(client.check_circuit().is_ok(), "probe should be admitted");
        assert!(
            matches!(
                *client.circuit.lock().unwrap(),
                CircuitState::Probing { .. }
            ),
            "circuit should be half-open after admitting a probe"
        );
        // ...and everyone else keeps fast-failing while the probe is in flight.
        assert!(client.check_circuit().is_err());
        assert_eq!(client.collector_sweep(), CollectorSweep::Skip);
    }

    #[test]
    fn failed_probe_escalates_backoff() {
        let client = test_client();

        client.set_circuit_for_test(CircuitState::Probing {
            deadline: Instant::now() + CIRCUIT_PROBE_TIMEOUT,
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });

        client.trip_circuit(&dummy_error());

        match *client.circuit.lock().unwrap() {
            CircuitState::Open { backoff, .. } => assert_eq!(
                backoff,
                (CIRCUIT_INITIAL_BACKOFF * 2).min(CIRCUIT_MAX_BACKOFF),
                "a failed probe must double the backoff window"
            ),
            ref other => panic!("expected Open after failed probe, got {other:?}"),
        }
    }

    #[test]
    fn stale_failure_while_open_does_not_extend_backoff() {
        let client = test_client();

        client.set_circuit_for_test(CircuitState::Open {
            until: Instant::now() + CIRCUIT_INITIAL_BACKOFF,
            backoff: CIRCUIT_INITIAL_BACKOFF,
        });

        // A request that was already in flight when the circuit opened fails. It
        // must not push the backoff window out further.
        client.trip_circuit(&dummy_error());

        match *client.circuit.lock().unwrap() {
            CircuitState::Open { backoff, .. } => {
                assert_eq!(
                    backoff, CIRCUIT_INITIAL_BACKOFF,
                    "backoff must be unchanged"
                )
            }
            ref other => panic!("expected Open, got {other:?}"),
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
