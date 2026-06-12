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

//! Per-SPIFFE-caller BMC Redfish session token manager.
//!
//! Issues one live `X-Auth-Token` per `(SPIFFE service id, BMC MAC)` pair by
//! calling `nv-redfish` directly. Every call to [`BmcSessionManager::rotate`]
//! revokes the prior session (if any) and creates a new one.
//!
//! ## Persistence model
//!
//! The outstanding session `@odata.id` for each pair is persisted in the
//! `bmc_redfish_sessions` Postgres table behind the [`BmcSessionStore`]
//! trait. The `X-Auth-Token` itself is returned to the caller once and is
//! never stored anywhere by this manager. The DB row exists purely so the
//! next rotate (and [`BmcSessionManager::flush_mac`]) knows which session
//! resource to `DELETE` on the BMC before issuing a new one.
//!
//! Multiple API replicas may concurrently rotate the same pair. We do not
//! serialize across replicas: in the worst case a race produces one orphan
//! session on the BMC that expires via the BMC's idle-timeout. Within a
//! single replica, a per-BMC `tokio::sync::Mutex` serializes all rotates
//! against the same MAC.
//!
//! ## Lifecycle hooks
//!
//! * [`BmcSessionManager::flush_mac`] -- intended for use when the BMC root
//!   credentials are deleted. Drops all rows for that MAC; does not contact
//!   the BMC (the credentials needed to authenticate the DELETE were just
//!   wiped). Orphans expire via the BMC idle timer.
//! * [`BmcSessionManager::note_credentials_updated`] -- intended for use
//!   when the BMC root credentials are set or rotated. Rows are
//!   intentionally retained so the next rotate revokes the now-stale
//!   sessions with the new credentials before issuing a fresh one.
//!
//! ## Lockout-avoidance circuit breaker
//!
//! Each [`BmcSessionManager`] tracks an in-memory per-BMC counter of
//! consecutive HTTP 401/403 responses returned during session creation.
//! Once that counter reaches the configured threshold the breaker trips and
//! any subsequent [`BmcSessionManager::rotate`] call for the same BMC
//! short-circuits with [`BmcSessionError::AvoidLockout`] rather than
//! attempting another login (which could exhaust the BMC root account's
//! retry budget). The breaker is cleared by:
//!   * a successful [`BmcSessionManager::rotate`] (online recovery),
//!   * [`BmcSessionManager::flush_mac`] (credentials deleted), or
//!   * [`BmcSessionManager::note_credentials_updated`] (credentials set or
//!     rotated).
//!
//! Breaker state is intentionally not persisted: after a process restart a
//! single login attempt per BMC may be burned before the breaker re-trips,
//! and other replicas track lockouts independently. Network errors,
//! timeouts, 5xx responses, and deserialization failures do **not** count
//! against the threshold.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use carbide_redfish::nv_redfish::{BmcError, NvRedfishClientPool, RedfishBmc};
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use db::bmc_redfish_session;
use mac_address::MacAddress;
use model::bmc_redfish_session::StoredSession;
use nv_redfish::Error as NvError;
use nv_redfish::core::{EntityTypeRef as _, ODataId};
use nv_redfish::session_service::SessionCreate;
use sqlx::PgPool;
use tokio::sync::Mutex;

/// Errors surfaced by [`BmcSessionManager`].
#[derive(thiserror::Error, Debug)]
pub enum BmcSessionError {
    /// No BMC root credentials are stored for this MAC; cannot create a
    /// session.
    #[error("BMC root credentials are not configured for MAC {0}")]
    MissingRootCredentials(MacAddress),

    /// Failure interacting with the BMC via nv-redfish (connect, create,
    /// or delete failed for a reason other than auth).
    #[error("Redfish error talking to BMC at {bmc_addr}: {detail}")]
    Redfish {
        bmc_addr: SocketAddr,
        detail: String,
    },

    /// Failure reading the BMC root credentials from the credential store.
    #[error("Credential store error: {0}")]
    CredentialStore(String),

    /// Failure persisting or reading session metadata from the
    /// [`BmcSessionStore`].
    #[error("BMC session store error: {0}")]
    Store(String),

    /// The BMC's Redfish ServiceRoot does not expose a `SessionService`.
    #[error("BMC at {bmc_addr} does not expose Redfish SessionService")]
    NoSessionService { bmc_addr: SocketAddr },

    /// The lockout-avoidance circuit breaker is tripped for this BMC and
    /// we refuse to attempt another session creation until the BMC root
    /// credentials are deleted or updated.
    #[error(
        "BMC {bmc_mac} is locked out after {consecutive_unauthorized} consecutive \
         unauthorized responses (last HTTP status {last_status}); update BMC root \
         credentials to recover"
    )]
    AvoidLockout {
        bmc_mac: MacAddress,
        consecutive_unauthorized: u32,
        last_status: u16,
    },
}

/// A live Redfish session that we issued to a caller. The `token` is
/// transient: it is returned exactly once and never persisted by us.
#[derive(Clone)]
pub struct SessionEntry {
    /// `X-Auth-Token` value returned by the BMC on session creation.
    pub token: String,
    /// `@odata.id` of the session resource on the BMC; used to revoke the
    /// session via `DELETE` on the next rotate.
    pub session_odata_id: ODataId,
}

impl fmt::Debug for SessionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionEntry")
            .field("token", &"[REDACTED]")
            .field("session_odata_id", &self.session_odata_id)
            .finish()
    }
}

pub enum BmcAuthMaterial {
    Session(SessionEntry),
    Basic(Credentials),
}

impl fmt::Debug for BmcAuthMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(entry) => f.debug_tuple("Session").field(entry).finish(),
            // `Credentials` does not yet implement a redacted Debug, so
            // print only the variant name to keep credentials out of logs.
            Self::Basic(_) => f
                .debug_struct("Basic")
                .field("creds", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Per-BMC lockout-avoidance state.
#[derive(Debug, Clone)]
struct LockoutState {
    consecutive_unauthorized: u32,
    last_status: u16,
    /// `Some(when)` once the breaker has tripped; subsequent rotate calls
    /// short-circuit until the state is cleared.
    tripped_at: Option<Instant>,
}

/// Persistence layer for outstanding Redfish sessions. Wraps DB errors as
/// [`BmcSessionError::Store`] so the manager's surface stays uniform.
#[async_trait]
pub trait BmcSessionStore: Send + Sync {
    async fn get(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
    ) -> Result<Option<StoredSession>, BmcSessionError>;

    async fn upsert(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
        session_odata_id: &str,
    ) -> Result<(), BmcSessionError>;

    async fn delete_by_mac(&self, bmc_mac: MacAddress) -> Result<(), BmcSessionError>;
}

/// Postgres-backed [`BmcSessionStore`] used in production.
pub struct PgBmcSessionStore {
    pool: PgPool,
}

impl PgBmcSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BmcSessionStore for PgBmcSessionStore {
    async fn get(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
    ) -> Result<Option<StoredSession>, BmcSessionError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|err| BmcSessionError::Store(err.to_string()))?;
        bmc_redfish_session::get(conn.as_mut(), spiffe_service_id, bmc_mac)
            .await
            .map_err(|err| BmcSessionError::Store(err.to_string()))
    }

    async fn upsert(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
        session_odata_id: &str,
    ) -> Result<(), BmcSessionError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|err| BmcSessionError::Store(err.to_string()))?;
        bmc_redfish_session::upsert(conn.as_mut(), spiffe_service_id, bmc_mac, session_odata_id)
            .await
            .map_err(|err| BmcSessionError::Store(err.to_string()))
    }

    async fn delete_by_mac(&self, bmc_mac: MacAddress) -> Result<(), BmcSessionError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|err| BmcSessionError::Store(err.to_string()))?;
        bmc_redfish_session::delete_by_mac(conn.as_mut(), bmc_mac)
            .await
            .map(|_| ())
            .map_err(|err| BmcSessionError::Store(err.to_string()))
    }
}

pub struct BmcSessionManager {
    redfish_pool: Arc<NvRedfishClientPool>,
    credential_manager: Arc<dyn CredentialManager>,
    store: Arc<dyn BmcSessionStore>,
    mac_locks: Mutex<HashMap<MacAddress, Arc<Mutex<()>>>>,
    lockouts: Mutex<HashMap<MacAddress, LockoutState>>,
    lockout_threshold: u32,
    allow_basic_auth_fallback: bool,
    no_session_service: Mutex<HashSet<MacAddress>>,
}

impl BmcSessionManager {
    pub fn new(
        redfish_pool: Arc<NvRedfishClientPool>,
        credential_manager: Arc<dyn CredentialManager>,
        store: Arc<dyn BmcSessionStore>,
        lockout_threshold: u32,
        allow_basic_auth_fallback: bool,
    ) -> Self {
        Self {
            redfish_pool,
            credential_manager,
            store,
            mac_locks: Mutex::new(HashMap::new()),
            lockouts: Mutex::new(HashMap::new()),
            lockout_threshold: lockout_threshold.max(1),
            allow_basic_auth_fallback,
            no_session_service: Mutex::new(HashSet::new()),
        }
    }

    /// Revoke the prior session (if any) for the given `(spiffe_service_id,
    /// bmc_mac)` pair, then create a brand new session against the BMC at
    /// `bmc_addr` and return its token.
    pub async fn rotate(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
        bmc_addr: SocketAddr,
    ) -> Result<SessionEntry, BmcSessionError> {
        let mac_lock = self.acquire_mac_lock(bmc_mac).await;
        let _mac_guard = mac_lock.lock().await;

        if let Some(err) = self.check_not_locked_out(bmc_mac).await {
            return Err(err);
        }

        let creds = self.bmc_root_credentials(bmc_mac).await?;
        let (username, password) = match &creds {
            Credentials::UsernamePassword { username, password } => {
                (username.clone(), password.clone())
            }
        };

        let service_root = match self.redfish_pool.service_root(bmc_addr, creds).await {
            Ok(root) => root,
            Err(err) => return Err(self.classify_and_map(err, bmc_mac, bmc_addr).await),
        };

        let session_service = match service_root.session_service().await {
            Ok(Some(svc)) => svc,
            Ok(None) => return Err(BmcSessionError::NoSessionService { bmc_addr }),
            Err(err) => return Err(self.classify_and_map(err, bmc_mac, bmc_addr).await),
        };

        let sessions = match session_service.sessions().await {
            Ok(Some(coll)) => coll,
            Ok(None) => {
                return Err(BmcSessionError::Redfish {
                    bmc_addr,
                    detail: "BMC SessionService does not expose a Sessions collection".to_string(),
                });
            }
            Err(err) => return Err(self.classify_and_map(err, bmc_mac, bmc_addr).await),
        };

        // We try to revoke previous session, best effort, if we fail we still try to
        // create a new session
        if let Some(prior) = self.store.get(spiffe_service_id, bmc_mac).await? {
            let prior_id = ODataId::from(prior.session_odata_id);
            match sessions.members().await {
                Ok(members) => {
                    if let Some(prior_session) = members
                        .into_iter()
                        .find(|m| m.raw().odata_id() == &prior_id)
                    {
                        if let Err(err) = prior_session.delete().await {
                            tracing::warn!(
                                error = ?err,
                                %bmc_mac,
                                spiffe_service_id,
                                session = %prior_id,
                                "failed to revoke prior BMC session; \
                                 continuing with new session creation"
                            );
                        }
                    } else {
                        tracing::info!(
                            %bmc_mac,
                            spiffe_service_id,
                            session = %prior_id,
                            "prior BMC session no longer present in Sessions collection; \
                             skipping revoke"
                        );
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        %bmc_mac,
                        spiffe_service_id,
                        "failed to list BMC sessions for prior-session revoke; continuing"
                    );
                }
            }
        }

        let created = match sessions
            .create_session(&SessionCreate::builder(username, password).build())
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(self.classify_and_map(err, bmc_mac, bmc_addr).await),
        };

        let token = created
            .auth_token()
            .ok_or_else(|| BmcSessionError::Redfish {
                bmc_addr,
                detail: "BMC did not return an X-Auth-Token on session creation".to_string(),
            })?
            .to_string();
        let location = created
            .location()
            .cloned()
            .ok_or_else(|| BmcSessionError::Redfish {
                bmc_addr,
                detail: "BMC did not return a session @odata.id on session creation".to_string(),
            })?;

        // If persist fails we revoke token to avoid exhaust of session limit
        if let Err(store_err) = self
            .store
            .upsert(spiffe_service_id, bmc_mac, &location.to_string())
            .await
        {
            if let Err(revoke_err) = created.delete().await {
                tracing::warn!(
                    error = ?revoke_err,
                    %bmc_mac,
                    spiffe_service_id,
                    session = %location,
                    "failed to revoke just-created session after store upsert failed; \
                     it will leak until BMC idle timeout"
                );
            }
            return Err(store_err);
        }

        self.clear_lockout(bmc_mac).await;

        Ok(SessionEntry {
            token,
            session_odata_id: location,
        })
    }

    pub async fn issue_credentials(
        &self,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
        bmc_addr: SocketAddr,
    ) -> Result<BmcAuthMaterial, BmcSessionError> {
        if !self.allow_basic_auth_fallback {
            return self
                .rotate(spiffe_service_id, bmc_mac, bmc_addr)
                .await
                .map(BmcAuthMaterial::Session);
        }

        // Fast path: we already discovered this BMC has no SessionService
        if self.no_session_service.lock().await.contains(&bmc_mac) {
            let creds = self.bmc_root_credentials(bmc_mac).await?;
            return Ok(BmcAuthMaterial::Basic(creds));
        }

        match self.rotate(spiffe_service_id, bmc_mac, bmc_addr).await {
            Ok(entry) => Ok(BmcAuthMaterial::Session(entry)),
            Err(BmcSessionError::NoSessionService { .. }) => {
                let newly_cached = self.no_session_service.lock().await.insert(bmc_mac);
                if newly_cached {
                    tracing::info!(
                        %bmc_mac,
                        %bmc_addr,
                        "BMC does not expose Redfish SessionService; serving basic-auth credentials for the remainder of this process lifetime"
                    );
                }
                let creds = self.bmc_root_credentials(bmc_mac).await?;
                Ok(BmcAuthMaterial::Basic(creds))
            }
            Err(other) => Err(other),
        }
    }

    async fn classify_and_map(
        &self,
        err: NvError<RedfishBmc>,
        bmc_mac: MacAddress,
        bmc_addr: SocketAddr,
    ) -> BmcSessionError {
        if let Some(status) = classify_unauthorized(&err)
            && let Some(lockout_err) = self.record_unauthorized(bmc_mac, status).await
        {
            return lockout_err;
        }
        BmcSessionError::Redfish {
            bmc_addr,
            detail: err.to_string(),
        }
    }

    /// Drop all session rows for `bmc_mac` and clear any lockout state.
    pub async fn flush_mac(&self, bmc_mac: MacAddress) {
        if let Err(err) = self.store.delete_by_mac(bmc_mac).await {
            tracing::warn!(
                error = %err,
                %bmc_mac,
                "failed to delete BMC session rows during flush_mac; continuing"
            );
        }
        self.clear_lockout(bmc_mac).await;
        self.clear_no_session_service(bmc_mac).await;
    }

    /// Reset Circtuit Breaker
    pub async fn note_credentials_updated(&self, bmc_mac: MacAddress) {
        self.clear_lockout(bmc_mac).await;
        self.clear_no_session_service(bmc_mac).await;
    }

    async fn clear_no_session_service(&self, bmc_mac: MacAddress) {
        if self.no_session_service.lock().await.remove(&bmc_mac) {
            tracing::info!(
                %bmc_mac,
                "BmcSessionManager: forgetting cached `no SessionService` decision; \
                 next issue_credentials will re-probe"
            );
        }
    }

    pub async fn check_not_locked_out(&self, bmc_mac: MacAddress) -> Option<BmcSessionError> {
        let lockouts = self.lockouts.lock().await;
        let state = lockouts.get(&bmc_mac)?;
        if state.tripped_at.is_some() {
            Some(BmcSessionError::AvoidLockout {
                bmc_mac,
                consecutive_unauthorized: state.consecutive_unauthorized,
                last_status: state.last_status,
            })
        } else {
            None
        }
    }

    /// Checks and return any authorization/authentication related error, as well as update lockouts
    async fn record_unauthorized(
        &self,
        bmc_mac: MacAddress,
        status: u16,
    ) -> Option<BmcSessionError> {
        let mut lockouts = self.lockouts.lock().await;
        let entry = lockouts.entry(bmc_mac).or_insert(LockoutState {
            consecutive_unauthorized: 0,
            last_status: status,
            tripped_at: None,
        });
        entry.consecutive_unauthorized = entry.consecutive_unauthorized.saturating_add(1);
        entry.last_status = status;
        if entry.consecutive_unauthorized >= self.lockout_threshold && entry.tripped_at.is_none() {
            entry.tripped_at = Some(Instant::now());
            tracing::warn!(
                %bmc_mac,
                status,
                consecutive_unauthorized = entry.consecutive_unauthorized,
                threshold = self.lockout_threshold,
                "BmcSessionManager: lockout-avoidance breaker tripped"
            );
            return Some(BmcSessionError::AvoidLockout {
                bmc_mac,
                consecutive_unauthorized: entry.consecutive_unauthorized,
                last_status: status,
            });
        }
        None
    }

    async fn clear_lockout(&self, bmc_mac: MacAddress) {
        if self.lockouts.lock().await.remove(&bmc_mac).is_some() {
            tracing::info!(%bmc_mac, "BmcSessionManager: lockout-avoidance breaker cleared");
        }
    }

    #[cfg(test)]
    pub(crate) async fn force_trip_for_test(
        &self,
        bmc_mac: MacAddress,
        consecutive_unauthorized: u32,
        last_status: u16,
    ) {
        self.lockouts.lock().await.insert(
            bmc_mac,
            LockoutState {
                consecutive_unauthorized: consecutive_unauthorized.max(1),
                last_status,
                tripped_at: Some(Instant::now()),
            },
        );
    }

    async fn acquire_mac_lock(&self, bmc_mac: MacAddress) -> Arc<Mutex<()>> {
        let mut mac_locks = self.mac_locks.lock().await;
        mac_locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        mac_locks
            .entry(bmc_mac)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn bmc_root_credentials(
        &self,
        bmc_mac: MacAddress,
    ) -> Result<Credentials, BmcSessionError> {
        self.credential_manager
            .get_credentials(&CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: bmc_mac,
                },
            })
            .await
            .map_err(|err| BmcSessionError::CredentialStore(err.to_string()))?
            .ok_or(BmcSessionError::MissingRootCredentials(bmc_mac))
    }
}

pub fn classify_unauthorized(err: &NvError<RedfishBmc>) -> Option<u16> {
    let NvError::Bmc(BmcError::InvalidResponse { status, .. }) = err else {
        return None;
    };
    if *status == reqwest::StatusCode::UNAUTHORIZED || *status == reqwest::StatusCode::FORBIDDEN {
        Some(status.as_u16())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use carbide_secrets::SecretsError;
    use carbide_secrets::credentials::{
        BmcCredentialType, CredentialKey, CredentialManager, CredentialReader, CredentialWriter,
        Credentials,
    };
    use carbide_secrets::test_support::credentials::TestCredentialManager;
    use mac_address::MacAddress;
    use sqlx::types::chrono::Utc;
    use tokio::sync::Mutex;

    use super::{BmcSessionError, BmcSessionManager, BmcSessionStore, StoredSession};

    fn mac(byte: u8) -> MacAddress {
        MacAddress::from([byte, 0, 0, 0, 0, 1])
    }

    const TEST_LOCKOUT_THRESHOLD: u32 = 3;

    #[derive(Default)]
    struct InMemoryBmcSessionStore {
        rows: Mutex<HashMap<(String, MacAddress), StoredSession>>,
    }

    impl InMemoryBmcSessionStore {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
    }

    #[async_trait]
    impl BmcSessionStore for InMemoryBmcSessionStore {
        async fn get(
            &self,
            spiffe_service_id: &str,
            bmc_mac: MacAddress,
        ) -> Result<Option<StoredSession>, BmcSessionError> {
            Ok(self
                .rows
                .lock()
                .await
                .get(&(spiffe_service_id.to_owned(), bmc_mac))
                .cloned())
        }

        async fn upsert(
            &self,
            spiffe_service_id: &str,
            bmc_mac: MacAddress,
            session_odata_id: &str,
        ) -> Result<(), BmcSessionError> {
            self.rows.lock().await.insert(
                (spiffe_service_id.to_owned(), bmc_mac),
                StoredSession {
                    spiffe_service_id: spiffe_service_id.to_owned(),
                    bmc_mac_address: bmc_mac,
                    session_odata_id: session_odata_id.to_owned(),
                    issued_at: Utc::now(),
                },
            );
            Ok(())
        }

        async fn delete_by_mac(&self, bmc_mac: MacAddress) -> Result<(), BmcSessionError> {
            self.rows.lock().await.retain(|(_, m), _| *m != bmc_mac);
            Ok(())
        }
    }

    fn manager_with_creds() -> (Arc<BmcSessionManager>, Arc<InMemoryBmcSessionStore>) {
        manager_with_creds_and_threshold(TEST_LOCKOUT_THRESHOLD)
    }

    fn manager_with_creds_and_threshold(
        threshold: u32,
    ) -> (Arc<BmcSessionManager>, Arc<InMemoryBmcSessionStore>) {
        manager_with_creds_threshold_and_fallback(threshold, false)
    }

    fn manager_with_creds_threshold_and_fallback(
        threshold: u32,
        allow_basic_auth_fallback: bool,
    ) -> (Arc<BmcSessionManager>, Arc<InMemoryBmcSessionStore>) {
        let bmc_proxy = Arc::new(ArcSwap::new(Arc::new(None)));
        let redfish_pool = carbide_redfish::nv_redfish::new_pool(bmc_proxy);
        let credential_manager =
            Arc::new(TestCredentialManager::new(Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            }));
        let store = InMemoryBmcSessionStore::new();
        let manager = Arc::new(BmcSessionManager::new(
            redfish_pool,
            credential_manager,
            store.clone(),
            threshold,
            allow_basic_auth_fallback,
        ));
        (manager, store)
    }

    #[test]
    fn odata_id_last_segment_returns_session_id() {
        let id = nv_redfish::core::ODataId::from(
            "/redfish/v1/SessionService/Sessions/abc123".to_string(),
        );
        assert_eq!(id.last_segment(), Some("abc123"));
    }

    async fn seed_row(
        store: &InMemoryBmcSessionStore,
        spiffe_service_id: &str,
        bmc_mac: MacAddress,
        session_odata_id: &str,
    ) {
        store
            .upsert(spiffe_service_id, bmc_mac, session_odata_id)
            .await
            .expect("in-memory upsert never fails");
    }

    #[tokio::test]
    async fn flush_mac_deletes_store_rows_and_clears_lockout() {
        let (manager, store) = manager_with_creds();
        let mac_a = mac(0xAA);
        let mac_b = mac(0xBB);

        seed_row(&store, "svc-1", mac_a, "/sessions/1").await;
        seed_row(&store, "svc-2", mac_a, "/sessions/2").await;
        seed_row(&store, "svc-1", mac_b, "/sessions/3").await;
        manager.force_trip_for_test(mac_a, 3, 401).await;

        manager.flush_mac(mac_a).await;

        // mac_a rows are gone, mac_b survives.
        let rows = store.rows.lock().await;
        assert_eq!(rows.len(), 1);
        assert!(rows.keys().all(|(_, m)| *m == mac_b));
        drop(rows);
        // lockout was cleared along with the rows.
        assert!(manager.check_not_locked_out(mac_a).await.is_none());
    }

    #[tokio::test]
    async fn note_credentials_updated_retains_store_rows() {
        let (manager, store) = manager_with_creds();
        let bmc_mac = mac(0xCC);
        seed_row(&store, "svc-1", bmc_mac, "/sessions/keep-me").await;
        manager.force_trip_for_test(bmc_mac, 5, 403).await;

        manager.note_credentials_updated(bmc_mac).await;

        // Row is still present so the next rotate can revoke it with the
        // new creds; the breaker has been cleared.
        let rows = store.rows.lock().await;
        assert!(rows.contains_key(&("svc-1".to_string(), bmc_mac)));
        drop(rows);
        assert!(manager.check_not_locked_out(bmc_mac).await.is_none());
    }

    #[tokio::test]
    async fn in_memory_store_upsert_replaces_existing_row() {
        let store = InMemoryBmcSessionStore::new();
        let bmc_mac = mac(0xDD);
        store.upsert("svc", bmc_mac, "/sessions/v1").await.unwrap();
        store.upsert("svc", bmc_mac, "/sessions/v2").await.unwrap();
        let row = store
            .get("svc", bmc_mac)
            .await
            .expect("ok")
            .expect("row present");
        assert_eq!(row.session_odata_id, "/sessions/v2");
    }

    #[tokio::test]
    async fn rotate_returns_missing_credentials_when_unset() {
        let bmc_proxy = Arc::new(ArcSwap::new(Arc::new(None)));
        let redfish_pool = carbide_redfish::nv_redfish::new_pool(bmc_proxy);
        let credential_manager = Arc::new(TestCredentialManager::default());
        let store = InMemoryBmcSessionStore::new();
        let manager = BmcSessionManager::new(
            redfish_pool,
            credential_manager,
            store,
            TEST_LOCKOUT_THRESHOLD,
            false,
        );

        let bmc_mac = mac(0xCE);
        let bmc_addr = "127.0.0.1:9999".parse().unwrap();
        let err = manager
            .rotate("svc-x", bmc_mac, bmc_addr)
            .await
            .expect_err("should fail with missing root credentials");
        match err {
            super::BmcSessionError::MissingRootCredentials(got) => assert_eq!(got, bmc_mac),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mac_lock_collapses_all_spiffe_callers_for_one_mac() {
        let (manager, _store) = manager_with_creds();
        let mac_a = mac(0x01);
        let mac_b = mac(0x02);

        let lock_a1 = manager.acquire_mac_lock(mac_a).await;
        let lock_a2 = manager.acquire_mac_lock(mac_a).await;
        let lock_b = manager.acquire_mac_lock(mac_b).await;

        assert!(
            Arc::ptr_eq(&lock_a1, &lock_a2),
            "every caller for the same MAC must share a single mutex — \
             otherwise the lockout breaker can be raced past"
        );
        assert!(
            !Arc::ptr_eq(&lock_a1, &lock_b),
            "distinct MACs must use distinct mutexes — otherwise one slow \
             BMC blocks unrelated traffic"
        );
        let _g = lock_b.lock().await;
    }

    #[tokio::test]
    async fn acquire_mac_lock_evicts_unused_entries() {
        let (manager, _store) = manager_with_creds();
        let mac_a = mac(0x10);
        let mac_b = mac(0x11);

        // Acquire and immediately drop a lock for mac_a — no rotate is
        // holding it once this expression statement ends.
        drop(manager.acquire_mac_lock(mac_a).await);
        assert!(
            manager.mac_locks.lock().await.contains_key(&mac_a),
            "entry should be present immediately after acquire-then-drop \
             (GC only runs on the next acquire)"
        );

        // Touching any MAC fires the opportunistic GC pass, which should
        // evict the now-stale mac_a entry because nobody references its
        // Arc except the map.
        let _b = manager.acquire_mac_lock(mac_b).await;

        let locks = manager.mac_locks.lock().await;
        assert!(
            !locks.contains_key(&mac_a),
            "stale mac_lock entry must have been evicted to keep the map \
             bounded; current keys = {:?}",
            locks.keys().collect::<Vec<_>>()
        );
        assert!(
            locks.contains_key(&mac_b),
            "the freshly-acquired entry must be retained"
        );
    }

    #[tokio::test]
    async fn acquire_mac_lock_retains_in_use_entries() {
        let (manager, _store) = manager_with_creds();
        let mac_busy = mac(0x20);
        let mac_other = mac(0x21);

        // Hold a clone of the Arc for mac_busy to simulate an in-flight
        // rotate that's currently inside its critical section.
        let in_flight = manager.acquire_mac_lock(mac_busy).await;

        // Touching a different MAC triggers GC. mac_busy must survive
        // because `in_flight` keeps the Arc strong_count above 1.
        let _other = manager.acquire_mac_lock(mac_other).await;

        let locks = manager.mac_locks.lock().await;
        assert!(
            locks.contains_key(&mac_busy),
            "entry held by an in-flight caller must NOT be evicted — \
             otherwise concurrent rotates would race past the per-MAC lock"
        );
        drop(in_flight);
    }

    struct CountingCredentialManager {
        creds: Credentials,
        in_flight: Mutex<HashMap<MacAddress, u32>>,
        peak: Mutex<HashMap<MacAddress, u32>>,
        hold: std::time::Duration,
    }

    impl CountingCredentialManager {
        fn new(creds: Credentials, hold: std::time::Duration) -> Arc<Self> {
            Arc::new(Self {
                creds,
                in_flight: Mutex::new(HashMap::new()),
                peak: Mutex::new(HashMap::new()),
                hold,
            })
        }

        async fn peak_for(&self, bmc_mac: MacAddress) -> u32 {
            self.peak.lock().await.get(&bmc_mac).copied().unwrap_or(0)
        }
    }

    #[async_trait]
    impl CredentialReader for CountingCredentialManager {
        async fn get_credentials(
            &self,
            key: &CredentialKey,
        ) -> Result<Option<Credentials>, SecretsError> {
            let bmc_mac = match key {
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                } => *bmc_mac_address,
                other => panic!("unexpected credential key in rotate path: {other:?}"),
            };

            let current = {
                let mut in_flight = self.in_flight.lock().await;
                let entry = in_flight.entry(bmc_mac).or_insert(0);
                *entry = entry.saturating_add(1);
                *entry
            };
            {
                let mut peak = self.peak.lock().await;
                let entry = peak.entry(bmc_mac).or_insert(0);
                if current > *entry {
                    *entry = current;
                }
            }

            tokio::time::sleep(self.hold).await;

            {
                let mut in_flight = self.in_flight.lock().await;
                if let Some(value) = in_flight.get_mut(&bmc_mac) {
                    *value = value.saturating_sub(1);
                }
            }

            Ok(Some(self.creds.clone()))
        }
    }

    #[async_trait]
    impl CredentialWriter for CountingCredentialManager {
        async fn set_credentials(
            &self,
            _key: &CredentialKey,
            _credentials: &Credentials,
        ) -> Result<(), SecretsError> {
            unreachable!("rotate path never writes credentials")
        }

        async fn create_credentials(
            &self,
            _key: &CredentialKey,
            _credentials: &Credentials,
        ) -> Result<(), SecretsError> {
            unreachable!("rotate path never creates credentials")
        }

        async fn delete_credentials(&self, _key: &CredentialKey) -> Result<(), SecretsError> {
            unreachable!("rotate path never deletes credentials")
        }
    }

    impl CredentialManager for CountingCredentialManager {}

    #[tokio::test]
    async fn rotate_serializes_per_mac_even_across_distinct_spiffe_callers() {
        let bmc_proxy = Arc::new(ArcSwap::new(Arc::new(None)));
        let redfish_pool = carbide_redfish::nv_redfish::new_pool(bmc_proxy);
        let credential_manager = CountingCredentialManager::new(
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
            std::time::Duration::from_millis(50),
        );
        let store = InMemoryBmcSessionStore::new();
        let manager = Arc::new(BmcSessionManager::new(
            redfish_pool,
            credential_manager.clone(),
            store,
            TEST_LOCKOUT_THRESHOLD,
            false,
        ));

        let bmc_mac = mac(0xAB);
        let bmc_addr = "127.0.0.1:1".parse().unwrap();

        let mut handles = Vec::new();
        for i in 0..16 {
            let manager = manager.clone();
            let spiffe = format!("svc-{i}");
            handles.push(tokio::spawn(async move {
                let _ = manager.rotate(&spiffe, bmc_mac, bmc_addr).await;
            }));
        }
        for h in handles {
            h.await.expect("rotate task should not panic");
        }

        let peak = credential_manager.peak_for(bmc_mac).await;
        assert_eq!(
            peak, 1,
            "rotate must serialize per-MAC across distinct SPIFFE callers; \
             observed peak in-flight credential lookups = {peak}, want 1"
        );
    }

    #[tokio::test]
    async fn record_unauthorized_returns_none_below_threshold() {
        let (manager, _store) = manager_with_creds_and_threshold(3);
        let bmc_mac = mac(0xDE);
        for _ in 0..2 {
            assert!(manager.record_unauthorized(bmc_mac, 401).await.is_none());
            assert!(
                manager.check_not_locked_out(bmc_mac).await.is_none(),
                "breaker should not trip below threshold"
            );
        }
        let state = manager
            .lockouts
            .lock()
            .await
            .get(&bmc_mac)
            .cloned()
            .expect("state should exist after recording");
        assert_eq!(state.consecutive_unauthorized, 2);
        assert!(state.tripped_at.is_none());
    }

    #[tokio::test]
    async fn record_unauthorized_trips_at_threshold() {
        let (manager, _store) = manager_with_creds_and_threshold(3);
        let bmc_mac = mac(0xDE);
        assert!(manager.record_unauthorized(bmc_mac, 401).await.is_none());
        assert!(manager.record_unauthorized(bmc_mac, 401).await.is_none());
        let trip = manager
            .record_unauthorized(bmc_mac, 403)
            .await
            .expect("third unauthorized should trip the breaker");
        match trip {
            super::BmcSessionError::AvoidLockout {
                bmc_mac: got_mac,
                consecutive_unauthorized,
                last_status,
            } => {
                assert_eq!(got_mac, bmc_mac);
                assert_eq!(consecutive_unauthorized, 3);
                assert_eq!(last_status, 403);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        let still = manager
            .check_not_locked_out(bmc_mac)
            .await
            .expect("breaker should remain tripped");
        assert!(matches!(still, super::BmcSessionError::AvoidLockout { .. }));
    }

    #[tokio::test]
    async fn record_unauthorized_only_emits_avoid_lockout_on_the_tripping_request() {
        let (manager, _store) = manager_with_creds_and_threshold(2);
        let bmc_mac = mac(0xDE);
        assert!(manager.record_unauthorized(bmc_mac, 401).await.is_none());
        let trip = manager.record_unauthorized(bmc_mac, 401).await;
        assert!(matches!(
            trip,
            Some(super::BmcSessionError::AvoidLockout { .. })
        ));
        let follow_up = manager.record_unauthorized(bmc_mac, 401).await;
        assert!(
            follow_up.is_none(),
            "second AvoidLockout should not be emitted from record_unauthorized"
        );
    }

    #[tokio::test]
    async fn clear_lockout_removes_tripped_state() {
        let (manager, _store) = manager_with_creds_and_threshold(1);
        let bmc_mac = mac(0xEE);
        manager.force_trip_for_test(bmc_mac, 1, 401).await;
        assert!(manager.check_not_locked_out(bmc_mac).await.is_some());
        manager.clear_lockout(bmc_mac).await;
        assert!(manager.check_not_locked_out(bmc_mac).await.is_none());
        assert!(!manager.lockouts.lock().await.contains_key(&bmc_mac));
    }

    #[tokio::test]
    async fn rotate_short_circuits_when_breaker_tripped() {
        let (manager, _store) = manager_with_creds_and_threshold(1);
        let bmc_mac = mac(0xF1);
        manager.force_trip_for_test(bmc_mac, 7, 401).await;

        let bmc_addr = "127.0.0.1:9999".parse().unwrap();
        let err = manager
            .rotate("svc-locked", bmc_mac, bmc_addr)
            .await
            .expect_err("rotate must refuse to contact a locked-out BMC");
        match err {
            super::BmcSessionError::AvoidLockout {
                bmc_mac: got,
                consecutive_unauthorized,
                last_status,
            } => {
                assert_eq!(got, bmc_mac);
                assert_eq!(consecutive_unauthorized, 7);
                assert_eq!(last_status, 401);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_unauthorized_records_trip_exactly_once() {
        let (manager, _store) = manager_with_creds_and_threshold(3);
        let bmc_mac = mac(0xF2);

        let mut handles = Vec::new();
        for _ in 0..16 {
            let manager = manager.clone();
            handles.push(tokio::spawn(async move {
                manager.record_unauthorized(bmc_mac, 401).await
            }));
        }

        let mut trips = 0;
        for h in handles {
            if matches!(
                h.await.expect("task panicked"),
                Some(super::BmcSessionError::AvoidLockout { .. })
            ) {
                trips += 1;
            }
        }
        assert_eq!(
            trips, 1,
            "exactly one record_unauthorized should report a trip"
        );

        let state = manager
            .lockouts
            .lock()
            .await
            .get(&bmc_mac)
            .cloned()
            .expect("state present after concurrent records");
        assert!(state.tripped_at.is_some());
        assert!(state.consecutive_unauthorized >= 3);
    }

    #[tokio::test]
    async fn issue_credentials_with_flag_off_surfaces_no_session_service_error() {
        let bmc_proxy = Arc::new(ArcSwap::new(Arc::new(None)));
        let redfish_pool = carbide_redfish::nv_redfish::new_pool(bmc_proxy);
        let credential_manager = Arc::new(TestCredentialManager::default());
        let store = InMemoryBmcSessionStore::new();
        let manager = BmcSessionManager::new(
            redfish_pool,
            credential_manager,
            store,
            TEST_LOCKOUT_THRESHOLD,
            false,
        );

        let bmc_mac = mac(0xA1);
        let bmc_addr = "127.0.0.1:9999".parse().unwrap();
        let err = manager
            .issue_credentials("svc-x", bmc_mac, bmc_addr)
            .await
            .map(|_| ())
            .expect_err("flag off must propagate the underlying rotate() error");
        assert!(
            matches!(err, BmcSessionError::MissingRootCredentials(_)),
            "expected MissingRootCredentials passthrough, got {err:?}"
        );
    }
}
