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

//! api-core implementation of [`model::attestation::DpuDeviceIdentityResolver`].
//!
//! This is the verification + backward-compatibility policy half of DPU
//! device-identity, decoupled from the *fetch* so that site-explorer (which
//! holds the live BMC Redfish connection during exploration) can resolve a
//! DPU's `machine_id` at creation time without depending on api-core. The
//! fetch happens in site-explorer; this resolver takes the already-fetched IRoT
//! cert chain PEM and applies exactly the same `verify_device_cert_chain` +
//! `select_dpu_machine_id` logic the `DiscoverMachine` handler uses.

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use chrono::Utc;
use model::attestation::{DpuDeviceIdentityRequired, DpuDeviceIdentityResolver};
use model::machine::machine_search_config::MachineSearchConfig;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};

use crate::attestation::dpu_device::{
    self, DpuDeviceAttestationMode, DpuIdentity, VerifiedDpuDevice,
};

/// Resolves a DPU's `machine_id` from its IRoT cert chain under the configured
/// [`DpuDeviceAttestationMode`]. Holds a DB pool for loading trusted roots and
/// checking whether the DPU is already enrolled under the legacy id.
pub struct ApiDpuDeviceIdentityResolver {
    db: PgPool,
    mode: DpuDeviceAttestationMode,
}

impl ApiDpuDeviceIdentityResolver {
    pub fn new(db: PgPool, mode: DpuDeviceAttestationMode) -> Self {
        Self { db, mode }
    }

    /// Best-effort verify of a fetched IRoT chain against the seeded device
    /// roots. Returns the verified identity and the leaf-cert sha256 (for the
    /// binding record), or `None` (logging the reason) on any soft failure so
    /// the caller can apply the mode policy.
    async fn verify(
        &self,
        irot_chain_pem: &str,
        conn: &mut PgConnection,
    ) -> Option<(VerifiedDpuDevice, Vec<u8>)> {
        let chain_der = dpu_device::pem_chain_to_der(irot_chain_pem)
            .map_err(|e| tracing::warn!("DPU IRoT cert chain PEM parse failed: {e}"))
            .ok()?;

        let roots = db::attestation::dpu_device_ca_certs::get_all(&mut *conn)
            .await
            .map_err(|e| tracing::warn!("loading device roots failed: {e}"))
            .ok()?;
        let roots_der: Vec<Vec<u8>> = roots.into_iter().map(|r| r.ca_cert_der).collect();

        let verified = dpu_device::verify_device_cert_chain(&chain_der, &roots_der, Utc::now())
            .map_err(|e| tracing::warn!("IRoT cert verification failed: {e}"))
            .ok()?;

        let mut hasher = Sha256::new();
        hasher.update(&chain_der[0]);
        let sha = hasher.finalize().to_vec();
        Some((verified, sha))
    }

    /// Best-effort binding audit record. A failure here must not fail resolution.
    async fn record_binding(&self, machine_id: MachineId, device_cert_sha256: &[u8], serial: &str) {
        let mut txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => {
                tracing::warn!("failed to begin DPU device-identity binding txn: {e}");
                return;
            }
        };
        if let Err(e) = db::attestation::dpu_device_cert_status::upsert(
            &mut txn,
            machine_id,
            device_cert_sha256,
            serial,
            None,
            &Utc::now(),
        )
        .await
        {
            tracing::warn!("failed to write DPU device-identity binding: {e}");
            return;
        }
        if let Err(e) = txn.commit().await {
            tracing::warn!("failed to commit DPU device-identity binding: {e}");
        }
    }
}

#[async_trait]
impl DpuDeviceIdentityResolver for ApiDpuDeviceIdentityResolver {
    async fn resolve_dpu_machine_id(
        &self,
        irot_chain_pem: Option<&str>,
        legacy_id: MachineId,
    ) -> Result<MachineId, DpuDeviceIdentityRequired> {
        if self.mode == DpuDeviceAttestationMode::Disabled {
            return Ok(legacy_id);
        }

        // A DB failure degrades to "no verified identity + not enrolled", which
        // the mode policy then handles (best_effort → legacy, required → error).
        let (verified, legacy_known) = match self.db.acquire().await {
            Ok(mut conn) => {
                let verified = match irot_chain_pem {
                    Some(pem) => self.verify(pem, &mut conn).await,
                    None => None,
                };
                let legacy_known = db::machine::find_one(
                    &mut *conn,
                    &legacy_id,
                    MachineSearchConfig {
                        include_dpus: true,
                        ..MachineSearchConfig::default()
                    },
                )
                .await
                .map(|m| m.is_some())
                .unwrap_or(false);
                (verified, legacy_known)
            }
            Err(e) => {
                tracing::warn!("DPU device-identity resolve: DB acquire failed: {e}");
                (None, false)
            }
        };

        let identity = dpu_device::select_dpu_machine_id(
            self.mode,
            legacy_id,
            verified.as_ref().map(|(v, _)| v),
            legacy_known,
        )
        .map_err(|e| DpuDeviceIdentityRequired(e.to_string()))?;

        if let (DpuIdentity::NewDeviceRooted(machine_id), Some((v, sha))) = (&identity, &verified) {
            self.record_binding(*machine_id, sha, &v.device_serial)
                .await;
        }

        Ok(identity.machine_id())
    }
}

#[cfg(test)]
mod tests {
    use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};

    use super::*;

    fn legacy_dpu_id() -> MachineId {
        MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            [7u8; 32],
            MachineType::Dpu,
        )
    }

    #[crate::sqlx_test]
    async fn disabled_mode_keeps_legacy_id(pool: sqlx::PgPool) {
        let resolver = ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::Disabled);
        let legacy = legacy_dpu_id();
        // Even with a (would-be) chain present, disabled short-circuits to legacy.
        let got = resolver
            .resolve_dpu_machine_id(Some("not-even-parsed"), legacy)
            .await
            .unwrap();
        assert_eq!(got, legacy);
    }

    #[crate::sqlx_test]
    async fn best_effort_without_verified_identity_falls_back_to_legacy(pool: sqlx::PgPool) {
        let resolver =
            ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::BestEffort);
        let legacy = legacy_dpu_id();
        // No IRoT chain and no seeded roots -> not verified, not enrolled -> legacy.
        let got = resolver.resolve_dpu_machine_id(None, legacy).await.unwrap();
        assert_eq!(got, legacy);
    }

    #[crate::sqlx_test]
    async fn required_mode_without_verified_identity_errors(pool: sqlx::PgPool) {
        let resolver = ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::Required);
        let err = resolver
            .resolve_dpu_machine_id(None, legacy_dpu_id())
            .await
            .expect_err("required mode with no verified identity must error");
        // Surfaces as the required-but-unavailable error.
        assert!(format!("{err}").contains("required"));
    }
}
