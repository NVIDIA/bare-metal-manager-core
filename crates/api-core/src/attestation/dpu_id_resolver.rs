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
//! holds the live BMC Redfish connection during exploration) and the
//! `DiscoverMachine` handler share exactly one pipeline: enrollment lookup →
//! `verify_device_cert_chain` → `select_dpu_machine_id` → binding record.
//!
//! Resolution order matters for identity stability:
//! 1. A DPU enrolled under its legacy id keeps it (in every mode).
//! 2. A DPU that previously adopted a device-rooted id keeps it — recognized
//!    via the `dpu_device_cert_status` binding by legacy id — even when the
//!    IRoT chain cannot be fetched this cycle, so a transient BMC failure can
//!    never flap an enrolled DPU back to its legacy id.
//! 3. Only a previously-unseen DPU goes through verification and the
//!    [`DpuDeviceAttestationMode`] policy.
//!
//! Database errors are propagated (never degraded to "unknown DPU"): treating
//! a failed lookup as "not enrolled" would silently re-key an enrolled DPU.

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use chrono::Utc;
use model::attestation::{DpuDeviceIdentityError, DpuDeviceIdentityResolver};
use model::machine::machine_search_config::MachineSearchConfig;
use sqlx::{PgConnection, PgPool};

use crate::attestation::dpu_device::{
    self, DpuDeviceAttestationMode, DpuIdentitySelection, VerifiedDpuDevice,
};

/// Resolves a DPU's `machine_id` from its IRoT cert chain under the configured
/// [`DpuDeviceAttestationMode`]. Holds a DB pool for loading trusted roots and
/// checking whether the DPU is already enrolled.
pub struct ApiDpuDeviceIdentityResolver {
    db: PgPool,
    mode: DpuDeviceAttestationMode,
}

fn internal(e: impl std::fmt::Display) -> DpuDeviceIdentityError {
    DpuDeviceIdentityError::Internal(e.to_string())
}

impl ApiDpuDeviceIdentityResolver {
    pub fn new(db: PgPool, mode: DpuDeviceAttestationMode) -> Self {
        Self { db, mode }
    }

    /// Verifies a fetched IRoT chain against the seeded device roots. A chain
    /// that fails to parse or verify is a soft failure (`Ok(None)`, logged) so
    /// the mode policy can decide; failing to *load* the roots is a hard error.
    async fn verify(
        &self,
        irot_chain_pem: &str,
        conn: &mut PgConnection,
    ) -> Result<Option<VerifiedDpuDevice>, DpuDeviceIdentityError> {
        let chain_der = match dpu_device::pem_chain_to_der(irot_chain_pem) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::warn!("DPU IRoT cert chain PEM parse failed: {e}");
                return Ok(None);
            }
        };

        let roots = db::attestation::dpu_device_ca_certs::get_all(&mut *conn)
            .await
            .map_err(internal)?;
        let roots_der: Vec<Vec<u8>> = roots.into_iter().map(|r| r.ca_cert_der).collect();

        match dpu_device::verify_device_cert_chain(&chain_der, &roots_der, Utc::now()) {
            Ok(verified) => Ok(Some(verified)),
            Err(e) => {
                tracing::warn!("IRoT cert verification failed: {e}");
                Ok(None)
            }
        }
    }

    /// Best-effort binding audit record. A failure here must not fail resolution.
    async fn record_binding(
        &self,
        machine_id: MachineId,
        legacy_machine_id: Option<MachineId>,
        device: &VerifiedDpuDevice,
    ) {
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
            legacy_machine_id,
            &device.leaf_cert_sha256,
            &device.device_serial,
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

    /// Whether a machine record exists under `machine_id`.
    async fn machine_exists(
        &self,
        conn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<bool, DpuDeviceIdentityError> {
        Ok(db::machine::find_one(
            &mut *conn,
            machine_id,
            MachineSearchConfig {
                include_dpus: true,
                ..MachineSearchConfig::default()
            },
        )
        .await
        .map_err(internal)?
        .is_some())
    }
}

#[async_trait]
impl DpuDeviceIdentityResolver for ApiDpuDeviceIdentityResolver {
    async fn enrolled_machine_id(
        &self,
        legacy_id: MachineId,
    ) -> Result<Option<MachineId>, DpuDeviceIdentityError> {
        let mut conn = self.db.acquire().await.map_err(internal)?;

        // Backward compatible: a DPU we already enrolled under its legacy id
        // keeps that id regardless of mode or of any attestation it presents.
        if self.machine_exists(&mut conn, &legacy_id).await? {
            return Ok(Some(legacy_id));
        }

        // A DPU that previously adopted a device-rooted id keeps it, even when
        // the IRoT chain is unavailable this cycle. Trust the binding only if
        // the machine still exists — a stale binding left after machine
        // deletion (e.g. the DPU behind this serial was replaced) must not
        // resurrect the old identity.
        if let Some(binding) =
            db::attestation::dpu_device_cert_status::get_by_legacy_machine_id(&mut *conn, legacy_id)
                .await
                .map_err(internal)?
            && self.machine_exists(&mut conn, &binding.machine_id).await?
        {
            return Ok(Some(binding.machine_id));
        }

        Ok(None)
    }

    fn wants_irot_chain(&self) -> bool {
        self.mode != DpuDeviceAttestationMode::Disabled
    }

    async fn resolve_dpu_machine_id(
        &self,
        irot_chain_pem: Option<&str>,
        legacy_id: Option<MachineId>,
    ) -> Result<Option<MachineId>, DpuDeviceIdentityError> {
        // Enrollment stability is mode-independent: even in `disabled` mode a
        // DPU that previously adopted a device-rooted id keeps it, so rolling
        // the mode back never re-keys (and duplicates) adopted DPUs. Re-checked
        // here even though callers normally do it first (to skip the IRoT
        // fetch): the identity-stability guarantee must not depend on the
        // caller's discipline.
        if let Some(legacy_id) = legacy_id
            && let Some(enrolled) = self.enrolled_machine_id(legacy_id).await?
        {
            return Ok(Some(enrolled));
        }

        let verified = match irot_chain_pem {
            // `select_dpu_machine_id` ignores the chain in `disabled` mode;
            // skip the verification work outright.
            Some(pem) if self.wants_irot_chain() => {
                let mut conn = self.db.acquire().await.map_err(internal)?;
                self.verify(pem, &mut conn).await?
            }
            _ => None,
        };

        let selection = dpu_device::select_dpu_machine_id(self.mode, legacy_id, verified.as_ref())
            .map_err(|e| DpuDeviceIdentityError::Required(e.to_string()))?;

        match selection {
            DpuIdentitySelection::DeviceRooted(machine_id) => {
                if let Some(device) = &verified {
                    self.record_binding(machine_id, legacy_id, device).await;
                }
                Ok(Some(machine_id))
            }
            DpuIdentitySelection::Legacy(id) => Ok(id),
        }
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
            .resolve_dpu_machine_id(Some("not-even-parsed"), Some(legacy))
            .await
            .unwrap();
        assert_eq!(got, Some(legacy));
    }

    #[crate::sqlx_test]
    async fn best_effort_without_verified_identity_falls_back_to_legacy(pool: sqlx::PgPool) {
        let resolver =
            ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::BestEffort);
        let legacy = legacy_dpu_id();
        // No IRoT chain and no seeded roots -> not verified, not enrolled -> legacy.
        let got = resolver
            .resolve_dpu_machine_id(None, Some(legacy))
            .await
            .unwrap();
        assert_eq!(got, Some(legacy));
    }

    #[crate::sqlx_test]
    async fn required_mode_without_verified_identity_errors(pool: sqlx::PgPool) {
        let resolver = ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::Required);
        let err = resolver
            .resolve_dpu_machine_id(None, Some(legacy_dpu_id()))
            .await
            .expect_err("required mode with no verified identity must error");
        assert!(
            matches!(err, DpuDeviceIdentityError::Required(_)),
            "got {err:?}"
        );
    }

    #[crate::sqlx_test]
    async fn required_mode_fails_closed_without_legacy_id(pool: sqlx::PgPool) {
        // A DPU whose report has no serial-derived id must not slip past the
        // required-mode policy.
        let resolver = ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::Required);
        let err = resolver
            .resolve_dpu_machine_id(None, None)
            .await
            .expect_err("required mode must fail closed even with no legacy id");
        assert!(
            matches!(err, DpuDeviceIdentityError::Required(_)),
            "got {err:?}"
        );
    }

    #[crate::sqlx_test]
    async fn unknown_dpu_is_not_enrolled(pool: sqlx::PgPool) {
        let resolver =
            ApiDpuDeviceIdentityResolver::new(pool, DpuDeviceAttestationMode::BestEffort);
        let got = resolver.enrolled_machine_id(legacy_dpu_id()).await.unwrap();
        assert_eq!(got, None);
    }

    fn device_rooted_dpu_id() -> MachineId {
        MachineId::new(MachineIdSource::DpuDeviceCert, [9u8; 32], MachineType::Dpu)
    }

    // `force-delete --delete-device-identity` clears the binding so the DPU
    // re-keys. Deleting by the device-rooted id removes it.
    #[crate::sqlx_test]
    async fn delete_binding_by_machine_id_removes_it(pool: sqlx::PgPool) {
        use db::attestation::dpu_device_cert_status as binding;
        let device_id = device_rooted_dpu_id();
        let mut conn = pool.acquire().await.unwrap();
        binding::upsert(
            &mut conn,
            device_id,
            Some(legacy_dpu_id()),
            &[1u8; 32],
            "SERIAL123",
            None,
            &Utc::now(),
        )
        .await
        .unwrap();
        assert!(
            binding::get_by_machine_id(&mut conn, device_id)
                .await
                .unwrap()
                .is_some()
        );

        let removed = binding::delete_by_machine_id(&mut conn, device_id)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(
            binding::get_by_machine_id(&mut conn, device_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    // A DPU that fell back to (or kept) its legacy id is force-deleted by that
    // legacy id; deleting by it must still clear the device-identity binding.
    #[crate::sqlx_test]
    async fn delete_binding_by_legacy_id_removes_it(pool: sqlx::PgPool) {
        use db::attestation::dpu_device_cert_status as binding;
        let device_id = device_rooted_dpu_id();
        let legacy = legacy_dpu_id();
        let mut conn = pool.acquire().await.unwrap();
        binding::upsert(
            &mut conn,
            device_id,
            Some(legacy),
            &[1u8; 32],
            "SERIAL123",
            None,
            &Utc::now(),
        )
        .await
        .unwrap();

        let removed = binding::delete_by_machine_id(&mut conn, legacy)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(
            binding::get_by_machine_id(&mut conn, device_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
