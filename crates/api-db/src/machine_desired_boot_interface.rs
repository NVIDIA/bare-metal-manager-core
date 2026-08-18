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

use carbide_uuid::machine::{MachineId, MachineType};
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use model::machine_boot_interface::{
    MachineBootInterface, MachineBootInterfaceTarget, canonical_redfish_boot_interface_id,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

#[derive(Debug, sqlx::FromRow)]
struct DesiredBootInterfaceRow {
    machine_version: ConfigVersion,
    desired_mac_address: Option<MacAddress>,
    desired_interface_id: Option<String>,
    desired_version: Option<ConfigVersion>,
    rollout_baseline_eligible: bool,
}

impl DesiredBootInterfaceRow {
    fn decode(
        self,
        machine_id: &MachineId,
    ) -> DatabaseResult<Option<Versioned<MachineBootInterfaceTarget>>> {
        match (
            self.desired_mac_address,
            self.desired_interface_id,
            self.desired_version,
        ) {
            (None, None, None) => Ok(None),
            (Some(mac_address), interface_id, Some(version)) => {
                if let Some(interface_id) = interface_id.as_deref()
                    && canonical_redfish_boot_interface_id(interface_id) != Some(interface_id)
                {
                    return Err(DatabaseError::Internal {
                        message: format!(
                            "machine {machine_id} has an empty or noncanonical desired boot interface id"
                        ),
                    });
                }
                let value = MachineBootInterfaceTarget::from_parts(Some(mac_address), interface_id)
                    .ok_or_else(|| DatabaseError::Internal {
                        message: format!(
                            "machine {machine_id} has an invalid desired boot interface"
                        ),
                    })?;
                Ok(Some(Versioned { value, version }))
            }
            _ => Err(DatabaseError::Internal {
                message: format!(
                    "machine {machine_id} has an inconsistent desired boot interface row"
                ),
            }),
        }
    }
}

fn validate_machine_id(machine_id: &MachineId) -> DatabaseResult<()> {
    let machine_type = machine_id.machine_type();
    if machine_type.is_host() || machine_type.is_predicted_host() {
        Ok(())
    } else {
        Err(DatabaseError::InvalidArgument(format!(
            "desired boot interfaces apply only to hosts, not {machine_type} machine {machine_id}"
        )))
    }
}

fn validate_target(target: &MachineBootInterfaceTarget) -> DatabaseResult<()> {
    if let Some(interface_id) = target.interface_id()
        && canonical_redfish_boot_interface_id(interface_id) != Some(interface_id)
    {
        Err(DatabaseError::InvalidArgument(
            "desired boot interface id must be nonempty and canonical".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn load(
    db: impl DbReader<'_>,
    machine_id: &MachineId,
) -> DatabaseResult<DesiredBootInterfaceRow> {
    let query = r#"
        SELECT
            machine.version AS machine_version,
            boot_interface.desired_mac_address,
            boot_interface.desired_interface_id,
            boot_interface.desired_version,
            COALESCE(
                machine.controller_state->>'state' IN ('ready', 'assigned'),
                false
            ) AS rollout_baseline_eligible
        FROM machines machine
        LEFT JOIN machine_boot_interfaces boot_interface
            ON boot_interface.machine_id = machine.id
        WHERE machine.id = $1
    "#;

    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })
}

async fn load_for_update(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<DesiredBootInterfaceRow> {
    let query = r#"
        SELECT
            machine.version AS machine_version,
            boot_interface.desired_mac_address,
            boot_interface.desired_interface_id,
            boot_interface.desired_version,
            COALESCE(
                machine.controller_state->>'state' IN ('ready', 'assigned'),
                false
            ) AS rollout_baseline_eligible
        FROM machines machine
        LEFT JOIN machine_boot_interfaces boot_interface
            ON boot_interface.machine_id = machine.id
        WHERE machine.id = $1
        FOR UPDATE OF machine
    "#;

    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|error| DatabaseError::query(query, error))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })
}

/// `get` returns the host's desired boot interface, or `None` before Site
/// Explorer has initialized it.
pub async fn get(
    db: impl DbReader<'_>,
    machine_id: &MachineId,
) -> Result<Option<Versioned<MachineBootInterfaceTarget>>, DatabaseError> {
    validate_machine_id(machine_id)?;
    load(db, machine_id).await?.decode(machine_id)
}

/// `lock` reads the desired boot interface while locking the machine row for
/// the rest of the caller's transaction.
pub async fn lock(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<Option<Versioned<MachineBootInterfaceTarget>>, DatabaseError> {
    validate_machine_id(machine_id)?;
    load_for_update(txn, machine_id).await?.decode(machine_id)
}

/// Returns one keyset page of hosts whose desired target is unset or still
/// lacks a Redfish id.
pub async fn find_incomplete_machine_ids(
    db: impl DbReader<'_>,
    after_id: Option<&MachineId>,
    limit: i64,
) -> DatabaseResult<Vec<MachineId>> {
    let query = r#"
        SELECT machine.id
        FROM machines machine
        LEFT JOIN machine_boot_interfaces boot_interface
            ON boot_interface.machine_id = machine.id
        WHERE (
                starts_with(machine.id, $1)
                OR starts_with(machine.id, $2)
            )
          AND boot_interface.desired_interface_id IS NULL
          AND ($3::text IS NULL OR machine.id::text > $3)
        ORDER BY machine.id
        LIMIT $4
    "#;

    sqlx::query_scalar(query)
        .bind(MachineType::Host.id_prefix())
        .bind(MachineType::PredictedHost.id_prefix())
        .bind(after_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

fn request_is_satisfied(
    current: &MachineBootInterfaceTarget,
    requested: &MachineBootInterfaceTarget,
) -> bool {
    current == requested
        || matches!(
            (current, requested),
            (
                MachineBootInterfaceTarget::Pair(current),
                MachineBootInterfaceTarget::MacOnly(requested_mac),
            ) if current.mac_address == *requested_mac
        )
}

fn next_version(expected_version: Option<ConfigVersion>) -> ConfigVersion {
    expected_version
        .map(|version| version.increment())
        .unwrap_or_else(ConfigVersion::initial)
}

#[derive(Clone, Copy)]
enum VerificationPolicy {
    Pending,
    AssumeVerified,
    CarryCurrentForward,
}

async fn update(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    current_machine_version: ConfigVersion,
    expected_version: Option<ConfigVersion>,
    target: &MachineBootInterfaceTarget,
    verification_policy: VerificationPolicy,
) -> DatabaseResult<Option<ConfigVersion>> {
    let (assume_verified, carry_current_forward) = match verification_policy {
        VerificationPolicy::Pending => (false, false),
        VerificationPolicy::AssumeVerified => (true, false),
        VerificationPolicy::CarryCurrentForward => (false, true),
    };
    let desired_version = next_version(expected_version);
    let machine_version = current_machine_version.increment();
    let updated: Option<MachineId> = if let Some(expected_version) = expected_version {
        let query = r#"
            UPDATE machine_boot_interfaces
            SET desired_mac_address = $1,
                desired_interface_id = $2,
                desired_version = $3,
                verified_version = CASE
                    WHEN $6 AND verified_version = $5 THEN $3
                    ELSE verified_version
                END
            WHERE machine_id = $4
              AND desired_version = $5
            RETURNING machine_id
        "#;
        sqlx::query_scalar(query)
            .bind(target.mac_address())
            .bind(target.interface_id())
            .bind(desired_version)
            .bind(machine_id)
            .bind(expected_version)
            .bind(carry_current_forward)
            .fetch_optional(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(query, error))?
    } else {
        let query = r#"
            INSERT INTO machine_boot_interfaces (
                machine_id,
                desired_mac_address,
                desired_interface_id,
                desired_version,
                verified_version,
                observed_at,
                assumed
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                CASE WHEN $5 THEN $4 END,
                CASE WHEN $5 THEN CURRENT_TIMESTAMP END,
                $5
            )
            ON CONFLICT (machine_id) DO NOTHING
            RETURNING machine_id
        "#;
        sqlx::query_scalar(query)
            .bind(machine_id)
            .bind(target.mac_address())
            .bind(target.interface_id())
            .bind(desired_version)
            .bind(assume_verified)
            .fetch_optional(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(query, error))?
    };

    if updated.is_none() {
        return Ok(None);
    }

    let query = r#"
        UPDATE machines
        SET version = $1
        WHERE id = $2
          AND version = $3
        RETURNING id
    "#;
    let bumped: Option<MachineId> = sqlx::query_scalar(query)
        .bind(machine_version)
        .bind(machine_id)
        .bind(current_machine_version)
        .fetch_optional(txn)
        .await
        .map_err(|error| DatabaseError::query(query, error))?;
    if bumped.is_none() {
        return Err(DatabaseError::Internal {
            message: format!(
                "failed to bump the aggregate version for locked machine {machine_id}"
            ),
        });
    }

    Ok(Some(desired_version))
}

/// `try_set` changes the target only when `expected_version` still matches.
///
/// It returns `true` for both an update and an already-satisfied request.
/// `false` means another writer changed the target first.
pub async fn try_set(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    expected_version: Option<ConfigVersion>,
    target: &MachineBootInterfaceTarget,
) -> Result<bool, DatabaseError> {
    validate_machine_id(machine_id)?;
    validate_target(target)?;

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    let current = row.decode(machine_id)?;

    if current
        .as_ref()
        .is_some_and(|current| request_is_satisfied(&current.value, target))
    {
        // A complete pair is stronger than the same MAC alone. Treat the
        // weaker retry as satisfied so it cannot discard the Redfish id.
        return Ok(true);
    }

    if current.as_ref().map(|current| current.version) != expected_version {
        return Ok(false);
    }

    Ok(update(
        txn,
        machine_id,
        current_machine_version,
        expected_version,
        target,
        VerificationPolicy::Pending,
    )
    .await?
    .is_some())
}

/// `set` stores an operator-selected target, serializing concurrent writers on
/// the machine row.
///
/// Repeating the current target is a no-op. A same-MAC MAC-only request also
/// keeps an existing pair so an operator retry cannot discard its Redfish id.
pub async fn set(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    target: &MachineBootInterfaceTarget,
) -> Result<Versioned<MachineBootInterfaceTarget>, DatabaseError> {
    set_with_mode(txn, machine_id, target, SetMode::IfChanged).await
}

/// `force_set` stores an operator-selected target as a new pending generation,
/// even when the value is unchanged.
///
/// A same-MAC MAC-only request keeps an existing complete pair, so forcing
/// convergence cannot discard the Redfish id we already learned.
pub async fn force_set(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    target: &MachineBootInterfaceTarget,
) -> Result<Versioned<MachineBootInterfaceTarget>, DatabaseError> {
    set_with_mode(txn, machine_id, target, SetMode::Force).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetMode {
    IfChanged,
    Force,
}

/// Serializes the desired-target write and applies the caller's generation
/// policy without weakening a complete interface pair.
async fn set_with_mode(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    target: &MachineBootInterfaceTarget,
    mode: SetMode,
) -> Result<Versioned<MachineBootInterfaceTarget>, DatabaseError> {
    validate_machine_id(machine_id)?;
    validate_target(target)?;

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    let current = row.decode(machine_id)?;
    if mode == SetMode::IfChanged
        && let Some(current) = current.as_ref()
        && request_is_satisfied(&current.value, target)
    {
        return Ok(current.clone());
    }

    let target = current
        .as_ref()
        .filter(|current| request_is_satisfied(&current.value, target))
        .map_or(target, |current| &current.value);
    let expected_version = current.as_ref().map(|current| current.version);
    let Some(version) = update(
        txn,
        machine_id,
        current_machine_version,
        expected_version,
        target,
        VerificationPolicy::Pending,
    )
    .await?
    else {
        return Err(DatabaseError::Internal {
            message: format!(
                "failed to set desired boot interface for locked machine {machine_id}"
            ),
        });
    };

    Ok(Versioned {
        value: target.clone(),
        version,
    })
}

/// `initialize_if_unset` stores Site Explorer's initial target without
/// replacing a target that is already present.
///
/// A stable host already in `Ready` or `Assigned` receives an explicitly
/// assumed compatibility observation. This covers a missing row during a
/// mixed-component rollout or later repair without scheduling fleet-wide
/// remediation. Normal lifecycle initialization happens on a predicted host or
/// in `HostInit`, so newly provisioned hosts remain pending real verification.
pub async fn initialize_if_unset(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    target: &MachineBootInterfaceTarget,
) -> Result<Versioned<MachineBootInterfaceTarget>, DatabaseError> {
    validate_machine_id(machine_id)?;
    validate_target(target)?;

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    let assume_verified = machine_id.machine_type().is_host() && row.rollout_baseline_eligible;
    let verification_policy = if assume_verified {
        VerificationPolicy::AssumeVerified
    } else {
        VerificationPolicy::Pending
    };
    if let Some(current) = row.decode(machine_id)? {
        return Ok(current);
    }

    let Some(version) = update(
        txn,
        machine_id,
        current_machine_version,
        None,
        target,
        verification_policy,
    )
    .await?
    else {
        return Err(DatabaseError::Internal {
            message: format!(
                "failed to initialize desired boot interface for locked machine {machine_id}"
            ),
        });
    };

    Ok(Versioned {
        value: target.clone(),
        version,
    })
}

/// `enrich_interface_id` adds a Redfish id to a matching MAC-only target.
///
/// Once a pair is stored, later observations do not replace its id.
/// Enrichment advances a current status because it strengthens the same
/// physical target's identity; stale or pending status remains unchanged.
pub async fn enrich_interface_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    mac_address: MacAddress,
    interface_id: &str,
) -> Result<Option<Versioned<MachineBootInterfaceTarget>>, DatabaseError> {
    validate_machine_id(machine_id)?;
    let Some(interface_id) = canonical_redfish_boot_interface_id(interface_id) else {
        return Err(DatabaseError::InvalidArgument(
            "desired boot interface id must not be blank".to_string(),
        ));
    };

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    let current = row.decode(machine_id)?;
    let Some(current) = current else {
        return Ok(None);
    };
    let MachineBootInterfaceTarget::MacOnly(current_mac) = current.value else {
        return Ok(Some(current));
    };
    if current_mac != mac_address {
        return Ok(Some(current));
    }

    let target = MachineBootInterfaceTarget::Pair(MachineBootInterface {
        mac_address,
        interface_id: interface_id.to_string(),
    });
    let expected_version = Some(current.version);
    let Some(version) = update(
        txn,
        machine_id,
        current_machine_version,
        expected_version,
        &target,
        VerificationPolicy::CarryCurrentForward,
    )
    .await?
    else {
        return Err(DatabaseError::Internal {
            message: format!(
                "failed to enrich desired boot interface for locked machine {machine_id}"
            ),
        });
    };

    Ok(Some(Versioned {
        value: target,
        version,
    }))
}

/// Tries to reopen an inspected target as a new pending generation after
/// Redfish drift.
///
/// The parent-machine lock and exact desired-generation check make this an
/// observation result, not a blind `force_set`: newer operator intent wins.
/// The verified-version check also makes replay a no-op once a generation is
/// already pending. `None` means either condition changed before this result
/// could be persisted.
pub async fn try_reopen_after_observed_drift(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    inspected_boot_interface: &Versioned<MachineBootInterfaceTarget>,
) -> Result<Option<Versioned<MachineBootInterfaceTarget>>, DatabaseError> {
    validate_machine_id(machine_id)?;
    validate_target(&inspected_boot_interface.value)?;

    let desired_boot_interface_row = load_for_update(txn, machine_id).await?;
    let current_machine_version = desired_boot_interface_row.machine_version;
    let Some(current_desired_boot_interface) = desired_boot_interface_row.decode(machine_id)?
    else {
        return Ok(None);
    };
    if current_desired_boot_interface.version != inspected_boot_interface.version
        || current_desired_boot_interface.value != inspected_boot_interface.value
    {
        return Ok(None);
    }

    // Read and lock the child status only after `load_for_update` has acquired
    // the parent-machine lock. Every desired/status writer uses this same
    // parent-first order, so this is both a fresh status read and deadlock-safe.
    let verified_version_query = r#"
        SELECT verified_version
        FROM machine_boot_interfaces
        WHERE machine_id = $1
        FOR UPDATE
    "#;
    let verified_version: Option<ConfigVersion> = sqlx::query_scalar(verified_version_query)
        .bind(machine_id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(verified_version_query, error))?;
    if verified_version != Some(current_desired_boot_interface.version) {
        return Ok(None);
    }

    let Some(reopened_version) = update(
        txn,
        machine_id,
        current_machine_version,
        Some(current_desired_boot_interface.version),
        &current_desired_boot_interface.value,
        VerificationPolicy::Pending,
    )
    .await?
    else {
        return Ok(None);
    };

    Ok(Some(Versioned {
        value: current_desired_boot_interface.value,
        version: reopened_version,
    }))
}

/// Records a Redfish observation only if the desired boot-interface version
/// still matches the version the caller observed.
///
/// A `false` return means the desired target was removed or replaced before
/// the observation could be committed. The caller must not treat that newer
/// target as verified.
pub async fn mark_verified(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    expected_desired_version: ConfigVersion,
    observed_at: DateTime<Utc>,
) -> Result<bool, DatabaseError> {
    validate_machine_id(machine_id)?;

    // Desired-target writers lock the parent machine row before touching this
    // child row. Preserve that order so a concurrent operator write cannot
    // deadlock verification against the state-controller transition, which
    // also updates the parent before commit.
    load_for_update(txn, machine_id).await?;

    let query = r#"
        UPDATE machine_boot_interfaces
        SET verified_version = desired_version,
            observed_at = $1,
            assumed = false
        WHERE machine_id = $2
          AND desired_version = $3
        RETURNING machine_id
    "#;
    let updated: Option<MachineId> = sqlx::query_scalar(query)
        .bind(observed_at)
        .bind(machine_id)
        .bind(expected_desired_version)
        .fetch_optional(txn)
        .await
        .map_err(|error| DatabaseError::query(query, error))?;

    Ok(updated.is_some())
}

#[cfg(test)]
mod tests {
    use carbide_uuid::machine::{MachineIdSource, MachineType};
    use model::machine::machine_search_config::MachineSearchConfig;
    use model::machine::{InstanceState, MachineState, ManagedHostState};
    use sqlx::PgPool;
    use sqlx::types::Json;

    use super::*;

    const MIGRATION: &str =
        include_str!("../migrations/20260728120000_machine_boot_interfaces.sql");
    const STATUS_MIGRATION: &str =
        include_str!("../migrations/20260730120000_machine_boot_interface_status.sql");

    fn machine_id(machine_type: MachineType, marker: u8) -> MachineId {
        let mut hardware_id = [0u8; 32];
        hardware_id[0] = marker;
        MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            hardware_id,
            machine_type,
        )
    }

    async fn seed_machine(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<ConfigVersion, sqlx::Error> {
        let query = r#"
            INSERT INTO machines (id, dpf)
            VALUES (
                $1,
                '{"enabled": false, "used_for_ingestion": false}'::jsonb
            )
            RETURNING version
        "#;
        sqlx::query_scalar(query)
            .bind(machine_id)
            .fetch_one(txn)
            .await
    }

    async fn versions(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<(ConfigVersion, Option<ConfigVersion>), sqlx::Error> {
        sqlx::query_as(
            "SELECT machine.version, boot_interface.desired_version
             FROM machines machine
             LEFT JOIN machine_boot_interfaces boot_interface
                 ON boot_interface.machine_id = machine.id
             WHERE machine.id = $1",
        )
        .bind(machine_id)
        .fetch_one(txn)
        .await
    }

    async fn set_controller_state(
        txn: &mut PgConnection,
        machine_id: &MachineId,
        state: ManagedHostState,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE machines SET controller_state = $1 WHERE id = $2")
            .bind(Json(state))
            .bind(machine_id)
            .execute(txn)
            .await?;
        Ok(())
    }

    async fn status_observation(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<(Option<ConfigVersion>, Option<DateTime<Utc>>, bool), sqlx::Error> {
        sqlx::query_as(
            "SELECT verified_version, observed_at, assumed
             FROM machine_boot_interfaces
             WHERE machine_id = $1",
        )
        .bind(machine_id)
        .fetch_one(txn)
        .await
    }

    fn assert_target(
        actual: &Versioned<MachineBootInterfaceTarget>,
        expected: &MachineBootInterfaceTarget,
    ) {
        assert_eq!(&actual.value, expected);
    }

    #[crate::sqlx_test]
    async fn initialize_only_sets_an_uninitialized_host(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 1);
        let initial_machine_version = seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 1]);
        let initial_target = MachineBootInterfaceTarget::MacOnly(mac_address);

        assert!(get(txn.as_mut(), &machine_id).await?.is_none());
        let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &initial_target).await?;
        assert_target(&initialized, &initial_target);
        assert_eq!(initialized.version.version_nr(), 1);

        let replacement = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 0, 2]));
        let existing = initialize_if_unset(txn.as_mut(), &machine_id, &replacement).await?;
        assert_target(&existing, &initial_target);
        assert_eq!(existing.version, initialized.version);

        let (machine_version, desired_version) = versions(txn.as_mut(), &machine_id).await?;
        assert_eq!(
            machine_version.version_nr(),
            initial_machine_version.version_nr() + 1
        );
        assert_eq!(desired_version, Some(initialized.version));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn rollout_baseline_only_applies_to_existing_stable_ready_or_assigned_hosts(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let cases = [
            (
                machine_id(MachineType::Host, 30),
                ManagedHostState::Ready,
                true,
            ),
            (
                machine_id(MachineType::Host, 31),
                ManagedHostState::Assigned {
                    instance_state: InstanceState::Init,
                },
                true,
            ),
            (
                machine_id(MachineType::Host, 32),
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForPlatformConfiguration { retry_count: 0 },
                },
                false,
            ),
            (
                machine_id(MachineType::PredictedHost, 33),
                ManagedHostState::Ready,
                false,
            ),
        ];

        for (index, (machine_id, state, expect_assumed)) in cases.into_iter().enumerate() {
            seed_machine(txn.as_mut(), &machine_id).await?;
            set_controller_state(txn.as_mut(), &machine_id, state).await?;
            let target =
                MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, index as u8]));
            let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &target).await?;
            let (verified_version, observed_at, assumed) =
                status_observation(txn.as_mut(), &machine_id).await?;

            if expect_assumed {
                assert_eq!(verified_version, Some(initialized.version));
                assert!(observed_at.is_some());
                assert!(assumed);
            } else {
                assert_eq!(verified_version, None);
                assert_eq!(observed_at, None);
                assert!(!assumed);
            }
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn verification_is_a_cas_and_is_exposed_in_machine_snapshots(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 34);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let target = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, 4]));
        let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &target).await?;
        let observed_at =
            DateTime::from_timestamp(1_722_000_000, 123_000_000).expect("fixture timestamp");

        assert!(
            !mark_verified(
                txn.as_mut(),
                &machine_id,
                ConfigVersion::invalid(),
                observed_at,
            )
            .await?
        );
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (None, None, false)
        );

        assert!(mark_verified(txn.as_mut(), &machine_id, initialized.version, observed_at,).await?);
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(initialized.version), Some(observed_at), false)
        );

        let machine =
            crate::machine::find_one(txn.as_mut(), &machine_id, MachineSearchConfig::default())
                .await?
                .expect("machine snapshot");
        let observation = machine
            .status
            .boot_interface_status_observation
            .expect("boot interface status observation");
        assert_eq!(observation.config_version, initialized.version);
        assert_eq!(observation.observed_at, observed_at);
        assert!(!observation.assumed);

        let replacement = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, 5]));
        let updated = set(txn.as_mut(), &machine_id, &replacement).await?;
        assert_ne!(updated.version, initialized.version);
        assert!(!mark_verified(txn.as_mut(), &machine_id, initialized.version, Utc::now(),).await?);
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(initialized.version), Some(observed_at), false),
            "changing the target keeps the last factual observation but makes its version stale",
        );

        Ok(())
    }

    /// A drift result for an old generation cannot overwrite newer operator intent.
    #[crate::sqlx_test]
    async fn observation_results_reject_a_newer_desired_generation(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 44);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let inspected_target = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address: MacAddress::new([2, 0, 0, 0, 4, 4]),
            interface_id: "NIC.Slot.4-1-1".to_string(),
        });
        let inspected_desired = set(txn.as_mut(), &machine_id, &inspected_target).await?;
        let observed_at =
            DateTime::from_timestamp(1_722_000_300, 123_000_000).expect("fixture timestamp");
        assert!(
            mark_verified(
                txn.as_mut(),
                &machine_id,
                inspected_desired.version,
                observed_at,
            )
            .await?
        );

        let operator_target =
            MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 4, 5]));
        let operator_desired = set(txn.as_mut(), &machine_id, &operator_target).await?;
        assert!(
            try_reopen_after_observed_drift(txn.as_mut(), &machine_id, &inspected_desired)
                .await?
                .is_none()
        );
        let persisted_desired = get(txn.as_mut(), &machine_id)
            .await?
            .expect("operator-selected target");
        assert_target(&persisted_desired, &operator_desired.value);
        assert_eq!(persisted_desired.version, operator_desired.version);
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(inspected_desired.version), Some(observed_at), false,),
        );

        Ok(())
    }

    /// Exact Pair drift opens one pending generation for the same target.
    #[crate::sqlx_test]
    async fn observation_drift_reopens_the_exact_pair_once(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 45);
        let initial_machine_version = seed_machine(txn.as_mut(), &machine_id).await?;
        let inspected_target = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address: MacAddress::new([2, 0, 0, 0, 4, 6]),
            interface_id: "NIC.Slot.4-1-2".to_string(),
        });
        let inspected_desired = set(txn.as_mut(), &machine_id, &inspected_target).await?;
        let observed_at =
            DateTime::from_timestamp(1_722_000_400, 123_000_000).expect("fixture timestamp");
        assert!(
            mark_verified(
                txn.as_mut(),
                &machine_id,
                inspected_desired.version,
                observed_at,
            )
            .await?
        );

        let pending_desired =
            try_reopen_after_observed_drift(txn.as_mut(), &machine_id, &inspected_desired)
                .await?
                .expect("fresh pending generation");
        assert_target(&pending_desired, &inspected_target);
        assert_eq!(
            pending_desired.version.version_nr(),
            inspected_desired.version.version_nr() + 1
        );
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(inspected_desired.version), Some(observed_at), false,),
            "drift keeps the last factual observation while the new generation is pending",
        );
        let (machine_version_after_reopen, desired_version_after_reopen) =
            versions(txn.as_mut(), &machine_id).await?;
        assert_eq!(
            machine_version_after_reopen.version_nr(),
            initial_machine_version.version_nr() + 2,
        );
        assert_eq!(desired_version_after_reopen, Some(pending_desired.version));

        assert!(
            try_reopen_after_observed_drift(txn.as_mut(), &machine_id, &pending_desired)
                .await?
                .is_none(),
            "an already-pending generation must not be reopened",
        );
        assert_eq!(
            versions(txn.as_mut(), &machine_id).await?,
            (machine_version_after_reopen, desired_version_after_reopen),
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn concurrent_set_and_mark_verified_use_parent_first_lock_order(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let machine_id = machine_id(MachineType::Host, 35);
        let initial_target =
            MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, 6]));
        let replacement = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, 7]));

        let mut setup_txn = pool.begin().await?;
        seed_machine(setup_txn.as_mut(), &machine_id).await?;
        let initial = initialize_if_unset(setup_txn.as_mut(), &machine_id, &initial_target).await?;
        setup_txn.commit().await?;

        // Hold the parent lock as `set` does. `mark_verified` must wait here,
        // before it can lock the child intent row.
        let mut setter_txn = pool.begin().await?;
        let setter_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(setter_txn.as_mut())
            .await?;
        load_for_update(setter_txn.as_mut(), &machine_id).await?;

        let (verification_pid_tx, verification_pid_rx) = tokio::sync::oneshot::channel();
        let verification_pool = pool.clone();
        let mut verification_task = tokio::spawn(async move {
            let mut txn = verification_pool
                .begin()
                .await
                .map_err(|error| error.to_string())?;
            let verification_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            verification_pid_tx
                .send(verification_pid)
                .map_err(|_| "could not signal verification backend pid".to_string())?;

            let marked = mark_verified(txn.as_mut(), &machine_id, initial.version, Utc::now())
                .await
                .map_err(|error| error.to_string())?;

            // The real state-controller transaction updates the parent state
            // after recording verification. This remains safe because
            // mark_verified already owns the parent lock.
            sqlx::query("UPDATE machines SET updated = updated WHERE id = $1")
                .bind(machine_id)
                .execute(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            txn.commit().await.map_err(|error| error.to_string())?;

            Ok::<bool, String>(marked)
        });

        let verification_pid = verification_pid_rx
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let wait_for_parent_lock = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked_by_setter: bool =
                    sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                        .bind(setter_pid)
                        .bind(verification_pid)
                        .fetch_one(&pool)
                        .await?;
                if blocked_by_setter {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        match wait_for_parent_lock {
            Ok(result) => result?,
            Err(_) => {
                verification_task.abort();
                let _ = verification_task.await;
                return Err(std::io::Error::other(
                    "verification did not wait on the setter's parent lock",
                )
                .into());
            }
        }

        let updated = set(setter_txn.as_mut(), &machine_id, &replacement).await?;
        setter_txn.commit().await?;

        let marked =
            match tokio::time::timeout(std::time::Duration::from_secs(5), &mut verification_task)
                .await
            {
                Ok(result) => result
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .map_err(std::io::Error::other)?,
                Err(_) => {
                    verification_task.abort();
                    let _ = verification_task.await;
                    return Err(std::io::Error::other("set and verification deadlocked").into());
                }
            };

        assert!(!marked, "a superseded desired version must not be verified");
        let desired = get(&pool, &machine_id).await?.expect("replacement target");
        assert_target(&desired, &replacement);
        assert_eq!(desired.version, updated.version);
        let mut conn = pool.acquire().await?;
        assert_eq!(
            status_observation(conn.as_mut(), &machine_id).await?,
            (None, None, false),
            "stale verification must not stamp the replacement version",
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn try_set_uses_cas_without_bumping_noops(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::PredictedHost, 2);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 3]);
        let pair = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: "NIC.Slot.7-1-1".to_string(),
        });
        let padded_pair = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: " \tNIC.Slot.7-1-1\n ".to_string(),
        });
        assert!(matches!(
            try_set(txn.as_mut(), &machine_id, None, &padded_pair).await,
            Err(DatabaseError::InvalidArgument(_))
        ));

        let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &pair).await?;
        let versions_before = versions(txn.as_mut(), &machine_id).await?;

        assert!(
            try_set(
                txn.as_mut(),
                &machine_id,
                Some(ConfigVersion::invalid()),
                &pair,
            )
            .await?
        );
        assert!(
            try_set(
                txn.as_mut(),
                &machine_id,
                Some(initialized.version),
                &MachineBootInterfaceTarget::MacOnly(mac_address),
            )
            .await?
        );
        assert_eq!(versions(txn.as_mut(), &machine_id).await?, versions_before);
        assert_target(
            &get(txn.as_mut(), &machine_id).await?.expect("target"),
            &pair,
        );

        let replacement = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 0, 4]));
        assert!(
            !try_set(
                txn.as_mut(),
                &machine_id,
                Some(ConfigVersion::invalid()),
                &replacement,
            )
            .await?
        );
        assert!(
            try_set(
                txn.as_mut(),
                &machine_id,
                Some(initialized.version),
                &replacement,
            )
            .await?
        );

        let updated = get(txn.as_mut(), &machine_id).await?.expect("target");
        assert_target(&updated, &replacement);
        assert_eq!(
            updated.version.version_nr(),
            initialized.version.version_nr() + 1
        );
        let versions_after = versions(txn.as_mut(), &machine_id).await?;
        assert_eq!(
            versions_after.0.version_nr(),
            versions_before.0.version_nr() + 1
        );
        assert_eq!(versions_after.1, Some(updated.version));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn set_serializes_operator_updates_without_weakening_pairs(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 5);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 8]);
        let pair = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: "NIC.Slot.8-1-1".to_string(),
        });

        let initialized = set(
            txn.as_mut(),
            &machine_id,
            &MachineBootInterfaceTarget::MacOnly(mac_address),
        )
        .await?;
        let paired = set(txn.as_mut(), &machine_id, &pair).await?;
        assert_eq!(
            paired.version.version_nr(),
            initialized.version.version_nr() + 1
        );

        let unchanged = set(
            txn.as_mut(),
            &machine_id,
            &MachineBootInterfaceTarget::MacOnly(mac_address),
        )
        .await?;
        assert_target(&unchanged, &pair);
        assert_eq!(unchanged.version, paired.version);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn force_set_creates_a_pending_generation_without_weakening_pairs(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 37);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 3, 10]);
        let pair = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: "NIC.Slot.10-1-1".to_string(),
        });
        let paired = set(txn.as_mut(), &machine_id, &pair).await?;
        let observed_at =
            DateTime::from_timestamp(1_722_000_200, 123_000_000).expect("fixture timestamp");
        assert!(mark_verified(txn.as_mut(), &machine_id, paired.version, observed_at).await?);
        let versions_before = versions(txn.as_mut(), &machine_id).await?;

        let forced = force_set(
            txn.as_mut(),
            &machine_id,
            &MachineBootInterfaceTarget::MacOnly(mac_address),
        )
        .await?;
        assert_target(&forced, &pair);
        assert_eq!(forced.version.version_nr(), paired.version.version_nr() + 1);
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(paired.version), Some(observed_at), false),
            "the fresh generation must remain pending",
        );

        let versions_after = versions(txn.as_mut(), &machine_id).await?;
        assert_eq!(
            versions_after.0.version_nr(),
            versions_before.0.version_nr() + 1
        );
        assert_eq!(versions_after.1, Some(forced.version));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn enrichment_only_strengthens_the_matching_mac(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 3);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 5]);
        let target = MachineBootInterfaceTarget::MacOnly(mac_address);
        let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &target).await?;
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (None, None, false),
        );

        let mismatch = enrich_interface_id(
            txn.as_mut(),
            &machine_id,
            MacAddress::new([2, 0, 0, 0, 0, 6]),
            "wrong",
        )
        .await?
        .expect("target");
        assert_target(&mismatch, &target);
        assert_eq!(mismatch.version, initialized.version);

        let enriched = enrich_interface_id(
            txn.as_mut(),
            &machine_id,
            mac_address,
            " \t\n\u{000b}\u{000c}\rNIC.Slot.7-1-1 \t\n\u{000b}\u{000c}\r",
        )
        .await?
        .expect("target");
        let pair = MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: "NIC.Slot.7-1-1".to_string(),
        });
        assert_target(&enriched, &pair);
        assert_eq!(
            enriched.version.version_nr(),
            initialized.version.version_nr() + 1
        );
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (None, None, false),
            "enrichment must not make an unverified target look converged",
        );

        let unchanged = enrich_interface_id(txn.as_mut(), &machine_id, mac_address, "replacement")
            .await?
            .expect("target");
        assert_target(&unchanged, &pair);
        assert_eq!(unchanged.version, enriched.version);

        assert!(matches!(
            enrich_interface_id(txn.as_mut(), &machine_id, mac_address, "\t\n").await,
            Err(DatabaseError::InvalidArgument(_))
        ));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn enrichment_carries_current_verification_without_hiding_target_changes(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 36);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 3, 8]);
        let initialized = initialize_if_unset(
            txn.as_mut(),
            &machine_id,
            &MachineBootInterfaceTarget::MacOnly(mac_address),
        )
        .await?;
        let observed_at =
            DateTime::from_timestamp(1_722_000_100, 123_000_000).expect("fixture timestamp");
        assert!(mark_verified(txn.as_mut(), &machine_id, initialized.version, observed_at,).await?);

        let enriched =
            enrich_interface_id(txn.as_mut(), &machine_id, mac_address, "NIC.Slot.8-1-1")
                .await?
                .expect("enriched target");
        assert_eq!(
            enriched.version.version_nr(),
            initialized.version.version_nr() + 1,
            "the enriched value remains a distinct immutable desired generation",
        );
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(enriched.version), Some(observed_at), false),
            "adding an id for the same MAC must not schedule redundant convergence",
        );

        let replacement = MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 3, 9]));
        let replaced = set(txn.as_mut(), &machine_id, &replacement).await?;
        assert_ne!(replaced.version, enriched.version);
        assert_eq!(
            status_observation(txn.as_mut(), &machine_id).await?,
            (Some(enriched.version), Some(observed_at), false),
            "a different target must retain only the stale factual observation",
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn desired_targets_reject_dpu_ids(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Dpu, 4);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 7]);
        let target = MachineBootInterfaceTarget::MacOnly(mac_address);

        assert!(matches!(
            get(txn.as_mut(), &machine_id).await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            lock(txn.as_mut(), &machine_id).await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            try_set(txn.as_mut(), &machine_id, None, &target).await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            set(txn.as_mut(), &machine_id, &target).await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            initialize_if_unset(txn.as_mut(), &machine_id, &target).await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            enrich_interface_id(txn.as_mut(), &machine_id, mac_address, "id").await,
            Err(DatabaseError::InvalidArgument(_))
        ));
        assert!(matches!(
            mark_verified(
                txn.as_mut(),
                &machine_id,
                ConfigVersion::initial(),
                Utc::now(),
            )
            .await,
            Err(DatabaseError::InvalidArgument(_))
        ));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn incomplete_targets_are_keyset_paged(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let unset_host = machine_id(MachineType::Host, 10);
        let mac_only_host = machine_id(MachineType::Host, 11);
        let unset_prediction = machine_id(MachineType::PredictedHost, 12);
        let complete_host = machine_id(MachineType::Host, 13);
        let dpu = machine_id(MachineType::Dpu, 14);
        for machine_id in [
            &unset_host,
            &mac_only_host,
            &unset_prediction,
            &complete_host,
            &dpu,
        ] {
            seed_machine(txn.as_mut(), machine_id).await?;
        }

        set(
            txn.as_mut(),
            &mac_only_host,
            &MachineBootInterfaceTarget::MacOnly(MacAddress::new([2, 0, 0, 0, 1, 1])),
        )
        .await?;
        set(
            txn.as_mut(),
            &complete_host,
            &MachineBootInterfaceTarget::Pair(MachineBootInterface {
                mac_address: MacAddress::new([2, 0, 0, 0, 1, 2]),
                interface_id: "NIC.Slot.1-1-1".to_string(),
            }),
        )
        .await?;
        txn.commit().await?;

        let mut found = Vec::new();
        let mut after_id = None;
        loop {
            let page = find_incomplete_machine_ids(&pool, after_id.as_ref(), 2).await?;
            let Some(last) = page.last() else {
                break;
            };
            after_id = Some(*last);
            found.extend(page);
        }

        let mut expected = vec![unset_host, mac_only_host, unset_prediction];
        expected.sort();
        assert_eq!(found, expected);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn migration_creates_an_empty_constrained_host_table(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query("DROP TABLE machine_boot_interfaces")
            .execute(&pool)
            .await?;

        let mut txn = pool.begin().await?;
        let predicted_id = machine_id(MachineType::PredictedHost, 20);
        let dpu_id = machine_id(MachineType::Dpu, 21);
        seed_machine(txn.as_mut(), &predicted_id).await?;
        seed_machine(txn.as_mut(), &dpu_id).await?;
        txn.commit().await?;

        sqlx::raw_sql(MIGRATION).execute(&pool).await?;
        let row_count: i64 = sqlx::query_scalar("SELECT count(*) FROM machine_boot_interfaces")
            .fetch_one(&pool)
            .await?;
        assert_eq!(row_count, 0, "the schema migration must not backfill data");

        let desired_version = ConfigVersion::initial();
        sqlx::query(
            "INSERT INTO machine_boot_interfaces (
                 machine_id,
                 desired_mac_address,
                 desired_interface_id,
                 desired_version
             )
             VALUES ($1, $2, $3, $4)",
        )
        .bind(predicted_id)
        .bind(MacAddress::new([2, 0, 0, 0, 2, 1]))
        .bind("NIC.Slot.2-1-1")
        .bind(desired_version)
        .execute(&pool)
        .await?;

        for noncanonical_id in ["\t\n", " \tcanonical-id\n "] {
            let result = sqlx::query(
                "UPDATE machine_boot_interfaces
                 SET desired_interface_id = $1
                 WHERE machine_id = $2",
            )
            .bind(noncanonical_id)
            .bind(predicted_id)
            .execute(&pool)
            .await;
            assert!(
                result.is_err(),
                "the table constraint should reject {noncanonical_id:?}"
            );
        }

        let dpu_result = sqlx::query(
            "INSERT INTO machine_boot_interfaces (
                 machine_id,
                 desired_mac_address,
                 desired_version
             )
             VALUES ($1, $2, $3)",
        )
        .bind(dpu_id)
        .bind(MacAddress::new([2, 0, 0, 0, 2, 2]))
        .bind(desired_version)
        .execute(&pool)
        .await;
        assert!(dpu_result.is_err(), "the table must reject DPU targets");

        let stable_id = machine_id(MachineType::Host, 22);
        sqlx::query("UPDATE machines SET id = $1 WHERE id = $2")
            .bind(stable_id)
            .bind(predicted_id)
            .execute(&pool)
            .await?;
        let stored_machine_id: MachineId =
            sqlx::query_scalar("SELECT machine_id FROM machine_boot_interfaces")
                .fetch_one(&pool)
                .await?;
        assert_eq!(stored_machine_id, stable_id);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn status_migration_scopes_rollout_baseline_and_constrains_status(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query("DROP TABLE machine_boot_interfaces")
            .execute(&pool)
            .await?;

        let mut txn = pool.begin().await?;
        let existing_host = machine_id(MachineType::Host, 40);
        let in_flight_host = machine_id(MachineType::Host, 42);
        seed_machine(txn.as_mut(), &existing_host).await?;
        seed_machine(txn.as_mut(), &in_flight_host).await?;
        set_controller_state(txn.as_mut(), &existing_host, ManagedHostState::Ready).await?;
        set_controller_state(
            txn.as_mut(),
            &in_flight_host,
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForPlatformConfiguration { retry_count: 0 },
            },
        )
        .await?;
        txn.commit().await?;

        sqlx::raw_sql(MIGRATION).execute(&pool).await?;
        let existing_version = ConfigVersion::initial();
        for (machine_id, mac_address) in [
            (existing_host, MacAddress::new([2, 0, 0, 0, 4, 0])),
            (in_flight_host, MacAddress::new([2, 0, 0, 0, 4, 2])),
        ] {
            sqlx::query(
                "INSERT INTO machine_boot_interfaces (
                     machine_id,
                     desired_mac_address,
                     desired_version
                 )
                 VALUES ($1, $2, $3)",
            )
            .bind(machine_id)
            .bind(mac_address)
            .bind(existing_version)
            .execute(&pool)
            .await?;
        }

        sqlx::raw_sql(STATUS_MIGRATION).execute(&pool).await?;
        let (verified_version, observed_at, assumed): (
            Option<ConfigVersion>,
            Option<DateTime<Utc>>,
            bool,
        ) = sqlx::query_as(
            "SELECT verified_version, observed_at, assumed
             FROM machine_boot_interfaces
             WHERE machine_id = $1",
        )
        .bind(existing_host)
        .fetch_one(&pool)
        .await?;
        assert_eq!(verified_version, Some(existing_version));
        assert!(observed_at.is_some());
        assert!(assumed);

        let in_flight_status: (Option<ConfigVersion>, Option<DateTime<Utc>>, bool) =
            sqlx::query_as(
                "SELECT verified_version, observed_at, assumed
                 FROM machine_boot_interfaces
                 WHERE machine_id = $1",
            )
            .bind(in_flight_host)
            .fetch_one(&pool)
            .await?;
        assert_eq!(in_flight_status, (None, None, false));

        for inconsistent_update in [
            "UPDATE machine_boot_interfaces
             SET observed_at = CURRENT_TIMESTAMP
             WHERE machine_id = $1",
            "UPDATE machine_boot_interfaces
             SET assumed = true
             WHERE machine_id = $1",
        ] {
            let result = sqlx::query(inconsistent_update)
                .bind(in_flight_host)
                .execute(&pool)
                .await;
            assert!(
                result.is_err(),
                "the status consistency constraint should reject {inconsistent_update:?}",
            );
        }

        Ok(())
    }
}
