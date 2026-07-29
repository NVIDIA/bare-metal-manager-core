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
            boot_interface.desired_version
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
            boot_interface.desired_version
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

async fn update(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    current_machine_version: ConfigVersion,
    expected_version: Option<ConfigVersion>,
    target: &MachineBootInterfaceTarget,
) -> DatabaseResult<Option<ConfigVersion>> {
    let desired_version = next_version(expected_version);
    let machine_version = current_machine_version.increment();
    let updated: Option<MachineId> = if let Some(expected_version) = expected_version {
        let query = r#"
            UPDATE machine_boot_interfaces
            SET desired_mac_address = $1,
                desired_interface_id = $2,
                desired_version = $3
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
            .fetch_optional(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(query, error))?
    } else {
        let query = r#"
            INSERT INTO machine_boot_interfaces (
                machine_id,
                desired_mac_address,
                desired_interface_id,
                desired_version
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (machine_id) DO NOTHING
            RETURNING machine_id
        "#;
        sqlx::query_scalar(query)
            .bind(machine_id)
            .bind(target.mac_address())
            .bind(target.interface_id())
            .bind(desired_version)
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
    validate_machine_id(machine_id)?;
    validate_target(target)?;

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    let current = row.decode(machine_id)?;
    if let Some(current) = current.as_ref()
        && request_is_satisfied(&current.value, target)
    {
        return Ok(current.clone());
    }

    let expected_version = current.as_ref().map(|current| current.version);
    let Some(version) = update(
        txn,
        machine_id,
        current_machine_version,
        expected_version,
        target,
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
pub async fn initialize_if_unset(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    target: &MachineBootInterfaceTarget,
) -> Result<Versioned<MachineBootInterfaceTarget>, DatabaseError> {
    validate_machine_id(machine_id)?;
    validate_target(target)?;

    let row = load_for_update(txn, machine_id).await?;
    let current_machine_version = row.machine_version;
    if let Some(current) = row.decode(machine_id)? {
        return Ok(current);
    }

    let Some(version) = update(txn, machine_id, current_machine_version, None, target).await?
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

#[cfg(test)]
mod tests {
    use carbide_uuid::machine::{MachineIdSource, MachineType};
    use sqlx::PgPool;

    use super::*;

    const MIGRATION: &str =
        include_str!("../migrations/20260728120000_machine_boot_interfaces.sql");

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
            VALUES ($1, '{}'::jsonb)
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
    async fn enrichment_only_strengthens_the_matching_mac(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(MachineType::Host, 3);
        seed_machine(txn.as_mut(), &machine_id).await?;
        let mac_address = MacAddress::new([2, 0, 0, 0, 0, 5]);
        let target = MachineBootInterfaceTarget::MacOnly(mac_address);
        let initialized = initialize_if_unset(txn.as_mut(), &machine_id, &target).await?;

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
}
