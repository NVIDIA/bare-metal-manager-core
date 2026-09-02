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

use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
use config_version::ConfigVersion;
use model::vpc::routing_profile_transition::{
    NewVpcRoutingProfileTransition, UpdateVpcRoutingProfileTransitionState,
    VpcRoutingProfileTransition, VpcRoutingProfileTransitionState,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

const ACTIVE_TRANSITION_UNIQUE: &str = "vpc_routing_profile_transitions_one_active_per_vpc";

/// Creates the durable recovery point for a cutover that has already updated
/// the VPC in the caller's transaction.
///
/// A new transition always starts with its target active and both VNI leases
/// retained. Replays should call [`find`] by operation ID before creating; a
/// concurrent different operation for the same VPC is rejected by the partial
/// unique index.
pub async fn create(
    value: &NewVpcRoutingProfileTransition,
    txn: &mut PgConnection,
) -> DatabaseResult<VpcRoutingProfileTransition> {
    let version = ConfigVersion::initial();
    let state = VpcRoutingProfileTransitionState::CutoverPendingFinalize;
    let query = r#"
        INSERT INTO vpc_routing_profile_transitions (
            id,
            vpc_id,
            version,
            state,
            source_routing_profile_type,
            target_routing_profile_type,
            source_pool_name,
            target_pool_name,
            source_vni,
            target_vni,
            source_requested_vni,
            target_requested_vni,
            source_routing_profile_overrides,
            target_routing_profile_overrides,
            source_vpc_version,
            cutover_vpc_version,
            reason
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13::jsonb, $14::jsonb, $15, $16, $17
        )
        RETURNING *
    "#;

    sqlx::query_as(query)
        .bind(value.id)
        .bind(value.vpc_id)
        .bind(version)
        .bind(state)
        .bind(&value.source_routing_profile_type)
        .bind(&value.target_routing_profile_type)
        .bind(&value.source_pool_name)
        .bind(&value.target_pool_name)
        .bind(value.source_vni)
        .bind(value.target_vni)
        .bind(value.source_requested_vni)
        .bind(value.target_requested_vni)
        .bind(
            value
                .source_routing_profile_overrides
                .as_ref()
                .map(sqlx::types::Json),
        )
        .bind(
            value
                .target_routing_profile_overrides
                .as_ref()
                .map(sqlx::types::Json),
        )
        .bind(value.source_vpc_version)
        .bind(value.cutover_vpc_version)
        .bind(&value.reason)
        .fetch_one(txn)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(database_error)
                if database_error.constraint() == Some(ACTIVE_TRANSITION_UNIQUE) =>
            {
                DatabaseError::FailedPrecondition(format!(
                    "VPC {} already has an active routing-profile transition",
                    value.vpc_id
                ))
            }
            _ => DatabaseError::query(query, error),
        })
}

/// Finds an operation by its caller-supplied idempotency key.
pub async fn find(
    db: impl DbReader<'_>,
    id: VpcRoutingProfileTransitionId,
) -> DatabaseResult<Option<VpcRoutingProfileTransition>> {
    let query = "SELECT * FROM vpc_routing_profile_transitions WHERE id = $1";
    sqlx::query_as(query)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Returns the complete transition history for one VPC, oldest first.
pub async fn find_by_vpc(
    db: impl DbReader<'_>,
    vpc_id: VpcId,
) -> DatabaseResult<Vec<VpcRoutingProfileTransition>> {
    let query = r#"
        SELECT *
        FROM vpc_routing_profile_transitions
        WHERE vpc_id = $1
        ORDER BY created, id
    "#;
    sqlx::query_as(query)
        .bind(vpc_id)
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Finds the single nonterminal transition for a VPC, if one exists.
pub async fn find_active_by_vpc(
    db: impl DbReader<'_>,
    vpc_id: VpcId,
) -> DatabaseResult<Option<VpcRoutingProfileTransition>> {
    let query = r#"
        SELECT *
        FROM vpc_routing_profile_transitions
        WHERE vpc_id = $1
          AND state IN ($2, $3)
    "#;
    sqlx::query_as(query)
        .bind(vpc_id)
        .bind(VpcRoutingProfileTransitionState::CutoverPendingFinalize)
        .bind(VpcRoutingProfileTransitionState::RollbackPendingFinalize)
        .fetch_optional(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Lists transition history deterministically across all VPCs.
pub async fn list(db: impl DbReader<'_>) -> DatabaseResult<Vec<VpcRoutingProfileTransition>> {
    let query = r#"
        SELECT *
        FROM vpc_routing_profile_transitions
        ORDER BY vpc_id, created, id
    "#;
    sqlx::query_as(query)
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Locks one transition after the caller has locked its parent VPC.
///
/// Keeping this lock order consistent avoids deadlocks with VPC mutation
/// handlers. The returned lock is held until the caller's transaction ends.
pub async fn lock_by_id_after_vpc_lock(
    txn: &mut PgConnection,
    id: VpcRoutingProfileTransitionId,
) -> DatabaseResult<Option<VpcRoutingProfileTransition>> {
    let query = "SELECT * FROM vpc_routing_profile_transitions WHERE id = $1 FOR UPDATE";
    sqlx::query_as(query)
        .bind(id)
        .fetch_optional(txn)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Advances a transition stage with optimistic concurrency.
///
/// Handlers choose the legal state-machine edge and perform the associated VPC
/// update. This operation requires their exact predecessor in addition to the
/// optimistic version, persists the chosen stage, refreshes the relevant VPC
/// version provenance, and derives terminal timestamps consistently. A
/// missing row, stale version, or changed predecessor share the existing
/// combined concurrent-modification policy.
pub async fn update_state(
    value: &UpdateVpcRoutingProfileTransitionState,
    txn: &mut PgConnection,
) -> DatabaseResult<VpcRoutingProfileTransition> {
    if !value.expected_state.can_transition_to(value.state) {
        return Err(DatabaseError::InvalidArgument(format!(
            "invalid VPC routing-profile transition edge from {:?} to {:?}",
            value.expected_state, value.state
        )));
    }
    let next_version = value.if_version_match.increment();
    let query = r#"
        UPDATE vpc_routing_profile_transitions
        SET state = $1,
            version = $2,
            cutover_vpc_version = COALESCE($3, cutover_vpc_version),
            rollback_vpc_version = COALESCE($4, rollback_vpc_version),
            updated = now(),
            completed = CASE
                WHEN $1 IN ($5, $6) THEN COALESCE(completed, now())
                ELSE NULL
            END
        WHERE id = $7
          AND version = $8
          AND state = $9
        RETURNING *
    "#;
    sqlx::query_as(query)
        .bind(value.state)
        .bind(next_version)
        .bind(value.cutover_vpc_version)
        .bind(value.rollback_vpc_version)
        .bind(VpcRoutingProfileTransitionState::Finalized)
        .bind(VpcRoutingProfileTransitionState::RolledBack)
        .bind(value.id)
        .bind(value.if_version_match)
        .bind(value.expected_state)
        .fetch_one(txn)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => DatabaseError::ConcurrentModificationError(
                "VPC routing-profile transition",
                value.if_version_match.to_string(),
            ),
            error => DatabaseError::query(query, error),
        })
}

#[cfg(test)]
mod tests {
    use carbide_uuid::vpc::VpcId;
    use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
    use config_version::ConfigVersion;
    use model::vpc::routing_profile::{RouteTargetConfig, VpcRoutingProfileOverrides};
    use model::vpc::routing_profile_transition::{
        NewVpcRoutingProfileTransition, UpdateVpcRoutingProfileTransitionState,
        VpcRoutingProfileTransitionState,
    };

    use super::*;

    async fn insert_vpc(vpc_id: VpcId, txn: &mut PgConnection) {
        let query = r#"
            INSERT INTO vpcs (id, name, organization_id, version)
            VALUES ($1, $2, $3, $4)
        "#;
        sqlx::query(query)
            .bind(vpc_id)
            .bind(format!("test-{vpc_id}"))
            .bind("test-tenant")
            .bind(ConfigVersion::initial())
            .execute(txn)
            .await
            .unwrap();
    }

    fn new_transition(
        id: VpcRoutingProfileTransitionId,
        vpc_id: VpcId,
    ) -> NewVpcRoutingProfileTransition {
        NewVpcRoutingProfileTransition {
            id,
            vpc_id,
            source_routing_profile_type: "INTERNAL".to_string(),
            target_routing_profile_type: "EXTERNAL".to_string(),
            source_pool_name: "vpc-vni".to_string(),
            target_pool_name: "external-vpc-vni".to_string(),
            source_vni: 20_001,
            target_vni: 51_000,
            source_requested_vni: None,
            target_requested_vni: Some(51_000),
            source_routing_profile_overrides: Some(VpcRoutingProfileOverrides {
                route_target_imports: Some(vec![RouteTargetConfig {
                    asn: 65_000,
                    vni: 20_001,
                }]),
                ..Default::default()
            }),
            target_routing_profile_overrides: Some(VpcRoutingProfileOverrides::default()),
            source_vpc_version: ConfigVersion::new(7),
            cutover_vpc_version: ConfigVersion::new(8),
            reason: "test transition".to_string(),
        }
    }

    #[crate::sqlx_test]
    async fn create_and_queries_preserve_transition_provenance(pool: sqlx::PgPool) {
        let vpc_id = VpcId::new();
        let id = VpcRoutingProfileTransitionId::new();
        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let input = new_transition(id, vpc_id);

        let created = create(&input, txn.as_mut()).await.unwrap();
        assert_eq!(created.id, id);
        assert_eq!(created.vpc_id, vpc_id);
        assert_eq!(
            created.state,
            VpcRoutingProfileTransitionState::CutoverPendingFinalize
        );
        assert_eq!(created.version.version_nr(), 1);
        assert_eq!(
            created.source_routing_profile_overrides,
            input.source_routing_profile_overrides
        );
        assert_eq!(
            created.target_routing_profile_overrides,
            input.target_routing_profile_overrides
        );
        assert_eq!(created.target_requested_vni, Some(51_000));
        assert!(created.completed.is_none());

        assert_eq!(find(txn.as_mut(), id).await.unwrap(), Some(created.clone()));
        assert_eq!(
            find_active_by_vpc(txn.as_mut(), vpc_id).await.unwrap(),
            Some(created.clone())
        );
        assert_eq!(
            find_by_vpc(txn.as_mut(), vpc_id).await.unwrap(),
            vec![created.clone()]
        );
        assert_eq!(list(txn.as_mut()).await.unwrap(), vec![created]);

        txn.commit().await.unwrap();
    }

    #[crate::sqlx_test]
    async fn active_transition_is_unique_but_terminal_history_is_retained(pool: sqlx::PgPool) {
        let vpc_id = VpcId::new();
        let first_id = VpcRoutingProfileTransitionId::new();
        let second_id = VpcRoutingProfileTransitionId::new();
        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        create(&new_transition(first_id, vpc_id), txn.as_mut())
            .await
            .unwrap();

        let duplicate_error = create(&new_transition(second_id, vpc_id), txn.as_mut())
            .await
            .unwrap_err();
        assert!(matches!(
            duplicate_error,
            DatabaseError::FailedPrecondition(_)
        ));

        // PostgreSQL aborts a transaction after a uniqueness violation. Finish
        // the terminal-history portion in a fresh transaction.
        txn.rollback().await.unwrap();

        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let first = create(&new_transition(first_id, vpc_id), txn.as_mut())
            .await
            .unwrap();
        let finalized = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id: first.id,
                if_version_match: first.version,
                expected_state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                state: VpcRoutingProfileTransitionState::Finalized,
                cutover_vpc_version: None,
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap();
        assert!(finalized.completed.is_some());

        let second = create(&new_transition(second_id, vpc_id), txn.as_mut())
            .await
            .unwrap();
        assert_eq!(second.id, second_id);
        assert_eq!(find_by_vpc(txn.as_mut(), vpc_id).await.unwrap().len(), 2);

        txn.commit().await.unwrap();
    }

    #[crate::sqlx_test]
    async fn state_updates_support_rollback_recutover_finalize_and_occ(pool: sqlx::PgPool) {
        let vpc_id = VpcId::new();
        let id = VpcRoutingProfileTransitionId::new();
        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let created = create(&new_transition(id, vpc_id), txn.as_mut())
            .await
            .unwrap();

        let rollback_vpc_version = ConfigVersion::new(9);
        let rolled_back_pending = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: created.version,
                expected_state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                state: VpcRoutingProfileTransitionState::RollbackPendingFinalize,
                cutover_vpc_version: None,
                rollback_vpc_version: Some(rollback_vpc_version),
            },
            txn.as_mut(),
        )
        .await
        .unwrap();
        assert_eq!(rolled_back_pending.version.version_nr(), 2);
        assert_eq!(
            rolled_back_pending.rollback_vpc_version,
            Some(rollback_vpc_version)
        );
        assert!(rolled_back_pending.completed.is_none());

        let illegal_edge = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: rolled_back_pending.version,
                expected_state: VpcRoutingProfileTransitionState::RollbackPendingFinalize,
                state: VpcRoutingProfileTransitionState::Finalized,
                cutover_vpc_version: None,
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap_err();
        assert!(matches!(illegal_edge, DatabaseError::InvalidArgument(_)));

        let wrong_predecessor = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: rolled_back_pending.version,
                expected_state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                state: VpcRoutingProfileTransitionState::Finalized,
                cutover_vpc_version: None,
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            wrong_predecessor,
            DatabaseError::ConcurrentModificationError("VPC routing-profile transition", _)
        ));

        let stale_error = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: created.version,
                expected_state: VpcRoutingProfileTransitionState::RollbackPendingFinalize,
                state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                cutover_vpc_version: Some(ConfigVersion::new(10)),
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            stale_error,
            DatabaseError::ConcurrentModificationError("VPC routing-profile transition", _)
        ));

        let recutover_vpc_version = ConfigVersion::new(10);
        let recutover = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: rolled_back_pending.version,
                expected_state: VpcRoutingProfileTransitionState::RollbackPendingFinalize,
                state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                cutover_vpc_version: Some(recutover_vpc_version),
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap();
        assert_eq!(recutover.version.version_nr(), 3);
        assert_eq!(recutover.cutover_vpc_version, recutover_vpc_version);
        assert_eq!(recutover.rollback_vpc_version, Some(rollback_vpc_version));

        let finalized = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id,
                if_version_match: recutover.version,
                expected_state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                state: VpcRoutingProfileTransitionState::Finalized,
                cutover_vpc_version: None,
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await
        .unwrap();
        assert_eq!(finalized.version.version_nr(), 4);
        assert!(finalized.completed.is_some());
        assert!(
            find_active_by_vpc(txn.as_mut(), vpc_id)
                .await
                .unwrap()
                .is_none()
        );

        txn.commit().await.unwrap();
    }

    #[crate::sqlx_test]
    async fn database_checks_reject_inconsistent_transition_rows(pool: sqlx::PgPool) {
        let vpc_id = VpcId::new();
        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;

        let mut same_pool = new_transition(VpcRoutingProfileTransitionId::new(), vpc_id);
        same_pool.target_pool_name = same_pool.source_pool_name.clone();
        assert!(create(&same_pool, txn.as_mut()).await.is_err());
        txn.rollback().await.unwrap();

        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let mut same_vni = new_transition(VpcRoutingProfileTransitionId::new(), vpc_id);
        same_vni.target_vni = same_vni.source_vni;
        same_vni.target_requested_vni = Some(same_vni.source_vni);
        assert!(create(&same_vni, txn.as_mut()).await.is_err());
        txn.rollback().await.unwrap();

        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let created = create(
            &new_transition(VpcRoutingProfileTransitionId::new(), vpc_id),
            txn.as_mut(),
        )
        .await
        .unwrap();
        assert!(
            sqlx::query(
                "UPDATE vpc_routing_profile_transitions SET completed = now() WHERE id = $1"
            )
            .bind(created.id)
            .execute(txn.as_mut())
            .await
            .is_err()
        );
        txn.rollback().await.unwrap();

        let mut txn = pool.begin().await.unwrap();
        insert_vpc(vpc_id, txn.as_mut()).await;
        let created = create(
            &new_transition(VpcRoutingProfileTransitionId::new(), vpc_id),
            txn.as_mut(),
        )
        .await
        .unwrap();
        let missing_rollback_version = update_state(
            &UpdateVpcRoutingProfileTransitionState {
                id: created.id,
                if_version_match: created.version,
                expected_state: VpcRoutingProfileTransitionState::CutoverPendingFinalize,
                state: VpcRoutingProfileTransitionState::RollbackPendingFinalize,
                cutover_vpc_version: None,
                rollback_vpc_version: None,
            },
            txn.as_mut(),
        )
        .await;
        assert!(missing_rollback_version.is_err());
        txn.rollback().await.unwrap();
    }

    #[crate::sqlx_test]
    async fn transition_lock_is_held_until_transaction_end(pool: sqlx::PgPool) {
        let vpc_id = VpcId::new();
        let id = VpcRoutingProfileTransitionId::new();
        let mut setup = pool.begin().await.unwrap();
        insert_vpc(vpc_id, setup.as_mut()).await;
        create(&new_transition(id, vpc_id), setup.as_mut())
            .await
            .unwrap();
        setup.commit().await.unwrap();

        let mut owner = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM vpcs WHERE id = $1 FOR NO KEY UPDATE")
            .bind(vpc_id)
            .fetch_one(owner.as_mut())
            .await
            .unwrap();
        assert!(
            lock_by_id_after_vpc_lock(owner.as_mut(), id)
                .await
                .unwrap()
                .is_some()
        );

        let mut contender = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '50ms'")
            .execute(contender.as_mut())
            .await
            .unwrap();
        assert!(
            lock_by_id_after_vpc_lock(contender.as_mut(), id)
                .await
                .is_err()
        );

        contender.rollback().await.unwrap();
        owner.rollback().await.unwrap();
    }
}
