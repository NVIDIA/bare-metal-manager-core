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
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};

static MIGRATION_LAYOUT: LazyLock<MigrationLayout> = LazyLock::new(|| {
    MigrationLayout::new(
        sqlx::migrate!("./migrations.pre-squash.20260708172302"),
        vec![MigrationEpoch::from_source(
            20260708172302,
            sqlx::migrate!("./migrations"),
        )],
    )
});

struct MigrationLayout {
    legacy: Migrator,
    epochs: Vec<MigrationEpoch>,
}

struct MigrationEpoch {
    squash: Migrator,
    post_squash: Migrator,
    squash_version: i64,
}

trait IgnoringMissing {
    fn ignoring_missing(self) -> Self;
}

impl IgnoringMissing for Migrator {
    fn ignoring_missing(mut self) -> Self {
        self.set_ignore_missing(true);
        self
    }
}

impl MigrationLayout {
    fn new(legacy: Migrator, epochs: Vec<MigrationEpoch>) -> Self {
        // Crash if these things aren't valid... proceeding anyway can cause us to skip migrations
        // we actually wanted, which is difficult to recover from.
        assert!(
            !epochs.is_empty(),
            "at least one migration epoch is required"
        );
        assert!(
            epochs
                .windows(2)
                .all(|epochs| epochs[0].squash_version < epochs[1].squash_version),
            "migration epochs must be ordered by squash version"
        );

        Self {
            legacy: legacy.ignoring_missing(),
            epochs,
        }
    }

    async fn run(
        &self,
        pool: &PgPool,
        mut applied_versions: HashSet<i64>,
    ) -> Result<(), MigrateError> {
        if applied_versions.is_empty() {
            // A fresh database starts at the newest snapshot and does not traverse older epochs.
            let current_epoch = self.epochs.last().expect("migration layout has no epochs");
            current_epoch.squash.run(pool).await?;
            return current_epoch.post_squash.run(pool).await;
        }

        let latest_applied_epoch = self
            .epochs
            .iter()
            .rposition(|epoch| applied_versions.contains(&epoch.squash_version));

        // A database with no squash marker predates the first snapshot. If a marker exists, that
        // snapshot already incorporates every earlier epoch, so resume from the newest marker.
        let first_epoch = if let Some(latest_applied_epoch) = latest_applied_epoch {
            latest_applied_epoch
        } else {
            self.legacy.run(pool).await?;
            0
        };

        for epoch in &self.epochs[first_epoch..] {
            if !applied_versions.contains(&epoch.squash_version) {
                // `squash` contains exactly one migration, so this cannot skip a raced migration
                // merely because its timestamp sorts before the squash timestamp.
                epoch.squash.skip(pool, None).await?;
                applied_versions.insert(epoch.squash_version);
            }

            epoch.post_squash.run(pool).await?;
        }

        Ok(())
    }

    fn expected_checksums(&self) -> HashMap<i64, Vec<u8>> {
        std::iter::once(&self.legacy)
            .chain(
                self.epochs
                    .iter()
                    .flat_map(|epoch| [&epoch.squash, &epoch.post_squash]),
            )
            .flat_map(|migrator| migrator.iter())
            .map(|migration| (migration.version, migration.checksum.to_vec()))
            .collect::<HashMap<i64, Vec<u8>>>()
    }
}

impl MigrationEpoch {
    fn from_source(squash_version: i64, source: Migrator) -> Self {
        // Select the squash by its exact identity, then treat every other file as post-squash. In
        // particular, do not infer membership from migration timestamps: a concurrently-developed
        // migration may have an earlier timestamp and must still run after the snapshot.
        let (squash, post_squash): (Vec<_>, Vec<_>) = source
            .iter()
            .cloned()
            .partition(|migration| migration.version == squash_version);
        assert_eq!(
            squash.len(),
            1,
            "expected exactly one squash migration with version {squash_version}"
        );

        Self {
            squash: Migrator::with_migrations(squash).ignoring_missing(),
            post_squash: Migrator::with_migrations(post_squash).ignoring_missing(),
            squash_version,
        }
    }
}

#[tracing::instrument(skip(pool))]
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    let applied = load_and_validate_history(pool, &MIGRATION_LAYOUT).await?;
    let applied_versions: HashSet<_> = applied.into_iter().map(|(version, _)| version).collect();
    MIGRATION_LAYOUT.run(pool, applied_versions).await
}

async fn load_and_validate_history(
    pool: &PgPool,
    layout: &MigrationLayout,
) -> Result<Vec<(i64, Vec<u8>)>, MigrateError> {
    let migrations_table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await?;

    if !migrations_table_exists {
        return Ok(Vec::new());
    }

    let applied: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    let expected = layout.expected_checksums();

    applied
        .into_iter()
        .map(|(version, checksum, success)| {
            if !success {
                return Err(MigrateError::Dirty(version));
            }

            let Some(expected_checksum) = expected.get(&version) else {
                return Err(MigrateError::VersionMissing(version));
            };

            if checksum != *expected_checksum {
                return Err(MigrateError::VersionMismatch(version));
            }

            Ok((version, checksum))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_are_ordered_and_point_to_their_squash_migration() {
        let mut previous = None;

        for epoch in &MIGRATION_LAYOUT.epochs {
            assert!(
                previous.is_none_or(|version| version < epoch.squash_version),
                "migration epochs must be ordered by squash version"
            );
            assert_eq!(epoch.squash.iter().count(), 1);
            assert!(epoch.squash.version_exists(epoch.squash_version));
            assert!(
                epoch
                    .post_squash
                    .iter()
                    .all(|migration| migration.version != epoch.squash_version)
            );
            previous = Some(epoch.squash_version);
        }
    }

    // Ensure that if we squash migrations in one PR while a new migration is added in another PR,
    // we still apply the latter migration when merged. Basically, ensure that we don't just sort
    // by version number and skip all the way up to the squashed migration.
    #[test]
    fn post_squash_migrations_are_selected_by_identity_not_timestamp() {
        let configured_epoch = MIGRATION_LAYOUT.epochs.first().unwrap();
        let squash_version = configured_epoch.squash_version;
        let squash = configured_epoch.squash.iter().next().unwrap().clone();
        let mut raced_migration = squash.clone();
        raced_migration.version = squash_version - 1;
        let source = Migrator::with_migrations(vec![raced_migration, squash]);

        let epoch = MigrationEpoch::from_source(squash_version, source);

        assert_eq!(epoch.squash.iter().count(), 1);
        assert_eq!(epoch.post_squash.iter().count(), 1);
        assert!(epoch.post_squash.version_exists(squash_version - 1));
    }

    #[crate::sqlx_test]
    async fn fully_migrated_legacy_database_skips_squash(pool: PgPool) {
        // The test template is built by the fresh-install path, so its schema already
        // contains every post-squash migration. Rewinding only the _sqlx_migrations
        // markers would leave those columns in place, and migrate() would fail
        // re-applying the post-squash migrations against them. Instead rebuild a
        // faithful pre-squash database: drop the schema and apply only the legacy
        // migrations, so both the schema and the recorded history match a database
        // that predates the snapshot.
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            .execute(&pool)
            .await
            .unwrap();

        MIGRATION_LAYOUT.legacy.run(&pool).await.unwrap();

        migrate(&pool).await.unwrap();

        let execution_time: i64 =
            sqlx::query_scalar("SELECT execution_time FROM _sqlx_migrations WHERE version = $1")
                .bind(MIGRATION_LAYOUT.epochs.first().unwrap().squash_version)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            execution_time, -1,
            "squash SQL must not run on legacy databases"
        );
    }
}
