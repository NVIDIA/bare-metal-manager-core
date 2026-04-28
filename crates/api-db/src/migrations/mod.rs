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
use sqlx::PgPool;

/// Timestamp prefix of the squash snapshot migration. When bumping this value,
/// you must also generate a new squash migration using `cargo run -p squash-migrations`
/// and delete all migrations older than the new squash. See `migrations/README.md`.
pub const LAST_SQUASH_VERSION: i64 = 20260411215700;

/// This is re-used for every unit test as well as the migrate function. Do not call `sqlx::migrate!`
/// from anywhere else in the codebase, as it causes the migrations to be dumped into the binary
/// multiple times.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

#[tracing::instrument(skip(pool))]
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    // On existing databases that had many individual migrations before the squash,
    // the _sqlx_migrations table still has rows for those old files. Since those
    // files no longer exist, sqlx would error ("migration not found"). Deleting the
    // stale rows lets the migrator see only the squash snapshot (which is idempotent)
    // and any migrations added after it.
    //
    // On fresh databases the table doesn't exist yet, so the DELETE harmlessly fails.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version < $1")
        .bind(LAST_SQUASH_VERSION)
        .execute(pool)
        .await
        .ok();

    MIGRATOR.run(pool).await
}
