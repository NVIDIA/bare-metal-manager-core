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

//! Site-level, one-time bootstrap flags (`site_state` table). The DB is
//! per-site, so each flag here is inherently site-scoped. Use these to gate
//! one-time application logic that the SQL schema migrator can't express -- e.g.
//! seeding/backfilling secrets in Vault -- so it runs at most once per site.
//!
//! Usage pattern (run-then-mark, so a crash/transient error retries on the next
//! startup; the gated work must therefore be idempotent):
//! ```ignore
//! if !site_state::per_device_uefi_backfill_applied(pool).await? {
//!     do_idempotent_backfill().await?;
//!     site_state::mark_per_device_uefi_backfill_applied(pool).await?;
//! }
//! ```

use sqlx::PgPool;

use crate::{DatabaseError, DatabaseResult};

/// Whether the one-time per-device UEFI secret backfill has run for this site.
pub async fn per_device_uefi_backfill_applied(pool: &PgPool) -> DatabaseResult<bool> {
    sqlx::query_scalar::<_, bool>("SELECT per_device_uefi_backfill_applied FROM site_state")
        .fetch_one(pool)
        .await
        .map_err(|e| DatabaseError::query("SELECT site_state.per_device_uefi_backfill_applied", e))
}

/// Records that the one-time per-device UEFI secret backfill has run for this site.
pub async fn mark_per_device_uefi_backfill_applied(pool: &PgPool) -> DatabaseResult<()> {
    sqlx::query("UPDATE site_state SET per_device_uefi_backfill_applied = TRUE")
        .execute(pool)
        .await
        .map_err(|e| {
            DatabaseError::query("UPDATE site_state.per_device_uefi_backfill_applied", e)
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[crate::sqlx_test]
    async fn flag_starts_false_then_marks_applied(pool: sqlx::PgPool) {
        assert!(
            !per_device_uefi_backfill_applied(&pool).await.unwrap(),
            "flag should default to false"
        );

        mark_per_device_uefi_backfill_applied(&pool).await.unwrap();
        assert!(
            per_device_uefi_backfill_applied(&pool).await.unwrap(),
            "flag should be true after marking applied"
        );

        // Marking again is a harmless no-op (stays true).
        mark_per_device_uefi_backfill_applied(&pool).await.unwrap();
        assert!(per_device_uefi_backfill_applied(&pool).await.unwrap());
    }
}
