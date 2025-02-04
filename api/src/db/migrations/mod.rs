/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use sqlx::PgPool;

/// This is re-used for every unit test as well as the migrate function. Do not call `sqlx::migrate!`
/// from anywhere else in the codebase, as it causes the migrations to be dumped into the binary
/// multiple times.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

#[tracing::instrument(skip(pool))]
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}
