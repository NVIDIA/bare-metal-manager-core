/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::db::DatabaseError;

use super::db;
use crate::state_controller::io::StateControllerIO;

/// Allows to request state handling for objects of a certain type
#[derive(Debug, Clone)]
pub struct Enqueuer<IO: StateControllerIO> {
    pool: sqlx::PgPool,
    _phantom_object: std::marker::PhantomData<IO::ObjectId>,
}

impl<IO: StateControllerIO> Enqueuer<IO> {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            _phantom_object: std::marker::PhantomData,
        }
    }

    /// Requests state handling for the given object
    pub async fn enqueue_object(&self, object_id: &IO::ObjectId) -> Result<bool, DatabaseError> {
        let mut conn = self.pool.acquire().await.map_err(DatabaseError::acquire)?;

        let num_enqueued = db::queue_objects(
            &mut conn,
            IO::DB_QUEUED_OBJECTS_TABLE_NAME,
            &[object_id.to_string()],
        )
        .await?;

        Ok(num_enqueued == 1)
    }
}
