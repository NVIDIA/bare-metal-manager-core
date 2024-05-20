/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use sqlx::{Pool, Postgres, Transaction};
use tonic::Status;

pub async fn begin_txn(db_conn: &Pool<Postgres>) -> Result<Transaction<'_, Postgres>, Status> {
    db_conn
        .begin()
        .await
        .map_err(|e| Status::internal(format!("failed to begin db txn: {}", e)))
}

pub async fn commit_txn(txn: Transaction<'_, Postgres>) -> Result<(), Status> {
    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("failed to begin db txn: {}", e)))
}
