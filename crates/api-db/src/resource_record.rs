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

use model::resource_record::ResourceRecord;
use sqlx::PgConnection;

use super::DatabaseError;

pub async fn find(
    txn: &mut PgConnection,
    query_name: &str,
) -> Result<Option<ResourceRecord>, DatabaseError> {
    let query =
        "SELECT resource_record from dns_records WHERE q_name=$1 AND family(resource_record) = 4";
    let result = sqlx::query_as::<_, ResourceRecord>(query)
        .bind(query_name)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(result)
}
