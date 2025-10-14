/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use sqlx::PgConnection;

use crate::DatabaseError;

pub async fn trim_table(
    txn: &mut PgConnection,
    target: rpc::forge::TrimTableTarget,
    keep_entries: u32,
) -> Result<i32, DatabaseError> {
    // choose a target and call an appropriate stored procedure/function
    match target {
        rpc::forge::TrimTableTarget::MeasuredBoot => {
            let query = "SELECT * FROM measured_boot_reports_keep_limit($1)";

            let val: (i32,) = sqlx::query_as(query)
                .bind(keep_entries as i32)
                .fetch_one(txn)
                .await
                .map_err(|e| DatabaseError::new(query, e))?;
            Ok(val.0)
        }
    }
}
