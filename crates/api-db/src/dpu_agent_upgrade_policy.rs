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
use model::machine::upgrade_policy::AgentUpgradePolicy;
use sqlx::{PgConnection, Row};

use crate::DatabaseError;

pub async fn get(txn: &mut PgConnection) -> Result<Option<AgentUpgradePolicy>, DatabaseError> {
    let query = "SELECT policy FROM dpu_agent_upgrade_policy ORDER BY created DESC LIMIT 1";
    let Some(row) = sqlx::query(query)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
    else {
        return Ok(None);
    };
    let str_policy: &str = row
        .try_get("policy")
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(Some(str_policy.into()))
}

pub async fn set(txn: &mut PgConnection, policy: AgentUpgradePolicy) -> Result<(), DatabaseError> {
    let query = "INSERT INTO dpu_agent_upgrade_policy VALUES ($1)";
    sqlx::query(query)
        .bind(policy.to_string())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
