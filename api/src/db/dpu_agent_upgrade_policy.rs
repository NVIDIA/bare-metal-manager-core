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

use sqlx::{Postgres, Row, Transaction};

use crate::db::DatabaseError;
use crate::model::machine::upgrade_policy::AgentUpgradePolicy;

pub struct DpuAgentUpgradePolicy {}
impl DpuAgentUpgradePolicy {
    pub async fn get(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<AgentUpgradePolicy>, DatabaseError> {
        let query = "SELECT policy FROM dpu_agent_upgrade_policy ORDER BY created DESC LIMIT 1";
        let Some(row) = sqlx::query(query)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        else {
            return Ok(None);
        };
        let str_policy: &str = row
            .try_get("policy")
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(Some(str_policy.into()))
    }

    pub async fn set(
        txn: &mut Transaction<'_, Postgres>,
        policy: AgentUpgradePolicy,
    ) -> Result<(), DatabaseError> {
        let query = "INSERT INTO dpu_agent_upgrade_policy VALUES ($1)";
        sqlx::query(query)
            .bind(policy.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}
