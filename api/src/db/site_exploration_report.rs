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

use sqlx::{Postgres, Transaction};

use crate::{
    db::{explored_endpoints::DbExploredEndpoint, DatabaseError},
    model::site_explorer::SiteExplorationReport,
};

#[derive(Debug, Clone)]
pub struct DbSiteExplorationReport {}

impl DbSiteExplorationReport {
    pub async fn fetch(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<SiteExplorationReport, DatabaseError> {
        let endpoints = DbExploredEndpoint::find_all(txn).await?;
        Ok(SiteExplorationReport { endpoints })
    }
}
