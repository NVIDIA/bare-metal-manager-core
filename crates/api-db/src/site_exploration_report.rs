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

use model::site_explorer::SiteExplorationReport;
use sqlx::PgConnection;

use crate::DatabaseError;

/// Fetches the latest site exploration report from the database
pub async fn fetch(txn: &mut PgConnection) -> Result<SiteExplorationReport, DatabaseError> {
    let endpoints = crate::explored_endpoints::find_all(txn).await?;
    let managed_hosts = crate::explored_managed_host::find_all(txn).await?;
    Ok(SiteExplorationReport {
        endpoints,
        managed_hosts,
    })
}
