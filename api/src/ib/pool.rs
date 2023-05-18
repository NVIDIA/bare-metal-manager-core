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

use std::sync::Arc;

use crate::resource_pool::{self, DbResourcePool};

#[derive(Clone)]
pub struct IBData {
    pub pool_pkey: Arc<DbResourcePool<i16>>,
}

/// Create Infiniband's resource pools (for pkey, etc)
///
/// Pools must also be created in the database: `forge-admin-cli resource-pool define`
pub fn enable() -> IBData {
    let pool_pkey: Arc<DbResourcePool<i16>> =
        Arc::new(DbResourcePool::new(resource_pool::PKEY.to_string()));

    IBData { pool_pkey }
}
