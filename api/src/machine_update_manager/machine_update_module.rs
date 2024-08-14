/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use crate::{model::machine::machine_id::MachineId, CarbideResult};

/// Used by [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager) to initiate
/// machine updates.  A module is responsible for managing its own updates and accurately reporting
/// the number of outstanding updates.
///
/// NOTE: Updating machines are treated as managed hosts and identified by the host machine id.  DPU
/// updates are identified by using the host machine id, and the host/DPU pair should be treated as one.
#[async_trait]
pub trait MachineUpdateModule: Send + Sync + fmt::Display {
    async fn get_updates_in_progress(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<HashSet<MachineId>>;

    async fn start_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
    ) -> CarbideResult<HashSet<MachineId>>;

    async fn clear_completed_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()>;

    async fn update_metrics(&self, txn: &mut Transaction<'_, Postgres>);
}

pub struct AutomaticFirmwareUpdateReference {
    pub from: String,
    pub to: String,
}

impl AutomaticFirmwareUpdateReference {
    pub const REF_NAME: &'static str = "AutomaticDpuFirmwareUpdate";
}

pub enum DpuReprovisionInitiator {
    Automatic(AutomaticFirmwareUpdateReference),
}

impl Display for DpuReprovisionInitiator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DpuReprovisionInitiator::Automatic(x) => write!(
                f,
                "{}/{}/{}",
                AutomaticFirmwareUpdateReference::REF_NAME,
                x.from,
                x.to
            ),
        }
    }
}
