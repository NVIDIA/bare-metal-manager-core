use std::fmt;

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use crate::CarbideResult;

/// Used by [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager) to initiate
/// machine updates.  A module is responsible for managing its own updates and accurately reporting
/// the number of outstanding updates.
#[async_trait]
pub trait MachineUpdateModule: Send + Sync + fmt::Display {
    async fn get_updates_in_progress_count(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<i32>;

    async fn start_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
    ) -> i32;

    async fn clear_completed_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()>;
}
