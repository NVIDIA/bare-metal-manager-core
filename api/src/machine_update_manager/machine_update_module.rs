use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use crate::{cfg::CarbideConfig, model::machine::machine_id::MachineId, CarbideResult};

/// Used by [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager) to initiate
/// machine updates.  A module is responsible for managing its own updates and accurately reporting
/// the number of outstanding updates.
///
/// NOTE: Updating machines are treated as managed hosts and identified by the host machine id.  DPU
/// updates are identified by using the host machine id, and the host/DPU pair should be treated as one.
#[async_trait]
pub trait MachineUpdateModule: Send + Sync + fmt::Display {
    fn new(config: Arc<CarbideConfig>, meter: opentelemetry::metrics::Meter) -> Option<Self>
    where
        Self: Sized;

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
