use crate::{CarbideError, CarbideResult};
use std::str::FromStr;

use sqlx::{postgres::PgRow, Postgres, Row};

use super::Machine;

use rpc::v0 as rpc;

use std::fmt::{Display, Formatter};

#[derive(sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "machine_state")]
#[derive(Debug, PartialEq)]
pub enum MachineState {
    Init,
    New,
    Adopted,
    Tested,
    Ready,
    Assigned,
    Broken,
    Decommissioned,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Init => "init",
                Self::New => "new",
                Self::Adopted => "adopted",
                Self::Tested => "tested",
                Self::Ready => "ready",
                Self::Assigned => "assigned",
                Self::Broken => "broken",
                Self::Decommissioned => "decommissioned",
            }
        )
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for MachineState {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        row.try_get("machine_state_machine")
    }
}

impl FromStr for MachineState {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "init" => Ok(Self::Init),
            "new" => Ok(Self::New),
            "adopted" => Ok(Self::Adopted),
            "tested" => Ok(Self::Tested),
            "ready" => Ok(Self::Ready),
            "assigned" => Ok(Self::Assigned),
            "broken" => Ok(Self::Broken),
            "decommissioned" => Ok(Self::Decommissioned),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field state: {}",
                x
            ))),
        }
    }
}

impl From<MachineState> for rpc::MachineState {
    fn from(machine_state: MachineState) -> rpc::MachineState {
        rpc::MachineState {
            state: machine_state.to_string(),
        }
    }
}

impl MachineState {
    pub async fn for_machine(
        machine: &Machine,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Self> {
        Ok(sqlx::query_as("SELECT machine_state_machine(action, version) OVER (PARTITION BY machine_id ORDER BY ID) FROM machine_events WHERE machine_id=$1::uuid;")
            .bind(&machine.id())
            .fetch_one(txn).await?)
    }
}
