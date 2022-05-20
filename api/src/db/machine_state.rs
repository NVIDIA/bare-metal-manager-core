use crate::CarbideError;
use std::str::FromStr;

use sqlx::{postgres::PgRow, Row};

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
    Unknown,
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
                Self::Unknown => "unknown",
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

impl From<&rpc::MachineStateMachineState> for MachineState {
    fn from(state: &rpc::MachineStateMachineState) -> Self {
        match state {
            rpc::MachineStateMachineState::Init => MachineState::Init,
            rpc::MachineStateMachineState::New => MachineState::New,
            rpc::MachineStateMachineState::Adopted => MachineState::Adopted,
            rpc::MachineStateMachineState::Tested => MachineState::Tested,
            rpc::MachineStateMachineState::Ready => MachineState::Ready,
            rpc::MachineStateMachineState::Assigned => MachineState::Assigned,
            rpc::MachineStateMachineState::Broken => MachineState::Broken,
            rpc::MachineStateMachineState::Decommissioned => MachineState::Decommissioned,
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
