use postgres::types::{FromSql, Type};

use crate::{CarbideError, CarbideResult};
use std::str::FromStr;

use super::Machine;

use rpc::v0 as rpc;

use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq)]
pub enum MachineState {
    Init = 0,
    New = 1,
    Adopted = 2,
    Tested = 3,
    Ready = 4,
    Assigned = 5,
    Broken = 6,
    Decommissioned = 7,
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

impl FromSql<'_> for MachineState {
    fn from_sql(
        db_type: &Type,
        raw: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match &*db_type.name() {
            "machine_state" => Ok(std::str::from_utf8(raw)?.parse()?),
            t => Err(Box::new(CarbideError::DatabaseTypeConversionError(
                format!("Could not convert type {0} into MachineState", &t),
            ))),
        }
    }

    fn accepts(db_type: &Type) -> bool {
        db_type.name() == "machine_state"
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

impl From<tokio_postgres::Row> for MachineState {
    fn from(row: tokio_postgres::Row) -> Self {
        row.get("machine_state_machine")
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
        dbc: &tokio_postgres::Transaction<'_>,
    ) -> CarbideResult<Self> {
        let row = dbc.query_one(
                "SELECT machine_state_machine(action, version) OVER (PARTITION BY machine_id ORDER BY ID) FROM machine_events WHERE machine_id=$1::uuid;",
                &[&machine.id()],
            ).await?;

        Ok(MachineState::from(row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn machine_state() -> Type {
        Type::new(
            String::from("machine_state"),
            0,
            postgres::types::Kind::Simple,
            String::from("test"),
        )
    }

    #[rstest]
    #[case("init", MachineState::Init)]
    #[case("new", MachineState::New)]
    #[case("adopted", MachineState::Adopted)]
    #[case("tested", MachineState::Tested)]
    #[case("ready", MachineState::Ready)]
    #[case("assigned", MachineState::Assigned)]
    #[case("broken", MachineState::Broken)]
    #[case("decommissioned", MachineState::Decommissioned)]
    fn test_sql_to_known_enum(#[case] input: &str, #[case] variant: MachineState) {
        if let Ok(parsed) = MachineState::from_sql(&machine_state(), input.as_bytes()) {
            assert_eq!(variant, parsed)
        }
    }

    #[test]
    fn test_sql_to_acceptable_type() {
        assert!(MachineState::accepts(&machine_state()))
    }

    #[test]
    fn test_sql_to_unknown_enum() {
        assert!(MachineState::from_sql(&Type::BOOL, &[0u8]).is_err())
    }

    #[test]
    fn null_not_ok() {
        assert!(MachineState::from_sql_nullable(&Type::VARCHAR, None).is_err())
    }
}
