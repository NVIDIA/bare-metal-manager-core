use crate::CarbideError;
use postgres::types::{FromSql, ToSql, Type};
use postgres_types::{private::BytesMut, to_sql_checked, IsNull};
use std::str::FromStr;

/// Representing actions that can be performed on Machines.
///
/// Note that the operations that are valid for a given machine state are checked by the PostgreSQL
/// database schema, not in this software.  This is to prevent manupulating state to invalid states
/// when not using the API to enforce database consistency.
///
/// In order to add a new Action to a machine, a migration must be created that adds the new state
/// transition to the `machine_actions` table.  If the state transition is incompatible with an
/// existing state transition (e.g. a state transition is deleted) a new version of the state
/// machine must be created and the correct states and actions must be created.  This is to
/// maintain backward compatibility with the existing machines while supporting a new state machine
/// graph.
///
/// Unfortunately the Rust code doesn't distinguish between versions so having multiple state
/// machine versions with the same MachineAction enum.
///
#[derive(Debug, PartialEq)]
pub enum MachineAction {
    Discover,
    Adopt,
    Test,
    Commission,
    Assign,
    Fail,
    Decommission,
    Recommission,
    Unassign,
    Release,
}

/// Conversion for a MachineAction into it's PostgreSQL equivalent representation (a VARCHAR)
impl ToSql for MachineAction {
    fn to_sql(
        &self,
        ty: &Type,
        output: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Send + Sync>> {
        if ty.name() != "machine_action" {
            return Err(Box::new(CarbideError::DatabaseTypeConversionError(
                format!("Trying to serialize into unknown type: {}", ty.name()),
            )));
        }

        let f = match self {
            Self::Discover => "discover",
            Self::Adopt => "adopt",
            Self::Test => "test",
            Self::Commission => "commission",
            Self::Assign => "assign",
            Self::Fail => "fail",
            Self::Decommission => "decommission",
            Self::Recommission => "recommission",
            Self::Unassign => "unassign",
            Self::Release => "release",
        };

        output.extend_from_slice(f.as_bytes());

        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "machine_action"
    }

    to_sql_checked!();
}

impl FromStr for MachineAction {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "discover" => Ok(Self::Discover),
            "adopt" => Ok(Self::Adopt),
            "test" => Ok(Self::Test),
            "commission" => Ok(Self::Commission),
            "assign" => Ok(Self::Assign),
            "fail" => Ok(Self::Fail),
            "decommission" => Ok(Self::Decommission),
            "recommission" => Ok(Self::Recommission),
            "unassign" => Ok(Self::Unassign),
            "release" => Ok(Self::Release),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field action: {}",
                x
            ))),
        }
    }
}

impl FromSql<'_> for MachineAction {
    fn from_sql(
        db_type: &Type,
        raw: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match &*db_type.name() {
            "machine_action" => Ok(std::str::from_utf8(raw)?.parse()?),
            t => Err(Box::new(CarbideError::DatabaseTypeConversionError(
                format!("Could not convert type {0} into MachineAction", &t),
            ))),
        }
    }

    fn accepts(db_type: &Type) -> bool {
        db_type.name() == "machine_action"
    }
}

/// Conversion from a MachineAction instance into a protobuf representation for the same type.
impl From<MachineAction> for rpc::MachineAction {
    fn from(action: MachineAction) -> rpc::MachineAction {
        match action {
            MachineAction::Discover => rpc::MachineAction::Discover,
            MachineAction::Adopt => rpc::MachineAction::Adopt,
            MachineAction::Test => rpc::MachineAction::Test,
            MachineAction::Commission => rpc::MachineAction::Commission,
            MachineAction::Assign => rpc::MachineAction::Assign,
            MachineAction::Fail => rpc::MachineAction::Fail,
            MachineAction::Decommission => rpc::MachineAction::Decommission,
            MachineAction::Recommission => rpc::MachineAction::Recommission,
            MachineAction::Unassign => rpc::MachineAction::Unassign,
            MachineAction::Release => rpc::MachineAction::Release,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn machine_action() -> Type {
        Type::new(
            String::from("machine_action"),
            0,
            postgres::types::Kind::Simple,
            String::from("test"),
        )
    }

    #[rstest]
    #[case("adopt", MachineAction::Adopt)]
    #[case("test", MachineAction::Test)]
    #[case("commission", MachineAction::Commission)]
    #[case("assign", MachineAction::Assign)]
    #[case("fail", MachineAction::Fail)]
    #[case("decommission", MachineAction::Decommission)]
    #[case("recommission", MachineAction::Recommission)]
    #[case("unassign", MachineAction::Unassign)]
    #[case("release", MachineAction::Release)]
    fn test_sql_to_known_enum(#[case] input: &str, #[case] variant: MachineAction) {
        if let Ok(parsed) = MachineAction::from_sql(&Type::VARCHAR, input.as_bytes()) {
            assert_eq!(variant, parsed)
        }
    }

    #[test]
    fn test_sql_to_acceptable_type() {
        assert!(<MachineAction as FromSql>::accepts(&machine_action()))
    }

    #[test]
    fn test_sql_to_unknown_enum() {
        assert!(<MachineAction as FromSql>::from_sql(&Type::BOOL, &[0u8]).is_err())
    }

    #[test]
    fn null_not_ok() {
        assert!(MachineAction::from_sql_nullable(&Type::VARCHAR, None).is_err())
    }
}
