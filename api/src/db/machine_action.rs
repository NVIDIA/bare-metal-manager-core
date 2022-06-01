use crate::CarbideError;
use std::str::FromStr;

use rpc::v0 as rpc;

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
#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(type_name = "machine_action")]
#[sqlx(rename_all = "lowercase")]
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

impl From<&rpc::MachineStateMachineInput> for MachineAction {
    fn from(action: &rpc::MachineStateMachineInput) -> Self {
        match action {
            rpc::MachineStateMachineInput::Discover => MachineAction::Discover,
            rpc::MachineStateMachineInput::Adopt => MachineAction::Adopt,
            rpc::MachineStateMachineInput::Test => MachineAction::Test,
            rpc::MachineStateMachineInput::Commission => MachineAction::Commission,
            rpc::MachineStateMachineInput::Assign => MachineAction::Assign,
            rpc::MachineStateMachineInput::Fail => MachineAction::Fail,
            rpc::MachineStateMachineInput::Decommission => MachineAction::Decommission,
            rpc::MachineStateMachineInput::Recommission => MachineAction::Recommission,
            rpc::MachineStateMachineInput::Unassign => MachineAction::Unassign,
            rpc::MachineStateMachineInput::Release => MachineAction::Release,
        }
    }
}

impl From<&MachineAction> for rpc::MachineStateMachineInput {
    fn from(event: &MachineAction) -> Self {
        match event {
            MachineAction::Discover => rpc::MachineStateMachineInput::Discover,
            MachineAction::Adopt => rpc::MachineStateMachineInput::Adopt,
            MachineAction::Test => rpc::MachineStateMachineInput::Test,
            MachineAction::Commission => rpc::MachineStateMachineInput::Commission,
            MachineAction::Assign => rpc::MachineStateMachineInput::Assign,
            MachineAction::Fail => rpc::MachineStateMachineInput::Fail,
            MachineAction::Decommission => rpc::MachineStateMachineInput::Decommission,
            MachineAction::Recommission => rpc::MachineStateMachineInput::Recommission,
            MachineAction::Unassign => rpc::MachineStateMachineInput::Unassign,
            MachineAction::Release => rpc::MachineStateMachineInput::Release,
        }
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
