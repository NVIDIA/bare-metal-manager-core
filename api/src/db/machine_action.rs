use std::str::FromStr;

use ::rpc::forge as rpc;
//use ::rpc::v0::MachineStateMachineInput;
use ::rpc::MachineStateMachineInput;

use crate::CarbideError;

/// Representing actions that can be performed on Machines.
///
/// Note that the operations that are valid for a given machine state are checked by the PostgreSQL
/// database schema, not in this software.  This is to prevent manipulating state to invalid states
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
#[derive(Debug, PartialEq, Eq, sqlx::Type)]
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
    Cleanup,
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
            "cleanup" => Ok(Self::Cleanup),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field action: {}",
                x
            ))),
        }
    }
}

impl From<&MachineStateMachineInput> for MachineAction {
    fn from(action: &MachineStateMachineInput) -> Self {
        match action {
            MachineStateMachineInput::Discover => MachineAction::Discover,
            MachineStateMachineInput::Adopt => MachineAction::Adopt,
            MachineStateMachineInput::Test => MachineAction::Test,
            MachineStateMachineInput::Commission => MachineAction::Commission,
            MachineStateMachineInput::Assign => MachineAction::Assign,
            MachineStateMachineInput::Fail => MachineAction::Fail,
            MachineStateMachineInput::Decommission => MachineAction::Decommission,
            MachineStateMachineInput::Recommission => MachineAction::Recommission,
            MachineStateMachineInput::Unassign => MachineAction::Unassign,
            MachineStateMachineInput::Release => MachineAction::Release,
            MachineStateMachineInput::Cleanup => MachineAction::Cleanup,
        }
    }
}

impl From<&MachineAction> for MachineStateMachineInput {
    fn from(event: &MachineAction) -> Self {
        match event {
            MachineAction::Discover => MachineStateMachineInput::Discover,
            MachineAction::Adopt => MachineStateMachineInput::Adopt,
            MachineAction::Test => MachineStateMachineInput::Test,
            MachineAction::Commission => MachineStateMachineInput::Commission,
            MachineAction::Assign => MachineStateMachineInput::Assign,
            MachineAction::Fail => MachineStateMachineInput::Fail,
            MachineAction::Decommission => MachineStateMachineInput::Decommission,
            MachineAction::Recommission => MachineStateMachineInput::Recommission,
            MachineAction::Unassign => MachineStateMachineInput::Unassign,
            MachineAction::Release => MachineStateMachineInput::Release,
            MachineAction::Cleanup => MachineStateMachineInput::Cleanup,
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
            MachineAction::Cleanup => rpc::MachineAction::Cleanup,
        }
    }
}
