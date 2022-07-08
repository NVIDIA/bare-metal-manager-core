use ::rpc::{MachineStateMachine, MachineStateMachineInput, MachineStateMachineState};
use rust_fsm::*;

#[test]
fn test_state_machine() {
    let mut machine: StateMachine<MachineStateMachine> = StateMachine::new();
    let _ = machine
        .consume(&MachineStateMachineInput::Discover)
        .unwrap();
    assert!(matches!(machine.state(), &MachineStateMachineState::New));
    machine.consume(&MachineStateMachineInput::Adopt).unwrap();

    let machine: StateMachine<MachineStateMachine> =
        StateMachine::from_state(MachineStateMachineState::Ready);
    assert!(matches!(
        machine.state(),
        &rpc::MachineStateMachineState::Ready
    ));
}
