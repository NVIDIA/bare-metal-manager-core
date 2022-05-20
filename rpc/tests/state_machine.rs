use rust_fsm::*;

#[test]
fn test_state_machine() {
    let mut machine: StateMachine<rpc::v0::MachineStateMachine> = StateMachine::new();
    let _ = machine
        .consume(&rpc::v0::MachineStateMachineInput::Discover)
        .unwrap();
    assert!(matches!(
        machine.state(),
        &rpc::v0::MachineStateMachineState::New
    ));
    machine
        .consume(&rpc::v0::MachineStateMachineInput::Adopt)
        .unwrap();

    let machine: StateMachine<rpc::v0::MachineStateMachine> =
        StateMachine::from_state(rpc::v0::MachineStateMachineState::Ready);
    assert!(matches!(
        machine.state(),
        &rpc::v0::MachineStateMachineState::Ready
    ));
}
