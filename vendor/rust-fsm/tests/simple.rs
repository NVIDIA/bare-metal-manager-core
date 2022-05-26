use rust_fsm::*;

state_machine! {
    derive(Debug)
    Door(Open)

    Open(Key) => Closed,
    Closed(Key) => Open,
    Open(Break) => Broken,
    Closed(Break) => Broken,
}

#[test]
fn simple() {
    let mut machine: StateMachine<Door> = StateMachine::new();
    machine.consume(&DoorInput::Key).unwrap();
    println!("{:?}", machine.state());
    machine.consume(&DoorInput::Key).unwrap();
    println!("{:?}", machine.state());
    machine.consume(&DoorInput::Break).unwrap();
    println!("{:?}", machine.state());
}
