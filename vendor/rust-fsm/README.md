# A framework for building finite state machines in Rust

[![Documentation][docs-badge]][docs-link]
[![Latest Version][crate-badge]][crate-link]

The `rust-fsm` crate provides a simple and universal framework for building
state machines in Rust with minimum effort.

The essential part of this crate is the `StateMachineImpl` trait. This trait
allows a developer to provide a strict state machine definition, e.g.
specify its:

* An input alphabet - a set of entities that the state machine takes as
  inputs and performs state transitions based on them.
* Possible states - a set of states this machine could be in.
* An output alphabet - a set of entities that the state machine may output
  as results of its work.
* A transition function - a function that changes the state of the state
  machine based on its current state and the provided input.
* An output function - a function that outputs something from the output
  alphabet based on the current state and the provided inputs.
* The initial state of the machine.

Note that on the implementation level such abstraction allows build any type
of state machines:

* A classical state machine by providing only an input alphabet, a set of
  states and a transition function.
* A Mealy machine by providing all entities listed above.
* A Moore machine by providing an output function that do not depend on the
  provided inputs.

## Features

This library has the feature named `std` which is enabled by default. You
may want to import this library as
`rust-fsm = { version = "0.5", default-features = false, features = ["dsl"] }`
to use it in a `no_std` environment. This only affects error types (the `Error`
trait is only available in `std`).

The DSL implementation re-export is gated by the feature named `dsl` which is
also enabled by default.

## Use

Initially this library was designed to build an easy to use DSL for defining
state machines on top of it. Using the DSL will require to connect an
additional crate `rust-fsm-dsl` (this is due to limitation of the procedural
macros system). 

### Using the DSL for defining state machines

The DSL is parsed by the `state_machine` macro. Here is a little example.

```rust
use rust_fsm::*;

state_machine! {
    derive(Debug)
    CircuitBreaker(Closed)

    Closed(Unsuccessful) => Open [SetupTimer],
    Open(TimerTriggered) => HalfOpen,
    HalfOpen => {
        Successful => Closed,
        Unsuccessful => Open [SetupTimer],
    }
}
```

This code sample:

* Defines a state machine called `CircuitBreaker`;
* Derives the `Debug` trait for it (the `derive` section is optional);
* Sets the initial state of this state machine to `Closed`;
* Defines state transitions. For example: on receiving the `Successful`
  input when in the `HalfOpen` state, the machine must move to the `Closed`
  state;
* Defines outputs. For example: on receiving `Unsuccessful` in the
  `Closed` state, the machine must output `SetupTimer`.

This state machine can be used as follows:

```rust
// Initialize the state machine. The state is `Closed` now.
let mut machine: StateMachine<CircuitBreaker> = StateMachine::new();
// Consume the `Successful` input. No state transition is performed.
let _ = machine.consume(&CircuitBreakerInput::Successful);
// Consume the `Unsuccesful` input. The machine is moved to the `Open`
// state. The output is `SetupTimer`.
let output = machine.consume(&CircuitBreakerInput::Unsuccesful).unwrap();
// Check the output
if output == Some(CircuitBreakerOutput::SetupTimer) {
    // Set up the timer...
}
// Check the state
if machine.state() == &CircuitBreakerState::Open {
    // Do something...
}
```

As you can see, the following entities are generated:

* An empty structure `CircuitBreaker` that implements the `StateMachineImpl`
  trait.
* Enums `CircuitBreakerState`, `CircuitBreakerInput` and
  `CircuitBreakerOutput` that represent the state, the input alphabet and
  the output alphabet respectively.

Note that if there is no outputs in the specification, the output alphabet
is set to `()`. The set of states and the input alphabet must be non-empty
sets.

### Without DSL

The `state_machine` macro has limited capabilities (for example, a state
cannot carry any additional data), so in certain complex cases a user might
want to write a more complex state machine by hand.

All you need to do to build a state machine is to implement the
`StateMachineImpl` trait and use it in conjuctions with some of the provided
wrappers (for now there is only `StateMachine`).

You can see an example of the Circuit Breaker state machine in the
[project repository][repo].

[repo]: https://github.com/eugene-babichenko/rust-fsm/blob/master/tests/circuit_breaker.rs
[docs-badge]: https://docs.rs/rust-fsm/badge.svg
[docs-link]: https://docs.rs/rust-fsm
[crate-badge]: https://img.shields.io/crates/v/rust-fsm.svg
[crate-link]: https://crates.io/crates/rust-fsm
