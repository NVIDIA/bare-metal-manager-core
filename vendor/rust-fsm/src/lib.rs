//! A framework for building finite state machines in Rust
//!
//! The `rust-fsm` crate provides a simple and universal framework for building
//! state machines in Rust with minimum effort.
//!
//! The essential part of this crate is the
//! [`StateMachineImpl`](trait.StateMachineImpl.html) trait. This trait allows a
//! developer to provide a strict state machine definition, e.g. specify its:
//!
//! * An input alphabet - a set of entities that the state machine takes as
//!   inputs and performs state transitions based on them.
//! * Possible states - a set of states this machine could be in.
//! * An output alphabet - a set of entities that the state machine may output
//!   as results of its work.
//! * A transition function - a function that changes the state of the state
//!   machine based on its current state and the provided input.
//! * An output function - a function that outputs something from the output
//!   alphabet based on the current state and the provided inputs.
//! * The initial state of the machine.
//!
//! Note that on the implementation level such abstraction allows build any type
//! of state machines:
//!
//! * A classical state machine by providing only an input alphabet, a set of
//!   states and a transition function.
//! * A Mealy machine by providing all entities listed above.
//! * A Moore machine by providing an output function that do not depend on the
//!   provided inputs.
//!
//! # Usage in `no_std` environments
//!
//! This library has the feature named `std` which is enabled by default. You
//! may want to import this library as
//! `rust-fsm = { version = "0.5", default-features = false, features = ["dsl"] }`
//! to use it in a `no_std` environment. This only affects error types (the
//! `Error` trait is only available in `std`).
//!
//! The DSL implementation re-export is gated by the feature named `dsl` which
//! is also enabled by default.
//!
//! # Use
//!
//! Initially this library was designed to build an easy to use DSL for defining
//! state machines on top of it. Using the DSL will require to connect an
//! additional crate `rust-fsm-dsl` (this is due to limitation of the procedural
//! macros system).
//!
//! ## Using the DSL for defining state machines
//!
//! The DSL is parsed by the `state_machine` macro. Here is a little example.
//!
//! ```rust,ignore
//! use rust_fsm::*;
//!
//! state_machine! {
//!     derive(Debug)
//!     CircuitBreaker(Closed)
//!
//!     Closed(Unsuccessful) => Open [SetupTimer],
//!     Open(TimerTriggered) => HalfOpen,
//!     HalfOpen => {
//!         Successful => Closed,
//!         Unsuccessful => Open [SetupTimer]
//!     }
//! }
//! ```
//!
//! This code sample:
//!
//! * Defines a state machine called `CircuitBreaker`;
//! * Derives the `Debug` trait for it (the `derive` section is optional);
//! * Sets the initial state of this state machine to `Closed`;
//! * Defines state transitions. For example: on receiving the `Successful`
//!   input when in the `HalfOpen` state, the machine must move to the `Closed`
//!   state;
//! * Defines outputs. For example: on receiving `Unsuccessful` in the
//!   `Closed` state, the machine must output `SetupTimer`.
//!
//! This state machine can be used as follows:
//!
//! ```rust,ignore
//! // Initialize the state machine. The state is `Closed` now.
//! let mut machine: StateMachine<CircuitBreaker> = StateMachine::new();
//! // Consume the `Successful` input. No state transition is performed.
//! let _ = machine.consume(&CircuitBreakerInput::Successful);
//! // Consume the `Unsuccesful` input. The machine is moved to the `Open`
//! // state. The output is `SetupTimer`.
//! let output = machine.consume(&CircuitBreakerInput::Unsuccesful).unwrap();
//! // Check the output
//! if output == Some(CircuitBreakerOutput::SetupTimer) {
//!     // Set up the timer...
//! }
//! // Check the state
//! if machine.state() == &CircuitBreakerState::Open {
//!     // Do something...
//! }
//! ```
//!
//! As you can see, the following entities are generated:
//!
//! * An empty structure `CircuitBreaker` that implements the `StateMachineImpl`
//!   trait.
//! * Enums `CircuitBreakerState`, `CircuitBreakerInput` and
//!   `CircuitBreakerOutput` that represent the state, the input alphabet and
//!   the output alphabet respectively.
//!
//! Note that if there is no outputs in the specification, the output alphabet
//! is set to `()`. The set of states and the input alphabet must be non-empty
//! sets.
//!
//! ## Without DSL
//!
//! The `state_machine` macro has limited capabilities (for example, a state
//! cannot carry any additional data), so in certain complex cases a user might
//! want to write a more complex state machine by hand.
//!
//! All you need to do to build a state machine is to implement the
//! `StateMachineImpl` trait and use it in conjuctions with some of the provided
//! wrappers (for now there is only `StateMachine`).
//!
//! You can see an example of the Circuit Breaker state machine in the
//! [project repository][repo].
//!
//! [repo]: https://github.com/eugene-babichenko/rust-fsm/blob/master/tests/circuit_breaker.rs

#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "dsl")]
pub use rust_fsm_dsl::state_machine;

/// This trait is designed to describe any possible deterministic finite state
/// machine/transducer. This is just a formal definition that may be
/// inconvenient to be used in practical programming, but it is used throughout
/// this library for more practical things.
pub trait StateMachineImpl {
    /// The input alphabet.
    type Input;
    /// The set of possible states.
    type State;
    /// The output alphabet.
    type Output;
    /// The initial state of the machine.
    // allow since there is usually no interior mutability because states are enums
    #[allow(clippy::declare_interior_mutable_const)]
    const INITIAL_STATE: Self::State;
    /// The transition fuction that outputs a new state based on the current
    /// state and the provided input. Outputs `None` when there is no transition
    /// for a given combination of the input and the state.
    fn transition(state: &Self::State, input: &Self::Input) -> Option<Self::State>;
    /// The output function that outputs some value from the output alphabet
    /// based on the current state and the given input. Outputs `None` when
    /// there is no output for a given combination of the input and the state.
    fn output(state: &Self::State, input: &Self::Input) -> Option<Self::Output>;
}

/// A convenience wrapper around the `StateMachine` trait that encapsulates the
/// state and transition and output function calls.
pub struct StateMachine<T: StateMachineImpl> {
    state: T::State,
}

#[derive(Debug, Clone)]
/// An error type that represents that the state transition is impossible given
/// the current combination of state and input.
pub struct TransitionImpossibleError;

impl<T> StateMachine<T>
where
    T: StateMachineImpl,
{
    /// Create a new instance of this wrapper which encapsulates the initial
    /// state.
    pub fn new() -> Self {
        Self::from_state(T::INITIAL_STATE)
    }

    /// Create a new instance of this wrapper which encapsulates the given
    /// state.
    pub fn from_state(state: T::State) -> Self {
        Self { state }
    }

    /// Consumes the provided input, gives an output and performs a state
    /// transition. If a state transition with the current state and the
    /// provided input is not allowed, returns an error.
    pub fn consume(
        &mut self,
        input: &T::Input,
    ) -> Result<Option<T::Output>, TransitionImpossibleError> {
        if let Some(state) = T::transition(&self.state, input) {
            let output = T::output(&self.state, input);
            self.state = state;
            Ok(output)
        } else {
            Err(TransitionImpossibleError)
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> &T::State {
        &self.state
    }
}

impl<T> Default for StateMachine<T>
where
    T: StateMachineImpl,
{
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransitionImpossibleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "cannot perform a state transition from the current state with the provided input"
        )
    }
}

#[cfg(feature = "std")]
impl Error for TransitionImpossibleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
