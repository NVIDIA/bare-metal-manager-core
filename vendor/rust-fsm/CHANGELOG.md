# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][keepachangelog], and this project
adheres to [Semantic Versioning][semver].

## [Unreleased]

## [0.6.0] - 2021-08-24
### Changed
* Updated to `1.x` versions of `syn` and `quote`.

## [0.5.0] - 2021-02-23
### Added
* The re-export of the DSL implementation is gated by the `dsl` feature which is
  enabled by default.
### Changed
* State transition error is now represented with `TransitionImpossibleError`
  instead of `()`.
* The library is not `no_std` by default due to the use of `std::error::Error`.
  Users should disable the new `std` feature to use this library in a `no_std`
  environment.

## [0.4.0] - 2020-08-25
### Added
* Allow deriving different traits for generated traits.
* Add the `from_state` method to start the machine from any given state.
* `no_std` support (thanks @luctius).
### Removed
* All default derives on generated enums.
* `Copy` constraint on `StateMachineImpl::State`.

## [0.3.0] - 2019-05-22
### Changed
* Re-organize repository to import a single crate instead of two.

## [0.2.0] - 2019-05-16
### Added
* Allow setting visibitility for generated state machine types by putting a
  visibility modifier before the state machine name.
* Allow to specify multiple transitions from the same state in a more compact
  form. See the example for the details.
### Changed
* More clear naming:
  * Renamed the `StateMachineWrapper` structure to `StateMachine`;
  * Renamed the `StateMachine` trait to `StateMachineImpl`.
### Removed
* Removed the `consume_anyway` function.

## [0.1.0] - 2019-04-29
### Added
* The `StateMachine` trait for formal definitions of state machines and
  transducers.
* The `StateMachineWrapper` struct - a convenience wrapper around `StateMachine`
  for practical usage.
* The first implementation of the DSL for defining state machines that allows
  to:
  * Define a state machine with its initial state;
  * Define state transitions;
  * Define outputs;
  * Generate boilerplates implementing `StateMachine`.

[keepachangelog]: https://keepachangelog.com/en/1.0.0/
[semver]: https://semver.org/spec/v2.0.0.html

[Unreleased]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.2.0...0.3.0
[0.2.0]: https://github.com/eugene-babichenko/rust-fsm/compare/v0.1.0...0.2.0
[0.1.0]: https://github.com/eugene-babichenko/rust-fsm/releases/tag/v0.1.0
