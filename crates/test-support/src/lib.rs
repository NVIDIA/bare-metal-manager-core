/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Tiny, zero-dependency helpers for making table-driven tests.
//!
//! Write a test as a list of labeled cases — each a `scenario`, an `input`, and an
//! `expect`ed result — then run them all through one operation, written once.
//! [`check_cases`] does the running and the asserting, [`Outcome`] is what a
//! fallible operation should produce, and [`Case`] is one row.
//!
//! # A table of cases
//!
//! ```
//! use nico_test_support::Outcome::*;
//! use nico_test_support::{Case, check_cases};
//!
//! check_cases(
//!     [
//!         Case {
//!             scenario: "valid",
//!             input: "42",
//!             expect: Yields(42),
//!         },
//!         Case {
//!             scenario: "not numeric",
//!             input: "x",
//!             expect: Fails,
//!         },
//!         Case {
//!             scenario: "out of range",
//!             input: "999",
//!             expect: FailsWith("bad byte: 999".to_string()),
//!         },
//!     ],
//!     // the operation under test, written once:
//!     |s| s.parse::<u8>().map_err(|_| format!("bad byte: {s}")),
//! );
//! ```
//!
//! # A single case
//!
//! A one-off test is just one [`Case`]; `.check(run)` is the single-row
//! counterpart to [`check_cases`]:
//!
//! ```
//! use nico_test_support::Case;
//! use nico_test_support::Outcome::*;
//!
//! Case {
//!     scenario: "in range",
//!     input: "42",
//!     expect: Yields(42),
//! }
//! .check(|s| s.parse::<u8>().map_err(|_| ()));
//! ```
//!
//! # What's shared, and what stays a convention
//!
//! [`Outcome`] is the one piece worth sharing — every fallible test otherwise
//! re-invents the same "succeeds / fails / fails-with-a-specific-error" enum. There
//! is deliberately no macro: that's a last-mile crystallization, not a starting
//! point. And when a row carries several inputs or expected values, a *local*
//! `struct Case` with content-named fields plus [`assert_outcome`] reads better
//! than forcing it through the generic [`Case`] here — so that stays a convention,
//! not a type.

use std::fmt::Debug;

/// The expected result of a fallible operation under test.
///
/// Pick the most specific variant that still says what you mean: [`Fails`] when
/// you only care *that* it errors, [`FailsWith`] when the exact error is part of
/// the contract.
///
/// [`Fails`]: Outcome::Fails
/// [`FailsWith`]: Outcome::FailsWith
#[derive(Debug)]
pub enum Outcome<T, E> {
    /// Succeeds, yielding this value.
    Yields(T),
    /// Fails — the specific error doesn't matter to this case.
    Fails,
    /// Fails with exactly this error.
    FailsWith(E),
}

/// One row of a table test: a labeled `input` and its expected [`Outcome`].
///
/// For rows with more than a single input (or several expected values), prefer a
/// *local* `struct Case` whose fields are named for their contents.
pub struct Case<I, T, E> {
    /// What this row exercises; used as the failure label.
    pub scenario: &'static str,
    /// The input handed to the operation under test.
    pub input: I,
    /// What the operation should produce.
    pub expect: Outcome<T, E>,
}

impl<I, T, E> Case<I, T, E> {
    /// Run this case's `input` through `run` and assert its [`Outcome`], naming a
    /// failure by `scenario`. The single-row counterpart to [`check_cases`] — for
    /// a test that is one labeled input and one expected result.
    pub fn check(self, run: impl FnOnce(I) -> Result<T, E>)
    where
        T: PartialEq + Debug,
        E: PartialEq + Debug,
    {
        assert_outcome(run(self.input), self.expect, self.scenario);
    }
}

/// Run each case's `input` through `run` and assert its [`Outcome`]. `run` is the
/// operation under test, written once.
pub fn check_cases<I, T, E>(
    cases: impl IntoIterator<Item = Case<I, T, E>>,
    run: impl Fn(I) -> Result<T, E>,
) where
    T: PartialEq + Debug,
    E: PartialEq + Debug,
{
    for case in cases {
        case.check(&run);
    }
}

/// Assert that `got` matches the expected [`Outcome`], attributing any mismatch to
/// `scenario`. This is the primitive [`Case::check`] and [`check_cases`] are built
/// on — reach for it directly when a case needs a hand-written body.
pub fn assert_outcome<T, E>(got: Result<T, E>, expect: Outcome<T, E>, scenario: &str)
where
    T: PartialEq + Debug,
    E: PartialEq + Debug,
{
    use Outcome::*;
    match (got, expect) {
        (Ok(got), Yields(want)) => assert_eq!(got, want, "{scenario}"),
        (Err(_), Fails) => {}
        (Err(got), FailsWith(want)) => assert_eq!(got, want, "{scenario}"),
        (got, expect) => panic!("{scenario}: got {got:?}, but expected {expect:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::Outcome::*;
    use super::{Case, assert_outcome, check_cases};

    #[test]
    fn check_runs_a_single_case() {
        Case {
            scenario: "doubles",
            input: 21u8,
            expect: Yields(42),
        }
        .check(|n| n.checked_mul(2).ok_or(()));
    }

    #[test]
    fn check_cases_runs_every_row() {
        check_cases(
            [
                Case {
                    scenario: "doubles",
                    input: 2u8,
                    expect: Yields(4),
                },
                Case {
                    scenario: "overflows",
                    input: 200u8,
                    expect: Fails,
                },
            ],
            |n| n.checked_mul(2).ok_or("overflow"),
        );
    }

    #[test]
    fn assert_outcome_matches_each_variant() {
        assert_outcome(Ok::<_, String>(7), Yields(7), "yields the value");
        assert_outcome(Err::<u8, _>("boom".to_string()), Fails, "fails, any error");
        assert_outcome(
            Err::<u8, _>("nope".to_string()),
            FailsWith("nope".to_string()),
            "fails with the exact error",
        );
    }

    #[test]
    #[should_panic(expected = "wanted a value")]
    fn flags_an_unexpected_error() {
        assert_outcome(Err::<u8, _>("x".to_string()), Yields(1), "wanted a value");
    }

    #[test]
    #[should_panic(expected = "wanted a failure")]
    fn flags_an_unexpected_success() {
        assert_outcome(Ok::<_, String>(1), Fails, "wanted a failure");
    }

    #[test]
    #[should_panic(expected = "wanted the other error")]
    fn flags_the_wrong_error() {
        assert_outcome(
            Err::<u8, _>("a".to_string()),
            FailsWith("b".to_string()),
            "wanted the other error",
        );
    }
}
