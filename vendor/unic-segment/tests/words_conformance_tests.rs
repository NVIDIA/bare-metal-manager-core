// Copyright 2012-2015 The Rust Project Developers.
// Copyright 2017 The UNIC Project Developers.
//
// See the COPYRIGHT file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use unic_segment::{WordBoundIndices, WordBounds};

type TestData = &'static [(&'static str, &'static [&'static str])];

const TEST_DATA: TestData = include!("tables/word_break_test_data.rsv");

/// Extra cases that the official test suite doesn't cover.
const EXTRA_TEST_DATA: TestData = include!("extra_word_break_test_data.rsv");

#[test]
fn test_words_conformance() {
    let tests = TEST_DATA.iter().chain(EXTRA_TEST_DATA);

    for &(input, words) in tests {
        macro_rules! assert_ {
            ($test:expr, $exp:expr, $name:expr) => {
                // collect into vector for better diagnostics in failure case
                let testing = $test.collect::<Vec<_>>();
                let expected = $exp.collect::<Vec<_>>();
                assert_eq!(
                    testing, expected,
                    "{} test for testcase ({:?}, {:?}) failed.",
                    $name, input, words
                )
            };
        }

        // test forward word boundaries
        assert_!(
            WordBounds::new(input),
            words.iter().cloned(),
            "Forward word boundaries"
        );

        // test reverse word boundaries
        assert_!(
            WordBounds::new(input).rev(),
            words.iter().rev().cloned(),
            "Reverse word boundaries"
        );

        // generate offsets from word string lengths
        let mut indices = vec![0];
        for i in words.iter().cloned().map(|s| s.len()).scan(0, |t, n| {
            *t += n;
            Some(*t)
        }) {
            indices.push(i);
        }
        indices.pop();
        let indices = indices;

        // test forward indices iterator
        assert_!(
            WordBoundIndices::new(input).map(|(l, _)| l),
            indices.iter().cloned(),
            "Forward word indices"
        );

        // test backward indices iterator
        assert_!(
            WordBoundIndices::new(input).rev().map(|(l, _)| l),
            indices.iter().rev().cloned(),
            "Reverse word indices"
        );
    }
}
