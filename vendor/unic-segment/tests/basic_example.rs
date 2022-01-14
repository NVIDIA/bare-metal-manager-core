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

use unic_segment::{GraphemeIndices, Graphemes, WordBoundIndices, WordBounds, Words};
use unic_ucd_common::is_alphanumeric;

#[test]
fn test_all() {
    assert_eq!(
        Graphemes::new("a\u{310}e\u{301}o\u{308}\u{332}").collect::<Vec<&str>>(),
        &["a\u{310}", "e\u{301}", "o\u{308}\u{332}"]
    );

    assert_eq!(
        Graphemes::new("a\r\nb🇺🇳🇮🇨").collect::<Vec<&str>>(),
        &["a", "\r\n", "b", "🇺🇳", "🇮🇨"]
    );

    assert_eq!(
        GraphemeIndices::new("a̐éö̲\r\n").collect::<Vec<(usize, &str)>>(),
        &[(0, "a̐"), (3, "é"), (6, "ö̲"), (11, "\r\n")]
    );

    assert_eq!(
        Words::new(
            "The quick (\"brown\") fox can't jump 32.3 feet, right?",
            |s: &&str| s.chars().any(is_alphanumeric),
        )
        .collect::<Vec<&str>>(),
        &["The", "quick", "brown", "fox", "can't", "jump", "32.3", "feet", "right"]
    );

    assert_eq!(
        WordBounds::new("The quick (\"brown\")  fox").collect::<Vec<&str>>(),
        &["The", " ", "quick", " ", "(", "\"", "brown", "\"", ")", " ", " ", "fox"]
    );

    assert_eq!(
        WordBoundIndices::new("Brr, it's 29.3°F!").collect::<Vec<(usize, &str)>>(),
        &[
            (0, "Brr"),
            (3, ","),
            (4, " "),
            (5, "it's"),
            (9, " "),
            (10, "29.3"),
            (14, "°"),
            (16, "F"),
            (17, "!")
        ]
    );
}
