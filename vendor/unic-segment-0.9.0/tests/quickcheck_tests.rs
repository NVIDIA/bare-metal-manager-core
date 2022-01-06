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

#[macro_use]
extern crate quickcheck;

use unic_segment::{Graphemes, WordBounds};

// QuickCheck Graphemes
quickcheck! {
    fn quickcheck_graphemes_new_join_vs_input(input: String) -> bool {
        let graphemes = Graphemes::new(&input).collect::<String>();
        graphemes == input
    }

    fn quickcheck_graphemes_new_forward_vs_reverse(input: String) -> bool {
        let graphemes1 = Graphemes::new(&input).collect::<Vec<_>>();
        let mut graphemes2 = Graphemes::new(&input).rev().collect::<Vec<_>>();
        graphemes2.reverse();
        graphemes1 == graphemes2
    }

    fn quickcheck_graphemes_new_legacy_join_vs_input(input: String) -> bool {
        let graphemes = Graphemes::new_legacy(&input).collect::<String>();
        graphemes == input
    }

    fn quickcheck_graphemes_new_legacy_forward_vs_reverse(input: String) -> bool {
        let graphemes1 = Graphemes::new_legacy(&input).collect::<Vec<_>>();
        let mut graphemes2 = Graphemes::new_legacy(&input).rev().collect::<Vec<_>>();
        graphemes2.reverse();
        graphemes1 == graphemes2
    }
}

// QuickCheck Words
quickcheck! {
    fn quickcheck_words_new_join_vs_input(input: String) -> bool {
        let words = WordBounds::new(&input).collect::<String>();
        words == input
    }

    fn quickcheck_words_new_forward_vs_reverse(input: String) -> bool {
        let words1 = WordBounds::new(&input).collect::<Vec<_>>();
        let mut words2 = WordBounds::new(&input).rev().collect::<Vec<_>>();
        words2.reverse();
        words1 == words2
    }
}
