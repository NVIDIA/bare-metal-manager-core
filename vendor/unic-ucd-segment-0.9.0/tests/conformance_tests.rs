// Copyright 2017 The UNIC Project Developers.
//
// See the COPYRIGHT file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use unic_char_property::tables::CharDataTable;

use unic_ucd_segment::grapheme_cluster_break::{self, GraphemeClusterBreak};
use unic_ucd_segment::word_break::{self, WordBreak};

#[test]
fn test_grapheme_cluster_break_conformance() {
    use crate::grapheme_cluster_break::abbr_names::*;
    use crate::grapheme_cluster_break::long_names::*;

    const TEST_DATA: CharDataTable<GraphemeClusterBreak> =
        include!("tables/grapheme_cluster_break_test_data.rsv");

    for (ch, gcb) in TEST_DATA.iter() {
        assert_eq!(GraphemeClusterBreak::of(ch.low), gcb);
    }
}

#[test]
fn test_word_break_conformance() {
    use crate::word_break::abbr_names::*;
    use crate::word_break::long_names::*;
    // The test data file uses some unexpected names for some values
    use crate::word_break::long_names::{Extend as Extend_FE, Format as Format_FE, ZWJ as ZWJ_FE};

    const TEST_DATA: CharDataTable<WordBreak> = include!("tables/word_break_test_data.rsv");

    for (ch, gcb) in TEST_DATA.iter() {
        assert_eq!(WordBreak::of(ch.low), gcb);
    }
}
