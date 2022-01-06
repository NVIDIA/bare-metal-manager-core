// Copyright 2017 The UNIC Project Developers.
//
// See the COPYRIGHT file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use unic_ucd_segment::grapheme_cluster_break::GraphemeClusterBreak as GCB;
use unic_ucd_segment::sentence_break::SentenceBreak as SB;
use unic_ucd_segment::word_break::WordBreak as WB;

#[test]
fn test_grapheme_cluster_break_display() {
    assert_eq!(format!("{}", GCB::CR), "Carriage Return");
}

#[test]
fn test_word_break_display() {
    assert_eq!(format!("{}", SB::CR), "Carriage Return");
}

#[test]
fn test_sentence_break_display() {
    assert_eq!(format!("{}", WB::CR), "Carriage Return");
}
