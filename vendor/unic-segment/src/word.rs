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

//! Unicode Words of a string.
//!
//! ## References
//!
//! * <https://www.unicode.org/reports/tr29/#Word_Boundaries>

use std::cmp;
use std::iter::Filter;

use unic_ucd_segment::WordBreak as WB;

/// An iterator over the substrings of a string which, after splitting the string on [word
/// boundaries](https://www.unicode.org/reports/tr29/#Word_Boundaries), contain any characters with
/// the [Alphabetic](http://unicode.org/reports/tr44/#Alphabetic) property, or with
/// [`General_Category=Number`](http://unicode.org/reports/tr44/#General_Category_Values).
#[derive(Debug)]
pub struct Words<'a> {
    inner: Filter<WordBounds<'a>, fn(&&str) -> bool>,
}

impl<'a> Iterator for Words<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        self.inner.next()
    }
}

impl<'a> DoubleEndedIterator for Words<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<&'a str> {
        self.inner.next_back()
    }
}

impl<'a> Words<'a> {
    /// Create new iterator for *words*.
    #[inline]
    pub fn new(s: &str, filter: fn(&&str) -> bool) -> Words<'_> {
        Words {
            inner: WordBounds::new(s).filter(filter),
        }
    }
}

/// External iterator for a string's
/// [word boundaries](https://www.unicode.org/reports/tr29/#Word_Boundaries).
#[derive(Clone, Debug)]
pub struct WordBounds<'a> {
    string: &'a str,
    cat: Option<WB>,
    catb: Option<WB>,
}

/// External iterator for word boundaries and byte offsets.
#[derive(Clone, Debug)]
pub struct WordBoundIndices<'a> {
    start_offset: usize,
    iter: WordBounds<'a>,
}

impl<'a> WordBoundIndices<'a> {
    /// Create new iterator for *word boundries and their indices*.
    #[inline]
    pub fn new(s: &str) -> WordBoundIndices<'_> {
        WordBoundIndices {
            start_offset: s.as_ptr() as usize,
            iter: WordBounds::new(s),
        }
    }

    #[inline]
    /// View the underlying data (the part yet to be iterated) as a slice of the original string.
    ///
    /// ```rust
    /// # use unic_segment::WordBoundIndices;
    /// let mut iter = WordBoundIndices::new("Hello world");
    /// assert_eq!(iter.as_str(), "Hello world");
    ///
    /// iter.next();
    /// assert_eq!(iter.as_str(), " world");
    ///
    /// iter.next();
    /// assert_eq!(iter.as_str(), "world");
    /// ```
    pub fn as_str(&self) -> &'a str {
        self.iter.as_str()
    }
}

impl<'a> Iterator for WordBoundIndices<'a> {
    type Item = (usize, &'a str);

    #[inline]
    fn next(&mut self) -> Option<(usize, &'a str)> {
        self.iter
            .next()
            .map(|s| (s.as_ptr() as usize - self.start_offset, s))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> DoubleEndedIterator for WordBoundIndices<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<(usize, &'a str)> {
        self.iter
            .next_back()
            .map(|s| (s.as_ptr() as usize - self.start_offset, s))
    }
}

// state machine for word boundary rules
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WordBoundsState {
    Start,
    Letter,
    HLetter,
    Numeric,
    Katakana,
    ExtendNumLet,
    Regional(RegionalState),
    FormatExtend(FormatExtendType),
    Zwj,
    Emoji,
}

// subtypes for FormatExtend state in WordBoundsState
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FormatExtendType {
    AcceptAny,
    AcceptNone,
    RequireLetter,
    RequireHLetter,
    AcceptQLetter,
    RequireNumeric,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegionalState {
    Half,
    Full,
    Unknown,
}

impl<'a> Iterator for WordBounds<'a> {
    type Item = &'a str;

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let slen = self.string.len();
        (cmp::min(slen, 1), Some(slen))
    }

    #[inline]
    #[cfg_attr(feature = "cargo-clippy", allow(match_same_arms))]
    fn next(&mut self) -> Option<&'a str> {
        use self::FormatExtendType::*;
        use self::WordBoundsState::*;

        if self.string.is_empty() {
            return None;
        }

        let mut take_curr = true;
        let mut take_cat = true;
        let mut idx = 0;
        let mut saveidx = 0;
        let mut state = Start;
        let mut cat = WB::Other;
        let mut savecat = WB::Other;

        // Whether or not the previous category was ZWJ
        // ZWJs get collapsed, so this handles precedence of WB3c over WB4
        let mut prev_zwj;
        for (curr, ch) in self.string.char_indices() {
            idx = curr;
            prev_zwj = cat == WB::ZWJ;
            // if there's a category cached, grab it
            cat = match self.cat {
                None => WB::of(ch),
                _ => self.cat.take().unwrap(),
            };
            take_cat = true;

            // handle rule WB4
            // just skip all format, extend, and zwj chars
            // note that Start is a special case: if there's a bunch of Format | Extend
            // characters at the beginning of a block of text, dump them out as one unit.
            //
            // (This is not obvious from the wording of UAX#29, but if you look at the
            // test cases https://www.unicode.org/Public/UNIDATA/auxiliary/WordBreakTest.txt
            // then the "correct" interpretation of WB4 becomes apparent.)
            if state != Start {
                match cat {
                    WB::Extend | WB::Format | WB::ZWJ => continue,
                    _ => {}
                }
            }

            // rule WB3c
            // WB4 makes all ZWJs collapse into the previous state
            // but you can still be in a Zwj state if you started with Zwj
            //
            // This means that Zwj + Extend will collapse into Zwj, which is wrong,
            // since Extend has a boundary with following EBG/GAZ chars but ZWJ doesn't,
            // and that rule (WB3c) has higher priority
            //
            // Additionally, Emoji_Base+ZWJ+(EBG/GAZ) will collapse into Emoji_Base+EBG/GAZ
            // which won't have a boundary even though EB+ZWJ+GAZ should have a boundary.
            //
            // Thus, we separately keep track of whether or not the last character
            // was a ZWJ. This is an additional bit of state tracked outside of the
            // state enum; the state enum represents the last non-zwj state encountered.
            // When prev_zwj is true, for the purposes of WB3c, we are in the Zwj state,
            // however we are in the previous state for the purposes of all other rules.
            if prev_zwj {
                match cat {
                    WB::GlueAfterZwj => continue,
                    WB::EBaseGAZ => {
                        state = Emoji;
                        continue;
                    }
                    _ => (),
                }
            }
            // Don't use `continue` in this match without updating `cat`
            state = match state {
                Start if cat == WB::CR => {
                    idx += match self.get_next_cat(idx) {
                        Some(ncat) if ncat == WB::LF => 1, // rule WB3
                        _ => 0,
                    };
                    break; // rule WB3a
                }
                Start => match cat {
                    WB::ALetter => Letter,            // rule WB5, WB6, WB9, WB13a
                    WB::HebrewLetter => HLetter,      // rule WB5, WB6, WB7a, WB7b, WB9, WB13a
                    WB::Numeric => Numeric,           // rule WB8, WB10, WB12, WB13a
                    WB::Katakana => Katakana,         // rule WB13, WB13a
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a, WB13b
                    WB::RegionalIndicator => Regional(RegionalState::Half), // rule WB13c
                    WB::LF | WB::Newline => break,    // rule WB3a
                    WB::ZWJ => Zwj,                   // rule WB3c
                    WB::EBase | WB::EBaseGAZ => Emoji, // rule WB14
                    _ => {
                        if let Some(ncat) = self.get_next_cat(idx) {
                            // rule WB4
                            if ncat == WB::Format || ncat == WB::Extend || ncat == WB::ZWJ {
                                state = FormatExtend(AcceptNone);
                                self.cat = Some(ncat);
                                continue;
                            }
                        }
                        break; // rule WB999
                    }
                },
                Zwj => {
                    // We already handle WB3c above. At this point,
                    // the current category is not GAZ or EBG,
                    // or the previous character was not actually a ZWJ
                    take_curr = false;
                    break;
                }
                Letter | HLetter => match cat {
                    WB::ALetter => Letter,            // rule WB5
                    WB::HebrewLetter => HLetter,      // rule WB5
                    WB::Numeric => Numeric,           // rule WB9
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    WB::DoubleQuote if state == HLetter => {
                        savecat = cat;
                        saveidx = idx;
                        FormatExtend(RequireHLetter) // rule WB7b
                    }
                    WB::SingleQuote if state == HLetter => {
                        FormatExtend(AcceptQLetter) // rule WB7a
                    }
                    WB::MidLetter | WB::MidNumLet | WB::SingleQuote => {
                        savecat = cat;
                        saveidx = idx;
                        FormatExtend(RequireLetter) // rule WB6
                    }
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Numeric => match cat {
                    WB::Numeric => Numeric,           // rule WB8
                    WB::ALetter => Letter,            // rule WB10
                    WB::HebrewLetter => HLetter,      // rule WB10
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    WB::MidNum | WB::MidNumLet | WB::SingleQuote => {
                        savecat = cat;
                        saveidx = idx;
                        FormatExtend(RequireNumeric) // rule WB12
                    }
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Katakana => match cat {
                    WB::Katakana => Katakana,         // rule WB13
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                ExtendNumLet => match cat {
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    WB::ALetter => Letter,            // rule WB13b
                    WB::HebrewLetter => HLetter,      // rule WB13b
                    WB::Numeric => Numeric,           // rule WB13b
                    WB::Katakana => Katakana,         // rule WB13b
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Regional(RegionalState::Full) => {
                    // if it reaches here we've gone too far,
                    // a full flag can only compose with ZWJ/Extend/Format
                    // proceeding it.
                    take_curr = false;
                    break;
                }
                Regional(RegionalState::Half) => match cat {
                    WB::RegionalIndicator => Regional(RegionalState::Full), // rule WB13c
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Regional(_) => {
                    unreachable!("RegionalState::Unknown should not occur on forward iteration")
                }
                Emoji => match cat {
                    // rule WB14
                    WB::EModifier => state,
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                FormatExtend(t) => match t {
                    // handle FormatExtends depending on what type
                    RequireNumeric if cat == WB::Numeric => Numeric, // rule WB11
                    RequireLetter | AcceptQLetter if cat == WB::ALetter => Letter, // rule WB7
                    RequireLetter | AcceptQLetter if cat == WB::HebrewLetter => HLetter, // WB7a
                    RequireHLetter if cat == WB::HebrewLetter => HLetter, // rule WB7b
                    AcceptNone | AcceptQLetter => {
                        take_curr = false; // emit all the Format|Extend characters
                        take_cat = false;
                        break;
                    }
                    _ => break, // rewind (in if statement below)
                },
            }
        }

        if let FormatExtend(t) = state {
            // we were looking for something and didn't find it; we have to back up
            if t == RequireLetter || t == RequireHLetter || t == RequireNumeric {
                idx = saveidx;
                cat = savecat;
                take_curr = false;
            }
        }

        self.cat = if take_curr {
            idx += self.string[idx..].chars().next().unwrap().len_utf8();
            None
        } else if take_cat {
            Some(cat)
        } else {
            None
        };

        let retstr = &self.string[..idx];
        self.string = &self.string[idx..];
        Some(retstr)
    }
}

impl<'a> DoubleEndedIterator for WordBounds<'a> {
    #[inline]
    #[cfg_attr(feature = "cargo-clippy", allow(cyclomatic_complexity))]
    fn next_back(&mut self) -> Option<&'a str> {
        use self::FormatExtendType::*;
        use self::WordBoundsState::*;
        if self.string.is_empty() {
            return None;
        }

        let mut take_curr = true;
        let mut take_cat = true;
        let mut idx = self.string.len();
        idx -= self.string.chars().next_back().unwrap().len_utf8();
        let mut previdx = idx;
        let mut saveidx = idx;
        let mut state = Start;
        let mut savestate = Start;
        let mut cat = WB::Other;

        for (curr, ch) in self.string.char_indices().rev() {
            previdx = idx;
            idx = curr;

            // if there's a category cached, grab it
            cat = match self.catb {
                None => WB::of(ch),
                _ => self.catb.take().unwrap(),
            };
            take_cat = true;

            // backward iterator over word boundaries. Mostly the same as the forward
            // iterator, with two weirdnesses:
            // (1) If we encounter a single quote in the Start state, we have to check for a
            //     Hebrew Letter immediately before it.
            // (2) Format and Extend char handling takes some gymnastics.

            if cat == WB::Extend || cat == WB::Format || (cat == WB::ZWJ && state != Zwj) {
                // WB3c has more priority so we should not
                // fold in that case
                if match state {
                    FormatExtend(_) | Start => false,
                    _ => true,
                } {
                    saveidx = previdx;
                    savestate = state;
                    state = FormatExtend(AcceptNone);
                }

                if state != Start {
                    continue;
                }
            } else if state == FormatExtend(AcceptNone) {
                // finished a scan of some Format|Extend chars, restore previous state
                state = savestate;
                previdx = saveidx;
                take_cat = false;
            }

            // Don't use `continue` in this match without updating `catb`
            state = match state {
                Start | FormatExtend(AcceptAny) => match cat {
                    WB::ALetter => Letter,            // rule WB5, WB7, WB10, WB13b
                    WB::HebrewLetter => HLetter,      // rule WB5, WB7, WB7c, WB10, WB13b
                    WB::Numeric => Numeric,           // rule WB8, WB9, WB11, WB13b
                    WB::Katakana => Katakana,         // rule WB13, WB13b
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    WB::RegionalIndicator => Regional(RegionalState::Unknown), // rule WB13c
                    WB::GlueAfterZwj | WB::EBaseGAZ => Zwj, // rule WB3c
                    // rule WB4:
                    WB::Extend | WB::Format | WB::ZWJ => FormatExtend(AcceptAny),
                    WB::SingleQuote => {
                        saveidx = idx;
                        FormatExtend(AcceptQLetter) // rule WB7a
                    }
                    WB::EModifier => Emoji, // rule WB14
                    WB::CR | WB::LF | WB::Newline => {
                        if state == Start {
                            if cat == WB::LF {
                                idx -= match self.get_prev_cat(idx) {
                                    Some(pcat) if pcat == WB::CR => 1, // rule WB3
                                    _ => 0,
                                };
                            }
                        } else {
                            take_curr = false;
                        }
                        break; // rule WB3a
                    }
                    _ => break, // rule WB999
                },
                Zwj => match cat {
                    // rule WB3c
                    WB::ZWJ => FormatExtend(AcceptAny),
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Letter | HLetter => match cat {
                    WB::ALetter => Letter,            // rule WB5
                    WB::HebrewLetter => HLetter,      // rule WB5
                    WB::Numeric => Numeric,           // rule WB10
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13b
                    WB::DoubleQuote if state == HLetter => {
                        saveidx = previdx;
                        FormatExtend(RequireHLetter) // rule WB7c
                    }
                    WB::MidLetter | WB::MidNumLet | WB::SingleQuote => {
                        saveidx = previdx;
                        FormatExtend(RequireLetter) // rule WB7
                    }
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Numeric => match cat {
                    WB::Numeric => Numeric,           // rule WB8
                    WB::ALetter => Letter,            // rule WB9
                    WB::HebrewLetter => HLetter,      // rule WB9
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13b
                    WB::MidNum | WB::MidNumLet | WB::SingleQuote => {
                        saveidx = previdx;
                        FormatExtend(RequireNumeric) // rule WB11
                    }
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Katakana => match cat {
                    WB::Katakana => Katakana,         // rule WB13
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13b
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                ExtendNumLet => match cat {
                    WB::ExtendNumLet => ExtendNumLet, // rule WB13a
                    WB::ALetter => Letter,            // rule WB13a
                    WB::HebrewLetter => HLetter,      // rule WB13a
                    WB::Numeric => Numeric,           // rule WB13a
                    WB::Katakana => Katakana,         // rule WB13a
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Regional(mut regional_state) => match cat {
                    // rule WB13c
                    WB::RegionalIndicator => {
                        if regional_state == RegionalState::Unknown {
                            let count = self.string[..previdx]
                                .chars()
                                .rev()
                                .map(WB::of)
                                .filter(|&c| !(c == WB::ZWJ || c == WB::Extend || c == WB::Format))
                                .take_while(|&c| c == WB::RegionalIndicator)
                                .count();
                            regional_state = if count % 2 == 0 {
                                RegionalState::Full
                            } else {
                                RegionalState::Half
                            };
                        }
                        if regional_state == RegionalState::Full {
                            take_curr = false;
                            break;
                        } else {
                            Regional(RegionalState::Full)
                        }
                    }
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                Emoji => match cat {
                    // rule WB14
                    WB::EBase | WB::EBaseGAZ => Zwj,
                    _ => {
                        take_curr = false;
                        break;
                    }
                },
                FormatExtend(t) => match t {
                    RequireNumeric if cat == WB::Numeric => Numeric, // rule WB12
                    RequireLetter if cat == WB::ALetter => Letter,   // rule WB6
                    RequireLetter if cat == WB::HebrewLetter => HLetter, // rule WB6
                    AcceptQLetter if cat == WB::HebrewLetter => HLetter, // rule WB7a
                    RequireHLetter if cat == WB::HebrewLetter => HLetter, // rule WB7b
                    _ => break,                                      // backtrack will happens
                },
            }
        }

        if let FormatExtend(t) = state {
            // if we required something but didn't find it, backtrack
            if t == RequireLetter
                || t == RequireHLetter
                || t == RequireNumeric
                || t == AcceptNone
                || t == AcceptQLetter
            {
                previdx = saveidx;
                take_cat = false;
                take_curr = false;
            }
        }

        self.catb = if take_curr {
            None
        } else {
            idx = previdx;
            if take_cat {
                Some(cat)
            } else {
                None
            }
        };

        let retstr = &self.string[idx..];
        self.string = &self.string[..idx];
        Some(retstr)
    }
}

impl<'a> WordBounds<'a> {
    /// Create new iterator for *word boundries*.
    #[inline]
    pub fn new(s: &str) -> WordBounds<'_> {
        WordBounds {
            string: s,
            cat: None,
            catb: None,
        }
    }

    #[inline]
    /// View the underlying data (the part yet to be iterated) as a slice of the original string.
    ///
    /// ```rust
    /// # use unic_segment::WordBounds;
    /// let mut iter = WordBounds::new("Hello world");
    /// assert_eq!(iter.as_str(), "Hello world");
    ///
    /// iter.next();
    /// assert_eq!(iter.as_str(), " world");
    ///
    /// iter.next();
    /// assert_eq!(iter.as_str(), "world");
    /// ```
    pub fn as_str(&self) -> &'a str {
        self.string
    }

    #[inline]
    fn get_next_cat(&self, idx: usize) -> Option<WB> {
        let nidx = idx + self.string[idx..].chars().next().unwrap().len_utf8();
        if nidx < self.string.len() {
            let nch = self.string[nidx..].chars().next().unwrap();
            Some(WB::of(nch))
        } else {
            None
        }
    }

    #[inline]
    fn get_prev_cat(&self, idx: usize) -> Option<WB> {
        if idx > 0 {
            let nch = self.string[..idx].chars().next_back().unwrap();
            Some(WB::of(nch))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WordBounds, Words};
    use unic_ucd_common::is_alphanumeric;

    #[test]
    fn test_word_bounds() {
        assert_eq!(
            WordBounds::new("The quick (\"brown\")  fox").collect::<Vec<&str>>(),
            &["The", " ", "quick", " ", "(", "\"", "brown", "\"", ")", " ", " ", "fox"]
        );
    }

    #[test]
    fn test_words() {
        assert_eq!(
            Words::new(
                "The quick (\"brown\") fox can't jump 32.3 feet, right?",
                |s: &&str| s.chars().any(is_alphanumeric),
            )
            .collect::<Vec<&str>>(),
            &["The", "quick", "brown", "fox", "can't", "jump", "32.3", "feet", "right"]
        );
    }
}
