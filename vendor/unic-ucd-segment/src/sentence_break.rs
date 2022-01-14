// Copyright 2017 The UNIC Project Developers.
//
// See the COPYRIGHT file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Unicode `Sentence_Break` Character Property.
//!
//! ## References
//!
//! * <https://www.unicode.org/reports/tr44/#Sentence_Break>
//! * <https://www.unicode.org/reports/tr29/#Sentence_Boundaries>
//! * <https://www.unicode.org/reports/tr29/#Table_Sentence_Break_Property_Values>

use unic_char_property::TotalCharProperty;

char_property! {
    /// Represents the Unicode character
    /// [`Sentence_Break`](https://www.unicode.org/reports/tr44/#Sentence_Break)
    /// property.
    ///
    /// ## References
    ///
    /// * <https://www.unicode.org/reports/tr44/#Sentence_Break>
    /// * <https://www.unicode.org/reports/tr29/#Sentence_Boundaries>
    /// * <https://www.unicode.org/reports/tr29/#Table_Sentence_Break_Property_Values>
    pub enum SentenceBreak {
        abbr => "SB";
        long => "Sentence_Break";
        human => "Sentence Break";

        /// ```text
        /// U+000D CARRIAGE RETURN (CR)
        /// ```
        CR {
            abbr => CR,
            long => CR,
            human => "Carriage Return",
        }

        /// ```text
        /// U+000A LINE FEED (LF)
        /// ```
        LF {
            abbr => LF,
            long => LF,
            human => "Line Feed",
        }

        /// ```text
        /// Grapheme_Extend = Yes, or
        /// U+200D ZERO WIDTH JOINER (ZWJ), or
        /// General_Category = Spacing_Mark
        /// ```
        Extend {
            abbr => Extend,
            long => Extend,
            human => "Extend",
        }

        /// ```text
        /// U+0085 NEXT LINE (NEL)
        /// U+2028 LINE SEPARATOR
        /// U+2029 PARAGRAPH SEPARATOR
        /// ```
        Sep {
            abbr => SE,
            long => Sep,
            human => "Separator",
        }

        /// ```text
        /// General_Category = Format
        /// and not U+200C ZERO WIDTH NON-JOINER (ZWNJ)
        /// and not U+200D ZERO WIDTH JOINER (ZWJ)
        /// ```
        Format {
            abbr => FO,
            long => Format,
            human => "Format",
        }

        /// ```text
        /// White_Space = Yes
        /// and Sentence_Break ≠ Sep
        /// and Sentence_Break ≠ CR
        /// and Sentence_Break ≠ LF
        /// ```
        Sp {
            abbr => SP,
            long => Sp,
            human => "Space",
        }

        /// ```text
        /// Lowercase = Yes
        /// and Grapheme_Extend = No
        /// ```
        Lower {
            abbr => LO,
            long => Lower,
            human => "Lowercase",
        }

        /// ```text
        /// General_Category = Titlecase_Letter, or
        /// Uppercase = Yes
        /// ```
        Upper {
            abbr => UP,
            long => Upper,
            human => "Uppercase",
        }

        /// ```text
        /// Alphabetic = Yes, or
        /// U+00A0 NO-BREAK SPACE (NBSP), or
        /// U+05F3 ( ׳ ) HEBREW PUNCTUATION GERESH
        /// and Lower = No
        /// and Upper = No
        /// and Sentence_Break ≠ Extend
        /// ```
        OLetter {
            abbr => LE,
            long => OLetter,
            human => "Other Letter",
        }

        /// ```text
        /// Line_Break = Numeric
        /// ```
        Numeric {
            abbr => NU,
            long => Numeric,
            human => "Numeric",
        }

        /// ```text
        /// U+002E ( . ) FULL STOP
        /// U+2024 ( ․ ) ONE DOT LEADER
        /// U+FE52 ( ﹒ ) SMALL FULL STOP
        /// U+FF0E ( ． ) FULLWIDTH FULL STOP
        /// ```
        ATerm {
            abbr => AT,
            long => ATerm,
            human => "ATerm",
        }

        /// ```text
        /// U+002C ( , ) COMMA
        /// U+002D ( - ) HYPHEN-MINUS
        /// U+003A ( : ) COLON
        /// U+055D ( ՝ ) ARMENIAN COMMA
        /// U+060C ( ، ) ARABIC COMMA
        /// U+060D ( ‎؍‎ ) ARABIC DATE SEPARATOR
        /// U+07F8 ( ߸ ) NKO COMMA
        /// U+1802 ( ᠂ ) MONGOLIAN COMMA
        /// U+1808 ( ᠈ ) MONGOLIAN MANCHU COMMA
        /// U+2013 ( – ) EN DASH
        /// U+2014 ( — ) EM DASH
        /// U+3001 ( 、 ) IDEOGRAPHIC COMMA
        /// U+FE10 ( ︐ ) PRESENTATION FORM FOR VERTICAL COMMA
        /// U+FE11 ( ︑ ) PRESENTATION FORM FOR VERTICAL IDEOGRAPHIC COMMA
        /// U+FE13 ( ︓ ) PRESENTATION FORM FOR VERTICAL COLON
        /// U+FE31 ( ︱ ) PRESENTATION FORM FOR VERTICAL EM DASH
        /// U+FE32 ( ︲ ) PRESENTATION FORM FOR VERTICAL EN DASH
        /// U+FE50 ( ﹐ ) SMALL COMMA
        /// U+FE51 ( ﹑ ) SMALL IDEOGRAPHIC COMMA
        /// U+FE55 ( ﹕ ) SMALL COLON
        /// U+FE58 ( ﹘ ) SMALL EM DASH
        /// U+FE63 ( ﹣ ) SMALL HYPHEN-MINUS
        /// U+FF0C ( ， ) FULLWIDTH COMMA
        /// U+FF0D ( － ) FULLWIDTH HYPHEN-MINUS
        /// U+FF1A ( ： ) FULLWIDTH COLON
        /// U+FF64 ( ､ ) HALFWIDTH IDEOGRAPHIC COMMA
        /// ```
        SContinue {
            abbr => SC,
            long => SContinue,
            human => "Sentence Continue",
        }

        /// ```text
        /// Sentence_Terminal = Yes
        /// ```
        STerm {
            abbr => ST,
            long => STerm,
            human => "Sentence Terminal",
        }

        /// ```text
        /// General_Category = Open_Punctuation, or
        /// General_Category = Close_Punctuation, or
        /// Line_Break = Quotation
        /// and not U+05F3 ( ׳ ) HEBREW PUNCTUATION GERESH
        /// and ATerm = No
        /// and STerm = No
        /// ```
        Close {
            abbr => CL,
            long => Close,
            human => "Close",
        }

        /// All other characters
        Other {
            abbr => XX,
            long => Other,
            human => "Other",
        }
    }

    /// Abbreviated name aliases for the
    /// [`Sentence_Break`](https://www.unicode.org/reports/tr44/#Sentence_Break)
    /// property.
    ///
    /// ## See Also
    ///
    /// * <https://www.unicode.org/reports/tr29/#Sentence_Boundaries>
    pub mod abbr_names for abbr;

    /// Long name aliases for the
    /// [`Sentence_Break`](https://www.unicode.org/reports/tr44/#Sentence_Break)
    /// property.
    ///
    /// ## See Also
    ///
    /// * <https://www.unicode.org/reports/tr29/#Sentence_Boundaries>
    pub mod long_names for long;
}

impl TotalCharProperty for SentenceBreak {
    fn of(ch: char) -> Self {
        Self::of(ch)
    }
}

impl Default for SentenceBreak {
    fn default() -> Self {
        SentenceBreak::Other
    }
}

mod data {
    use super::long_names as SB;
    use unic_char_property::tables::CharDataTable;
    pub const SENTENCE_BREAK_TABLE: CharDataTable<super::SentenceBreak> =
        include!("../tables/sentence_break.rsv");
}

impl SentenceBreak {
    /// Find the character `Sentence_Break` property value.
    pub fn of(ch: char) -> SentenceBreak {
        data::SENTENCE_BREAK_TABLE.find_or_default(ch)
    }
}

#[cfg(test)]
mod tests {
    use super::SentenceBreak as SB;
    use unic_char_property::EnumeratedCharProperty;

    #[test]
    fn test_ascii() {
        assert_eq!(SB::of('\u{0000}'), SB::Other);
        assert_eq!(SB::of('\u{0040}'), SB::Other);
        assert_eq!(SB::of('\u{0041}'), SB::Upper);
        assert_eq!(SB::of('\u{0062}'), SB::Lower);
        assert_eq!(SB::of('\u{007F}'), SB::Other);
    }

    #[test]
    fn test_bmp() {
        // Hebrew
        assert_eq!(SB::of('\u{0590}'), SB::Other);
        assert_eq!(SB::of('\u{05D0}'), SB::OLetter);
        assert_eq!(SB::of('\u{05D1}'), SB::OLetter);
        assert_eq!(SB::of('\u{05FF}'), SB::Other);

        // Arabic
        assert_eq!(SB::of('\u{0600}'), SB::Format);
        assert_eq!(SB::of('\u{0627}'), SB::OLetter);
        assert_eq!(SB::of('\u{07BF}'), SB::Other);

        // Default R + Arabic Extras
        assert_eq!(SB::of('\u{07C0}'), SB::Numeric);
        assert_eq!(SB::of('\u{085F}'), SB::Other);
        assert_eq!(SB::of('\u{0860}'), SB::OLetter);
        assert_eq!(SB::of('\u{0870}'), SB::Other);
        assert_eq!(SB::of('\u{089F}'), SB::Other);
        assert_eq!(SB::of('\u{08A0}'), SB::OLetter);
        assert_eq!(SB::of('\u{089F}'), SB::Other);
        assert_eq!(SB::of('\u{08FF}'), SB::Extend);

        // Default ET
        assert_eq!(SB::of('\u{20A0}'), SB::Other);
        assert_eq!(SB::of('\u{20CF}'), SB::Other);

        // Arabic Presentation Forms
        assert_eq!(SB::of('\u{FB1D}'), SB::OLetter);
        assert_eq!(SB::of('\u{FB4F}'), SB::OLetter);
        assert_eq!(SB::of('\u{FB50}'), SB::OLetter);
        assert_eq!(SB::of('\u{FDCF}'), SB::Other);
        assert_eq!(SB::of('\u{FDF0}'), SB::OLetter);
        assert_eq!(SB::of('\u{FDFF}'), SB::Other);
        assert_eq!(SB::of('\u{FE70}'), SB::OLetter);
        assert_eq!(SB::of('\u{FEFE}'), SB::Other);
        assert_eq!(SB::of('\u{FEFF}'), SB::Format);

        // noncharacters
        assert_eq!(SB::of('\u{FDD0}'), SB::Other);
        assert_eq!(SB::of('\u{FDD1}'), SB::Other);
        assert_eq!(SB::of('\u{FDEE}'), SB::Other);
        assert_eq!(SB::of('\u{FDEF}'), SB::Other);
        assert_eq!(SB::of('\u{FFFE}'), SB::Other);
        assert_eq!(SB::of('\u{FFFF}'), SB::Other);
    }

    #[test]
    fn test_smp() {
        // Default AL + R
        assert_eq!(SB::of('\u{10800}'), SB::OLetter);
        assert_eq!(SB::of('\u{10FFF}'), SB::Other);
        assert_eq!(SB::of('\u{1E800}'), SB::OLetter);
        assert_eq!(SB::of('\u{1EDFF}'), SB::Other);
        assert_eq!(SB::of('\u{1EE00}'), SB::OLetter);
        assert_eq!(SB::of('\u{1EEFF}'), SB::Other);
        assert_eq!(SB::of('\u{1EF00}'), SB::Other);
        assert_eq!(SB::of('\u{1EFFF}'), SB::Other);
    }

    #[test]
    fn test_unassigned_planes() {
        assert_eq!(SB::of('\u{30000}'), SB::Other);
        assert_eq!(SB::of('\u{40000}'), SB::Other);
        assert_eq!(SB::of('\u{50000}'), SB::Other);
        assert_eq!(SB::of('\u{60000}'), SB::Other);
        assert_eq!(SB::of('\u{70000}'), SB::Other);
        assert_eq!(SB::of('\u{80000}'), SB::Other);
        assert_eq!(SB::of('\u{90000}'), SB::Other);
        assert_eq!(SB::of('\u{a0000}'), SB::Other);
    }

    #[test]
    fn test_abbr_name() {
        assert_eq!(SB::CR.abbr_name(), "CR");
    }

    #[test]
    fn test_long_name() {
        assert_eq!(SB::CR.long_name(), "CR");
    }

    #[test]
    fn test_human_name() {
        assert_eq!(SB::CR.human_name(), "Carriage Return");
    }
}
