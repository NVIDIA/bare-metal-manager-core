// Copyright 2017 The UNIC Project Developers.
//
// See the COPYRIGHT file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Unicode `Word_Break` Character Property.
//!
//! ## References
//!
//! * <https://www.unicode.org/reports/tr44/#Word_Break>
//! * <https://www.unicode.org/reports/tr29/#Word_Boundaries>
//! * <https://www.unicode.org/reports/tr29/#Table_Word_Break_Property_Values>

use unic_char_property::TotalCharProperty;

char_property! {
    /// Represents the Unicode character
    /// [`Word_Break`](https://www.unicode.org/reports/tr44/#Word_Break)
    /// property.
    ///
    /// ## References
    ///
    /// * <https://www.unicode.org/reports/tr44/#Word_Break>
    /// * <https://www.unicode.org/reports/tr29/#Word_Boundaries>
    /// * <https://www.unicode.org/reports/tr29/#Table_Word_Break_Property_Values>
    pub enum WordBreak {
        abbr => "WB";
        long => "Word_Break";
        human => "Word Break";

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
        /// U+000B LINE TABULATION
        /// U+000C FORM FEED (FF)
        /// U+0085 NEXT LINE (NEL)
        /// U+2028 LINE SEPARATOR
        /// U+2029 PARAGRAPH SEPARATOR
        /// ```
        Newline {
            abbr => NL,
            long => Newline,
            human => "Newline",
        }

        /// ```text
        /// Grapheme_Extend = Yes, or
        /// General_Category = Spacing_Mark
        /// and not U+200D ZERO WIDTH JOINER (ZWJ)
        /// ```
        Extend {
            abbr => Extend,
            long => Extend,
            human => "Extend",
        }

        /// ```text
        /// U+200D ZERO WIDTH JOINER
        /// ```
        ZWJ {
            abbr => ZWJ,
            long => ZWJ,
            human => "Zero Width Joiner (ZWJ)",
        }

        /// ```text
        /// Regional_Indicator = Yes
        /// ```
        ///
        /// This consists of the range:
        ///
        /// ```text
        /// U+1F1E6 REGIONAL INDICATOR SYMBOL LETTER A
        /// ..U+1F1FF REGIONAL INDICATOR SYMBOL LETTER Z
        /// ```
        RegionalIndicator {
            abbr => RI,
            long => Regional_Indicator,
            human => "Regional Indicator",
        }

        /// ```text
        /// General_Category = Format
        /// and not U+200B ZERO WIDTH SPACE (ZWSP)
        /// and not U+200C ZERO WIDTH NON-JOINER (ZWNJ)
        /// and not U+200D ZERO WIDTH JOINER (ZWJ)
        /// ```
        Format {
            abbr => FO,
            long => Format,
            human => "Format",
        }

        /// ```text
        /// Script = KATAKANA, or
        /// any of the following:
        /// U+3031 ( 〱 ) VERTICAL KANA REPEAT MARK
        /// U+3032 ( 〲 ) VERTICAL KANA REPEAT WITH VOICED SOUND MARK
        /// U+3033 ( 〳 ) VERTICAL KANA REPEAT MARK UPPER HALF
        /// U+3034 ( 〴 ) VERTICAL KANA REPEAT WITH VOICED SOUND MARK UPPER HALF
        /// U+3035 ( 〵 ) VERTICAL KANA REPEAT MARK LOWER HALF
        /// U+309B ( ゛ ) KATAKANA-HIRAGANA VOICED SOUND MARK
        /// U+309C ( ゜ ) KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK
        /// U+30A0 ( ゠ ) KATAKANA-HIRAGANA DOUBLE HYPHEN
        /// U+30FC ( ー ) KATAKANA-HIRAGANA PROLONGED SOUND MARK
        /// U+FF70 ( ｰ ) HALFWIDTH KATAKANA-HIRAGANA PROLONGED SOUND MARK
        /// ```
        Katakana {
            abbr => KA,
            long => Katakana,
            human => "Katakana",
        }

        /// ```text
        /// Script = Hebrew
        /// and General_Category = Other_Letter
        /// ```
        HebrewLetter {
            abbr => HL,
            long => Hebrew_Letter,
            human => "Hebrew Letter",
        }

        /// ```text
        /// Alphabetic = Yes, or
        /// any of the following 36 characters:
        /// U+02C2 ( ˂ ) MODIFIER LETTER LEFT ARROWHEAD
        /// ..U+02C5 ( ˅ ) MODIFIER LETTER DOWN ARROWHEAD
        /// U+02D2 ( ˒ ) MODIFIER LETTER CENTRED RIGHT HALF RING
        /// ..U+02D7 ( ˗ ) MODIFIER LETTER MINUS SIGN
        /// U+02DE ( ˞ ) MODIFIER LETTER RHOTIC HOOK
        /// U+02DF ( ˟ ) MODIFIER LETTER CROSS ACCENT
        /// U+02ED ( ˭ ) MODIFIER LETTER UNASPIRATED
        /// U+02EF ( ˯ ) MODIFIER LETTER LOW DOWN ARROWHEAD
        /// ..U+02FF ( ˿ ) MODIFIER LETTER LOW LEFT ARROW
        /// U+05F3 ( ׳ ) HEBREW PUNCTUATION GERESH
        /// U+A720 ( ꜠ ) MODIFIER LETTER STRESS AND HIGH TONE
        /// U+A721 ( ꜡ ) MODIFIER LETTER STRESS AND LOW TONE
        /// U+A789 ( ꞉ ) MODIFIER LETTER COLON
        /// U+A78A ( ꞊ ) MODIFIER LETTER SHORT EQUALS SIGN
        /// U+AB5B ( ꭛ ) MODIFIER BREVE WITH INVERTED BREVE
        /// and Ideographic = No
        /// and Word_Break ≠ Katakana
        /// and Line_Break ≠ Complex_Context (SA)
        /// and Script ≠ Hiragana
        /// and Word_Break ≠ Extend
        /// and Word_Break ≠ Hebrew_Letter
        /// ```
        ALetter {
            abbr => LE,
            long => ALetter,
            human => "Alphabetic Letter",
        }

        /// ```text
        /// U+0027 ( ' ) APOSTROPHE
        /// ```
        SingleQuote {
            abbr => SQ,
            long => Single_Quote,
            human => "Single Quote",
        }

        /// ```text
        /// U+0022 ( " ) QUOTATION MARK
        /// ```
        DoubleQuote {
            abbr => DQ,
            long => Double_Quote,
            human => "Double Quote",
        }

        /// ```text
        /// U+002E ( . ) FULL STOP
        /// U+2018 ( ‘ ) LEFT SINGLE QUOTATION MARK
        /// U+2019 ( ’ ) RIGHT SINGLE QUOTATION MARK
        /// U+2024 ( ․ ) ONE DOT LEADER
        /// U+FE52 ( ﹒ ) SMALL FULL STOP
        /// U+FF07 ( ＇ ) FULLWIDTH APOSTROPHE
        /// U+FF0E ( ． ) FULLWIDTH FULL STOP
        /// ```
        MidNumLet {
            abbr => MB,
            long => MidNumLet,
            human => "Middle of Numeric/Letter",
        }

        /// ```text
        /// U+00B7 ( · ) MIDDLE DOT
        /// U+0387 ( · ) GREEK ANO TELEIA
        /// U+05F4 ( ״ ) HEBREW PUNCTUATION GERSHAYIM
        /// U+2027 ( ‧ ) HYPHENATION POINT
        /// U+003A ( : ) COLON (used in Swedish)
        /// U+FE13 ( ︓ ) PRESENTATION FORM FOR VERTICAL COLON
        /// U+FE55 ( ﹕ ) SMALL COLON
        /// U+FF1A ( ： ) FULLWIDTH COLON
        /// ```
        MidLetter {
            abbr => ML,
            long => MidLetter,
            human => "Middle of Letter",
        }

        /// ```text
        /// Line_Break = Infix_Numeric, or
        /// any of the following:
        /// U+066C ( ٬ ) ARABIC THOUSANDS SEPARATOR
        /// U+FE50 ( ﹐ ) SMALL COMMA
        /// U+FE54 ( ﹔ ) SMALL SEMICOLON
        /// U+FF0C ( ， ) FULLWIDTH COMMA
        /// U+FF1B ( ； ) FULLWIDTH SEMICOLON
        /// and not U+003A ( : ) COLON
        /// and not U+FE13 ( ︓ ) PRESENTATION FORM FOR VERTICAL COLON
        /// and not U+002E ( . ) FULL STOP
        /// ```
        MidNum {
            abbr => MN,
            long => MidNum,
            human => "Middle of Numeric",
        }

        /// ```text
        /// Line_Break = Numeric
        /// and not U+066C ( ٬ ) ARABIC THOUSANDS SEPARATOR
        /// ```
        Numeric {
            abbr => NU,
            long => Numeric,
            human => "Numeric",
        }

        /// ```text
        /// General_Category = Connector_Punctuation, or
        /// U+202F NARROW NO-BREAK SPACE (NNBSP)
        /// ```
        ExtendNumLet {
            abbr => EX,
            long => ExtendNumLet,
            human => "Extend Numeric/Letter",
        }

        // Emoji

        /// Emoji characters listed as `Emoji_Modifier_Base=Yes` in `emoji-data.txt`, which do not
        /// occur after ZWJ in `emoji-zwj-sequences.txt`.
        ///
        /// See <https://www.unicode.org/reports/tr51/>.
        EBase {
            abbr => EB,
            long => E_Base,
            human => "Emoji Base",
        }

        /// Emoji characters listed as `Emoji_Modifer=Yes` in `emoji-data.txt`.
        ///
        /// See <https://www.unicode.org/reports/tr51/>.
        EModifier {
            abbr => EM,
            long => E_Modifier,
            human => "Emoji Modifier",
        }

        /// Emoji characters that do not break from a previous ZWJ in a defined emoji ZWJ sequence,
        /// and are not listed as `Emoji_Modifier_Base=Yes` in `emoji-data.txt`.
        ///
        /// See <https://www.unicode.org/reports/tr51/>.
        GlueAfterZwj {
            abbr => GAZ,
            long => Glue_After_Zwj,
            human => "Glue After ZWJ",
        }

        /// Emoji characters listed as `Emoji_Modifer_Base=Yes` in `emoji_data.txt`, and also occur
        /// after ZWJ in `emoji-zwj-sequences.txt`.
        ///
        /// See <https://www.unicode.org/reports/tr51/>.
        EBaseGAZ {
            abbr => EBG,
            long => E_Base_GAZ,
            human => "Emoji Base and Glue After ZWJ",
        }

        /// All other characters
        Other {
            abbr => XX,
            long => Other,
            human => "Other",
        }
    }

    /// Abbreviated name aliases for the
    /// [`Word_Break`](https://www.unicode.org/reports/tr44/#Word_Break)
    /// property.
    ///
    /// ## See Also
    ///
    /// * <https://www.unicode.org/reports/tr29/#Word_Boundaries>
    pub mod abbr_names for abbr;

    /// Long name aliases for the
    /// [`Word_Break`](https://www.unicode.org/reports/tr44/#Word_Break)
    /// property.
    ///
    /// ## See Also
    ///
    /// * <https://www.unicode.org/reports/tr29/#Word_Boundaries>
    pub mod long_names for long;
}

impl TotalCharProperty for WordBreak {
    fn of(ch: char) -> Self {
        Self::of(ch)
    }
}

impl Default for WordBreak {
    fn default() -> Self {
        WordBreak::Other
    }
}

mod data {
    use super::long_names as WB;
    use unic_char_property::tables::CharDataTable;
    pub const WORD_BREAK_TABLE: CharDataTable<super::WordBreak> =
        include!("../tables/word_break.rsv");
}

impl WordBreak {
    /// Find the character `Word_Break` property value.
    pub fn of(ch: char) -> WordBreak {
        data::WORD_BREAK_TABLE.find_or_default(ch)
    }
}

#[cfg(test)]
mod tests {
    use super::WordBreak as WB;
    use unic_char_property::EnumeratedCharProperty;

    #[test]
    fn test_ascii() {
        assert_eq!(WB::of('\u{0000}'), WB::Other);
        assert_eq!(WB::of('\u{0040}'), WB::Other);
        assert_eq!(WB::of('\u{0041}'), WB::ALetter);
        assert_eq!(WB::of('\u{0062}'), WB::ALetter);
        assert_eq!(WB::of('\u{007F}'), WB::Other);
    }

    #[test]
    fn test_bmp() {
        // Hebrew
        assert_eq!(WB::of('\u{0590}'), WB::Other);
        assert_eq!(WB::of('\u{05D0}'), WB::HebrewLetter);
        assert_eq!(WB::of('\u{05D1}'), WB::HebrewLetter);
        assert_eq!(WB::of('\u{05FF}'), WB::Other);

        // Arabic
        assert_eq!(WB::of('\u{0600}'), WB::Format);
        assert_eq!(WB::of('\u{0627}'), WB::ALetter);
        assert_eq!(WB::of('\u{07BF}'), WB::Other);

        // Default R + Arabic Extras
        assert_eq!(WB::of('\u{07C0}'), WB::Numeric);
        assert_eq!(WB::of('\u{085F}'), WB::Other);
        assert_eq!(WB::of('\u{0860}'), WB::ALetter);
        assert_eq!(WB::of('\u{0870}'), WB::Other);
        assert_eq!(WB::of('\u{089F}'), WB::Other);
        assert_eq!(WB::of('\u{08A0}'), WB::ALetter);
        assert_eq!(WB::of('\u{089F}'), WB::Other);
        assert_eq!(WB::of('\u{08FF}'), WB::Extend);

        // Default ET
        assert_eq!(WB::of('\u{20A0}'), WB::Other);
        assert_eq!(WB::of('\u{20CF}'), WB::Other);

        // Arabic Presentation Forms
        assert_eq!(WB::of('\u{FB1D}'), WB::HebrewLetter);
        assert_eq!(WB::of('\u{FB4F}'), WB::HebrewLetter);
        assert_eq!(WB::of('\u{FB50}'), WB::ALetter);
        assert_eq!(WB::of('\u{FDCF}'), WB::Other);
        assert_eq!(WB::of('\u{FDF0}'), WB::ALetter);
        assert_eq!(WB::of('\u{FDFF}'), WB::Other);
        assert_eq!(WB::of('\u{FE70}'), WB::ALetter);
        assert_eq!(WB::of('\u{FEFE}'), WB::Other);
        assert_eq!(WB::of('\u{FEFF}'), WB::Format);

        // noncharacters
        assert_eq!(WB::of('\u{FDD0}'), WB::Other);
        assert_eq!(WB::of('\u{FDD1}'), WB::Other);
        assert_eq!(WB::of('\u{FDEE}'), WB::Other);
        assert_eq!(WB::of('\u{FDEF}'), WB::Other);
        assert_eq!(WB::of('\u{FFFE}'), WB::Other);
        assert_eq!(WB::of('\u{FFFF}'), WB::Other);
    }

    #[test]
    fn test_smp() {
        // Default AL + R
        assert_eq!(WB::of('\u{10800}'), WB::ALetter);
        assert_eq!(WB::of('\u{10FFF}'), WB::Other);
        assert_eq!(WB::of('\u{1E800}'), WB::ALetter);
        assert_eq!(WB::of('\u{1EDFF}'), WB::Other);
        assert_eq!(WB::of('\u{1EE00}'), WB::ALetter);
        assert_eq!(WB::of('\u{1EEFF}'), WB::Other);
        assert_eq!(WB::of('\u{1EF00}'), WB::Other);
        assert_eq!(WB::of('\u{1EFFF}'), WB::Other);
    }

    #[test]
    fn test_unassigned_planes() {
        assert_eq!(WB::of('\u{30000}'), WB::Other);
        assert_eq!(WB::of('\u{40000}'), WB::Other);
        assert_eq!(WB::of('\u{50000}'), WB::Other);
        assert_eq!(WB::of('\u{60000}'), WB::Other);
        assert_eq!(WB::of('\u{70000}'), WB::Other);
        assert_eq!(WB::of('\u{80000}'), WB::Other);
        assert_eq!(WB::of('\u{90000}'), WB::Other);
        assert_eq!(WB::of('\u{a0000}'), WB::Other);
    }

    #[test]
    fn test_abbr_name() {
        assert_eq!(WB::CR.abbr_name(), "CR");
    }

    #[test]
    fn test_long_name() {
        assert_eq!(WB::CR.long_name(), "CR");
    }

    #[test]
    fn test_human_name() {
        assert_eq!(WB::CR.human_name(), "Carriage Return");
    }
}
