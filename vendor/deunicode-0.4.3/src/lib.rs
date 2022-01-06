//! The `deunicode` library transliterates Unicode strings such as "Æneid" into pure
//! ASCII ones such as "AEneid."
//!
//! It started as a Rust port of [`Text::Unidecode`](http://search.cpan.org/~sburke/Text-Unidecode-1.30/lib/Text/Unidecode.pm) Perl module, and was extended to support emoji.
//!
//! See [README](https://github.com/kornelski/deunicode/blob/master/README.md) for more info.
//!
//! Examples
//! --------
//! ```rust
//! extern crate deunicode;
//! use deunicode::deunicode;
//!
//! assert_eq!(deunicode("Æneid"), "AEneid");
//! assert_eq!(deunicode("étude"), "etude");
//! assert_eq!(deunicode("北亰"), "Bei Jing");
//! assert_eq!(deunicode("ᔕᓇᓇ"), "shanana");
//! assert_eq!(deunicode("げんまい茶"), "genmaiCha");
//! assert_eq!(deunicode("🦄☣"), "unicorn face biohazard");
//! ```

use std::str::Chars;
use std::iter::FusedIterator;

const MAPPING: &str = include_str!("mapping.txt");

#[repr(C)]
#[derive(Copy, Clone)]
struct Ptr {
    /// if len <= 2, it's the string itself,
    /// otherwise it's an u16 offset into MAPPING
    chr: [u8; 2],
    len: u8,
}

/// POINTERS format is described by struct Ptr
const POINTERS: &[u8] = include_bytes!("pointers.bin");

/// This function takes any Unicode string and returns an ASCII transliteration
/// of that string.
///
/// Guarantees and Warnings
/// -----------------------
/// Here are some guarantees you have when calling `deunicode()`:
///   * The `String` returned will be valid ASCII; the decimal representation of
///     every `char` in the string will be between 0 and 127, inclusive.
///   * Every ASCII character (0x0000 - 0x007F) is mapped to itself.
///   * All Unicode characters will translate to a string containing newlines
///     (`"\n"`) or ASCII characters in the range 0x0020 - 0x007E. So for example,
///     no Unicode character will translate to `\u{01}`. The exception is if the
///     ASCII character itself is passed in, in which case it will be mapped to
///     itself. (So `'\u{01}'` will be mapped to `"\u{01}"`.)
///
/// There are, however, some things you should keep in mind:
///   * As stated, some transliterations do produce `\n` characters.
///   * Some Unicode characters transliterate to an empty string, either on purpose
///     or because `deunicode` does not know about the character.
///   * Some Unicode characters are unknown and transliterate to `"[?]"`.
///   * Many Unicode characters transliterate to multi-character strings. For
///     example, 北 is transliterated as "Bei ".
///   * Han characters are mapped to Mandarin, and will be mostly illegible to Japanese readers.
#[inline]
pub fn deunicode(s: &str) -> String {
    deunicode_with_tofu(s, "[?]")
}

/// Same as `deunicode`, but unknown characters can be replaced with a custom string.
///
/// "Tofu" is a nickname for a replacement character, which in Unicode fonts usually
/// looks like a block of tofu.
pub fn deunicode_with_tofu(s: &str, custom_placeholder: &str) -> String {
    // reserve a bit more space to avoid reallocations on longer transliterations
    let mut out = String::with_capacity(s.len() + 16);
    out.extend(s.ascii_chars().map(|ch| ch.unwrap_or(custom_placeholder)));
    out
}

/// This function takes a single Unicode character and returns an ASCII
/// transliteration.
///
/// The warnings and guarantees of `deunicode()` apply to this function as well.
///
/// Examples
/// --------
/// ```rust
/// # extern crate deunicode;
/// # use deunicode::deunicode_char;
/// assert_eq!(deunicode_char('Æ'), Some("AE"));
/// assert_eq!(deunicode_char('北'), Some("Bei "));
/// ```
#[inline]
pub fn deunicode_char(ch: char) -> Option<&'static str> {
    // when using the global directly, LLVM fails to remove bounds checks
    let pointers: &'static [Ptr] = unsafe {
        std::slice::from_raw_parts(POINTERS.as_ptr() as *const Ptr, POINTERS.len()/3)
    };

    if let Some(p) = pointers.get(ch as usize) {
        // if length is 1 or 2, then the "pointer" data is used to store the char
        if p.len <= 2 {
            // safe, because we're returning only ASCII
            unsafe {
                Some(std::str::from_utf8_unchecked(&p.chr[..p.len as usize]))
            }
        } else {
            let map_pos = (p.chr[0] as u16 | (p.chr[1] as u16) << 8) as usize;
            // unknown characters are intentionally mapped to out of range length
            MAPPING.get(map_pos..map_pos + p.len as usize)
        }
    } else {
        None
    }
}

/// Convenience functions for deunicode. `use deunicode::AsciiChars`
pub trait AsciiChars {
    /// Iterate over Unicode characters converted to ASCII sequences.
    ///
    /// Items of this iterator may be `None` for some characters.
    /// Use `.map(|ch| ch.unwrap_or("?"))` to replace invalid characters.
    fn ascii_chars(&self) -> AsciiCharsIter;
    /// Convert any Unicode string to ASCII-only string.
    ///
    /// Characters are converted to closest ASCII equivalent.
    /// Characters that can't be converted are replaced with `"[?]"`.
    fn to_ascii_lossy(&self) -> String;
}

impl AsciiChars for String {
    fn ascii_chars(&self) -> AsciiCharsIter {
        AsciiCharsIter::new(self)
    }
    fn to_ascii_lossy(&self) -> String {
        deunicode(self)
    }
}

impl AsciiChars for str {
    fn ascii_chars(&self) -> AsciiCharsIter {
        AsciiCharsIter::new(self)
    }
    fn to_ascii_lossy(&self) -> String {
        deunicode(self)
    }
}

/// Iterator that translates Unicode characters to ASCII strings.pub
///
/// See `AsciiChars` trait's `str.ascii_chars()` method.
pub struct AsciiCharsIter<'a> {
    next_char: Option<Option<&'static str>>,
    chars: Chars<'a>,
}

impl<'a> AsciiCharsIter<'a> {
    #[inline]
    pub fn new(unicode_string: &'a str) -> Self {
        let mut chars = unicode_string.chars();
        Self {
            next_char: chars.next().map(deunicode_char),
            chars,
        }
    }
}

impl<'a> FusedIterator for AsciiCharsIter<'a> {}

impl<'a> Iterator for AsciiCharsIter<'a> {
    type Item = Option<&'static str>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.next_char.map(|dch| {
            self.next_char = self.chars.next().map(deunicode_char);
            dch.map(|dch| {
                let bytes = dch.as_bytes();
                let ends_with_space = bytes.len() > 1 && bytes.last().cloned() == Some(b' ');
                if !ends_with_space {
                    return dch;
                }
                let space_or_end_next = self.next_char.map_or(true, |ch| { // true if end
                    ch.map_or(false, |ch| ch.as_bytes().get(0).cloned() == Some(b' ')) // space next (assume placeholder is not space)
                });
                if !space_or_end_next {
                    dch
                } else {
                    &dch[..dch.len()-1]
                }
            })
        })
    }

    #[inline]
    fn count(self) -> usize {
        self.chars.count() + if self.next_char.is_some() {1} else {0}
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.chars.size_hint().0 + if self.next_char.is_some() {1} else {0}, None)
    }
}

#[test]
fn iter_test() {
    let chars: Vec<_> = AsciiCharsIter::new("中国").filter_map(|ch| ch).collect();
    assert_eq!(&chars, &["Zhong ", "Guo"]);
    let chars: Vec<_> = "中国x".ascii_chars().filter_map(|ch| ch).collect();
    assert_eq!(&chars, &["Zhong ", "Guo ", "x"]);
    let chars: Vec<_> = "中 国".ascii_chars().filter_map(|ch| ch).collect();
    assert_eq!(&chars, &["Zhong", " ", "Guo"]);
}
